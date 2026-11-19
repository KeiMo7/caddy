// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

type preparedLocalAdminServer struct {
	server   *http.Server
	listener net.Listener
	addr     NetworkAddress
	cfg      *AdminConfig
	handler  adminHandler

	committed bool
}

func prepareLocalAdminServer(cfg *Config, ctx Context) (*preparedLocalAdminServer, error) {
	if cfg.Admin == nil {
		cfg.Admin = &AdminConfig{
			Listen: DefaultAdminListen,
		}
	}

	prepared := &preparedLocalAdminServer{cfg: cfg.Admin}
	if cfg.Admin.Disabled {
		Log().Named("admin").Warn("admin endpoint disabled")
		return prepared, nil
	}

	addr, err := parseAdminListenAddr(cfg.Admin.Listen, DefaultAdminListen)
	if err != nil {
		return nil, err
	}
	prepared.addr = addr

	handler, err := cfg.Admin.newAdminHandler(addr, false, ctx)
	if err != nil {
		return nil, err
	}
	prepared.handler = handler

	ln, err := addr.Listen(context.TODO(), 0, net.ListenConfig{})
	if err != nil {
		return nil, err
	}
	prepared.listener = ln.(net.Listener)
	prepared.server = &http.Server{
		Addr:              addr.String(), // for logging purposes only
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1024 * 64,
	}
	return prepared, nil
}

func (p *preparedLocalAdminServer) Commit() {
	if p == nil {
		return
	}

	var oldAdminServer *http.Server
	serverMu.Lock()
	oldAdminServer = localAdminServer
	localAdminServer = p.server
	serverMu.Unlock()

	if p.server != nil {
		adminLogger := Log().Named("admin")
		go func() {
			if err := p.server.Serve(p.listener); !errors.Is(err, http.ErrServerClosed) {
				adminLogger.Error("admin server shutdown for unknown reason", zap.Error(err))
			}
		}()

		adminLogger.Info("admin endpoint started",
			zap.String("address", p.addr.String()),
			zap.Bool("enforce_origin", p.cfg.EnforceOrigin),
			zap.Array("origins", loggableURLArray(p.handler.allowedOrigins)))

		if !p.handler.enforceHost {
			adminLogger.Warn("admin endpoint on open interface; host checking disabled",
				zap.String("address", p.addr.String()))
		}
	}
	p.committed = true

	if oldAdminServer != nil {
		go func(oldAdminServer *http.Server) {
			err := stopAdminServer(oldAdminServer)
			if err != nil {
				Log().Named("admin").Error("stopping current admin endpoint", zap.Error(err))
			}
		}(oldAdminServer)
	}
}

func (p *preparedLocalAdminServer) Rollback() error {
	if p == nil || p.committed || p.listener == nil {
		return nil
	}
	return p.listener.Close()
}

type preparedRemoteAdminServer struct {
	server   *http.Server
	listener net.Listener
	addr     NetworkAddress

	committed bool
}

func prepareRemoteAdminServer(ctx Context, cfg *Config) (*preparedRemoteAdminServer, error) {
	if cfg == nil {
		return nil, nil
	}

	prepared := new(preparedRemoteAdminServer)
	if cfg.Admin == nil || cfg.Admin.Remote == nil {
		return prepared, nil
	}

	remoteLogger := Log().Named("admin.remote")
	addr, err := parseAdminListenAddr(cfg.Admin.Remote.Listen, DefaultRemoteAdminListen)
	if err != nil {
		return nil, err
	}
	prepared.addr = addr

	// make the HTTP handler but disable Host/Origin enforcement
	// because we are using TLS authentication instead
	handler, err := cfg.Admin.newAdminHandler(addr, true, ctx)
	if err != nil {
		return nil, err
	}

	// create client certificate pool for TLS mutual auth, and extract public keys
	// so that we can enforce access controls at the application layer
	clientCertPool := x509.NewCertPool()
	for i, accessControl := range cfg.Admin.Remote.AccessControl {
		for j, certBase64 := range accessControl.PublicKeys {
			cert, err := decodeBase64DERCert(certBase64)
			if err != nil {
				return nil, fmt.Errorf("access control %d public key %d: parsing base64 certificate DER: %v", i, j, err)
			}
			accessControl.publicKeys = append(accessControl.publicKeys, cert.PublicKey)
			clientCertPool.AddCert(cert)
		}
		for j, perm := range accessControl.Permissions {
			for _, permPath := range perm.Paths {
				if permPath == "" || permPath == "/" {
					continue
				}
				cleanPath := path.Clean(permPath)
				hasCanonicalTrailingSlash := cleanPath != "/" && strings.TrimSuffix(permPath, "/") == cleanPath
				if cleanPath != permPath && !hasCanonicalTrailingSlash {
					return nil, fmt.Errorf("access control %d permission %d: path %q is not canonical (did you mean %q?)", i, j, permPath, cleanPath)
				}
			}
		}
	}

	if identityCertCache == nil {
		return nil, fmt.Errorf("cannot enable remote admin without a certificate cache; configure identity management to initialize a certificate cache")
	}
	cmCfg := cfg.Admin.Identity.certmagicConfig(remoteLogger, false)
	tlsConfig := cmCfg.TLSConfig()
	tlsConfig.NextProtos = nil // this server does not solve ACME challenges
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = clientCertPool

	serverLogger, err := zap.NewStdLogAt(remoteLogger, zap.DebugLevel)
	if err != nil {
		return nil, err
	}

	lnAny, err := addr.Listen(ctx, 0, net.ListenConfig{})
	if err != nil {
		return nil, err
	}
	prepared.listener = tls.NewListener(lnAny.(net.Listener), tlsConfig)
	prepared.server = &http.Server{
		Addr:              addr.String(), // for logging purposes only
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1024 * 64,
		ErrorLog:          serverLogger,
	}
	return prepared, nil
}

func (p *preparedRemoteAdminServer) Commit() {
	if p == nil {
		return
	}

	var oldAdminServer *http.Server
	serverMu.Lock()
	oldAdminServer = remoteAdminServer
	remoteAdminServer = p.server
	serverMu.Unlock()

	if p.server != nil {
		remoteLogger := Log().Named("admin.remote")
		go func() {
			if err := p.server.Serve(p.listener); !errors.Is(err, http.ErrServerClosed) {
				remoteLogger.Error("admin remote server shutdown for unknown reason", zap.Error(err))
			}
		}()
		remoteLogger.Info("secure admin remote control endpoint started",
			zap.String("address", p.addr.String()))
	}
	p.committed = true

	if oldAdminServer != nil {
		go func(oldAdminServer *http.Server) {
			err := stopAdminServer(oldAdminServer)
			if err != nil {
				Log().Named("admin").Error("stopping current secure admin endpoint", zap.Error(err))
			}
		}(oldAdminServer)
	}
}

func (p *preparedRemoteAdminServer) Rollback() error {
	if p == nil || p.committed || p.listener == nil {
		return nil
	}
	return p.listener.Close()
}

type preparedIdentity struct {
	old *certmagic.Cache
	new *certmagic.Cache
}

func prepareIdentity(ctx Context, cfg *Config) (*preparedIdentity, error) {
	prepared := &preparedIdentity{}
	if cfg == nil || cfg.Admin == nil || cfg.Admin.Identity == nil {
		return prepared, nil
	}

	if cfg.Admin.Identity.IssuersRaw == nil {
		cfg.Admin.Identity.IssuersRaw = []json.RawMessage{
			json.RawMessage(`{"module": "acme"}`),
		}
	}

	val, err := ctx.LoadModule(cfg.Admin.Identity, "IssuersRaw")
	if err != nil {
		return nil, fmt.Errorf("loading identity issuer modules: %s", err)
	}
	for _, issVal := range val.([]any) {
		cfg.Admin.Identity.issuers = append(cfg.Admin.Identity.issuers, issVal.(certmagic.Issuer))
	}

	prepared.old = identityCertCache
	logger := Log().Named("admin.identity")
	cmCfg := cfg.Admin.Identity.certmagicConfig(logger, true)
	prepared.new = identityCertCache

	for _, issuer := range cfg.Admin.Identity.issuers {
		if setter, ok := issuer.(interface{ SetConfig(cfg *certmagic.Config) }); ok {
			setter.SetConfig(cmCfg)
		}
	}

	if err := cmCfg.ManageAsync(ctx, cfg.Admin.Identity.Identifiers); err != nil {
		prepared.Rollback()
		return nil, err
	}
	return prepared, nil
}

func (p *preparedIdentity) Commit() {
	if p == nil || p.new == nil || p.old == nil || p.old == p.new {
		return
	}
	p.old.Stop()
}

func (p *preparedIdentity) Rollback() {
	if p == nil {
		return
	}
	identityCertCache = p.old
	if p.new != nil && p.new != p.old {
		p.new.Stop()
	}
}
