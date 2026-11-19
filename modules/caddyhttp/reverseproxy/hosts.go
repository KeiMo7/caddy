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

package reverseproxy

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// UpstreamPool is a collection of upstreams.
type UpstreamPool []*Upstream

// Upstream bridges this proxy's configuration to the
// state of the backend host it is correlated with.
// Upstream values must not be copied.
type Upstream struct {
	*Host `json:"-"`

	// The [network address](/docs/conventions#network-addresses)
	// to dial to connect to the upstream. Must represent precisely
	// one socket (i.e. no port ranges). A valid network address
	// either has a host and port or is a unix socket address.
	//
	// Placeholders may be used to make the upstream dynamic, but be
	// aware of the health check implications of this: a single
	// upstream that represents numerous (perhaps arbitrary) backends
	// can be considered down if one or enough of the arbitrary
	// backends is down. Also be aware of open proxy vulnerabilities.
	Dial string `json:"dial,omitempty"`

	// The maximum number of simultaneous requests to allow to
	// this upstream. If set, overrides the global passive health
	// check UnhealthyRequestCount value.
	MaxRequests int `json:"max_requests,omitempty"`

	// HealthGroup optionally assigns this upstream to a named active
	// health check group configured in HealthChecks.Active.Groups.
	HealthGroup string `json:"health_group,omitempty"`

	// TODO: This could be really useful, to bind requests
	// with certain properties to specific backends
	// HeaderAffinity string
	// IPAffinity     string

	activeHealthCheckPort     int
	activeHealthCheckUpstream string
	healthCheckPolicy         *PassiveHealthChecks
	cb                        CircuitBreaker

	// state from the active health checker. It lives here rather than on
	// the shared Host because the Host is keyed by dial address alone,
	// while an active health check is configured per handler: two handlers
	// dialing the same address with different health_uri or health_headers
	// are checking distinct health targets, and must not push each other
	// over their own consecutive pass/fail thresholds.
	unhealthy    atomic.Int32
	activePasses atomic.Int64
	activeFails  atomic.Int64

	healthStateOnce sync.Once
	healthState     *HealthStateMachine
	probeInFlight   atomic.Bool
	probeSeq        atomic.Uint64
	overlapSkipped  atomic.Uint64
	rampAdmissions  atomic.Uint64
	manualRemoval   atomic.Bool
	loadFactorBits  atomic.Uint64
}

// (pointer receiver necessary to avoid a race condition, since
// copying the Upstream reads the 'unhealthy' field which is
// accessed atomically)
func (u *Upstream) String() string { return u.Dial }

// Available returns true if the remote host
// is available to receive requests. This is
// the method that should be used by selection
// policies, etc. to determine if a backend
// should be able to be sent a request.
func (u *Upstream) Available() bool {
	if u.Full() || u.ManualUnhealthy() || !u.healthPolicyOK() {
		return false
	}
	factor := u.LoadFactor()
	if factor >= 1 {
		return u.unhealthy.Load() == 0
	}
	if factor <= 0 {
		return false
	}
	const admissions = 1000
	slot := u.rampAdmissions.Add(1) % admissions
	return slot < uint64(factor*admissions)
}

// Healthy returns true if the remote host
// is currently known to be healthy or "up".
// It consults the circuit breaker, if any.
func (u *Upstream) Healthy() bool {
	return !u.ManualUnhealthy() && u.healthy() && u.healthPolicyOK()
}

// Full returns true if the remote host
// cannot receive more requests at this time.
func (u *Upstream) Full() bool {
	return u.MaxRequests > 0 && u.Host.NumRequests() >= u.MaxRequests
}

func (u *Upstream) healthPolicyOK() bool {
	if u.Host != nil && u.healthCheckPolicy != nil && u.Host.Fails() >= u.healthCheckPolicy.MaxFails {
		return false
	}
	return u.cb == nil || u.cb.OK()
}

// LoadFactor returns the fraction of health-check admission slots currently
// allowed for this upstream. It is 0 while unavailable, 1 when fully healthy,
// and between 0 and 1 while a recovery ramp is in progress.
func (u *Upstream) LoadFactor() float64 {
	bits := u.loadFactorBits.Load()
	if bits == 0 {
		if u.unhealthy.Load() == 0 {
			return 1
		}
		return 0
	}
	factor := math.Float64frombits(bits)
	if factor < 0 {
		return 0
	}
	if factor > 1 {
		return 1
	}
	return factor
}

// HealthSnapshot returns a read-only snapshot of this upstream's active
// health state. It never performs a probe or changes recovery timers.
func (u *Upstream) HealthSnapshot(now time.Time) (HealthStateSnapshot, bool) {
	if u.healthState == nil {
		return HealthStateSnapshot{}, false
	}
	snapshot := u.healthState.Snapshot(now)
	snapshot.Address = u.Dial
	snapshot.Group = u.HealthGroup
	snapshot.OverlapsSkipped = u.overlapSkipped.Load()
	return snapshot, true
}

// ManualUnhealthy reports whether traffic is manually disabled for this
// upstream. Manual removal always takes precedence over automatic recovery.
func (u *Upstream) ManualUnhealthy() bool {
	return u.manualRemoval.Load()
}

// SetManualUnhealthy manually removes an upstream from service, or clears a
// previous manual removal. Automatic health checks continue to run while the
// override is active, but cannot make the upstream available.
func (u *Upstream) SetManualUnhealthy(removed bool, reason string) bool {
	u.manualRemoval.Store(removed)
	if u.healthState != nil {
		_, _ = u.healthState.SetManualRemoval(removed, reason, time.Now())
	}
	if removed {
		u.unhealthy.Store(1)
		u.loadFactorBits.Store(math.Float64bits(0))
		return true
	}
	if u.healthState == nil {
		u.unhealthy.Store(0)
		u.loadFactorBits.Store(math.Float64bits(1))
		return true
	}
	u.applyHealthState()
	return true
}

// SetManuallyUnhealthy is an alias for SetManualUnhealthy.
func (u *Upstream) SetManuallyUnhealthy(removed bool, reason string) bool {
	return u.SetManualUnhealthy(removed, reason)
}

// ensureHealthState initializes the per-upstream state machine once.
func (u *Upstream) ensureHealthState(cfg HealthStateConfig) *HealthStateMachine {
	u.healthStateOnce.Do(func() {
		u.healthState = NewHealthStateMachine(cfg)
	})
	return u.healthState
}

// applyHealthState copies the machine's current load factor into the hot-path
// atomics used by selection policies.
func (u *Upstream) applyHealthState() {
	if u.healthState == nil {
		return
	}
	snapshot := u.healthState.Snapshot(time.Now())
	if snapshot.ManualRemoval {
		u.unhealthy.Store(1)
		u.loadFactorBits.Store(math.Float64bits(0))
		return
	}
	factor := snapshot.LoadFactor
	u.loadFactorBits.Store(math.Float64bits(factor))
	if snapshot.AutomaticState == HealthStateHealthy {
		u.unhealthy.Store(0)
	} else {
		u.unhealthy.Store(1)
	}
}

// fillDialInfo returns a filled DialInfo for upstream u, using the request
// context. Note that the returned value is not a pointer.
func (u *Upstream) fillDialInfo(repl *caddy.Replacer) (DialInfo, error) {
	var addr caddy.NetworkAddress

	// use provided dial address
	var err error
	dial := repl.ReplaceAll(u.Dial, "")
	addr, err = caddy.ParseNetworkAddress(dial)
	if err != nil {
		return DialInfo{}, fmt.Errorf("upstream %s: invalid dial address %s: %v", u.Dial, dial, err)
	}
	if numPorts := addr.PortRangeSize(); numPorts != 1 {
		return DialInfo{}, fmt.Errorf("upstream %s: dial address must represent precisely one socket: %s represents %d",
			u.Dial, dial, numPorts)
	}

	return DialInfo{
		Upstream: u,
		Network:  addr.Network,
		Address:  addr.JoinHostPort(0),
		Host:     addr.Host,
		Port:     strconv.Itoa(int(addr.StartPort)),
	}, nil
}

func (u *Upstream) fillHost() {
	host := new(Host)
	existingHost, loaded := hosts.LoadOrStore(u.String(), host)
	if loaded {
		host = existingHost.(*Host)
	}
	u.Host = host
}

// fillDynamicHost is like fillHost, but stores the host in the separate
// dynamicHosts map rather than the reference-counted UsagePool. Dynamic
// hosts are not reference-counted; instead, they are retained as long as
// they are actively seen and are evicted by a background cleanup goroutine
// after dynamicHostIdleExpiry of inactivity. This preserves health state
// (e.g. passive fail counts) across sequential requests.
func (u *Upstream) fillDynamicHost() {
	dynamicHostsMu.Lock()
	entry, ok := dynamicHosts[u.String()]
	if ok {
		entry.lastSeen = time.Now()
		dynamicHosts[u.String()] = entry
		u.Host = entry.host
	} else {
		h := new(Host)
		dynamicHosts[u.String()] = dynamicHostEntry{host: h, lastSeen: time.Now()}
		u.Host = h
	}
	dynamicHostsMu.Unlock()

	// ensure the cleanup goroutine is running
	dynamicHostsCleanerOnce.Do(func() {
		go func() {
			for {
				time.Sleep(dynamicHostCleanupInterval)
				dynamicHostsMu.Lock()
				for addr, entry := range dynamicHosts {
					if time.Since(entry.lastSeen) > dynamicHostIdleExpiry {
						delete(dynamicHosts, addr)
					}
				}
				dynamicHostsMu.Unlock()
			}
		}()
	})
}

// Host is the basic, in-memory representation of the state of a remote host.
// Its fields are accessed atomically and Host values must not be copied.
type Host struct {
	numRequests atomic.Int64
	fails       atomic.Int64
}

// NumRequests returns the number of active requests to the upstream.
func (h *Host) NumRequests() int {
	return int(h.numRequests.Load())
}

// Fails returns the number of recent failures with the upstream.
func (h *Host) Fails() int {
	return int(h.fails.Load())
}

// countRequest mutates the active request count by
// delta. It returns an error if the adjustment fails.
func (h *Host) countRequest(delta int) error {
	result := h.numRequests.Add(int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// countFail mutates the recent failures count by
// delta. It returns an error if the adjustment fails.
func (h *Host) countFail(delta int) error {
	result := h.fails.Add(int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// activeHealthPasses returns the number of consecutive passing
// active health checks observed by this upstream's checker.
func (u *Upstream) activeHealthPasses() int {
	return int(u.activePasses.Load())
}

// activeHealthFails returns the number of consecutive failing
// active health checks observed by this upstream's checker.
func (u *Upstream) activeHealthFails() int {
	return int(u.activeFails.Load())
}

// countHealthPass mutates the recent passes count by
// delta. It returns an error if the adjustment fails.
func (u *Upstream) countHealthPass(delta int) error {
	result := u.activePasses.Add(int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// countHealthFail mutates the recent failures count by
// delta. It returns an error if the adjustment fails.
func (u *Upstream) countHealthFail(delta int) error {
	result := u.activeFails.Add(int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// resetHealth resets the health check counters.
func (u *Upstream) resetHealth() {
	u.activePasses.Store(0)
	u.activeFails.Store(0)
}

// healthy returns true if the upstream is not actively marked as unhealthy.
// (This returns the status only from the "active" health checks.)
func (u *Upstream) healthy() bool {
	return u.unhealthy.Load() == 0
}

// SetHealthy sets the upstream has healthy or unhealthy
// and returns true if the new value is different. This
// sets the status only for the "active" health checks.
func (u *Upstream) setHealthy(healthy bool) bool {
	var unhealthy, compare int32 = 1, 0
	if healthy {
		unhealthy, compare = 0, 1
	}
	changed := u.unhealthy.CompareAndSwap(compare, unhealthy)
	if changed {
		if healthy {
			u.loadFactorBits.Store(math.Float64bits(1))
		} else {
			u.loadFactorBits.Store(math.Float64bits(0))
		}
	}
	return changed
}

// DialInfo contains information needed to dial a
// connection to an upstream host. This information
// may be different than that which is represented
// in a URL (for example, unix sockets don't have
// a host that can be represented in a URL, but
// they certainly have a network name and address).
type DialInfo struct {
	// Upstream is the Upstream associated with
	// this DialInfo. It may be nil.
	Upstream *Upstream

	// The network to use. This should be one of
	// the values that is accepted by net.Dial:
	// https://golang.org/pkg/net/#Dial
	Network string

	// The address to dial. Follows the same
	// semantics and rules as net.Dial.
	Address string

	// Host and Port are components of Address.
	Host, Port string
}

// String returns the Caddy network address form
// by joining the network and address with a
// forward slash.
func (di DialInfo) String() string {
	return caddy.JoinNetworkAddress(di.Network, di.Host, di.Port)
}

// GetDialInfo gets the upstream dialing info out of the context,
// and returns true if there was a valid value; false otherwise.
func GetDialInfo(ctx context.Context) (DialInfo, bool) {
	dialInfo, ok := ctx.Value(dialInfoCtxKey).(DialInfo)
	return dialInfo, ok
}

// hosts is the global repository for hosts that are
// currently in use by active configuration(s). This
// allows the state of remote hosts to be preserved
// through config reloads.
var hosts = caddy.NewUsagePool()

// dynamicHosts tracks hosts that were provisioned from dynamic upstream
// sources. Unlike static upstreams which are reference-counted via the
// UsagePool, dynamic upstream hosts are not reference-counted. Instead,
// their last-seen time is updated on each request, and a background
// goroutine evicts entries that have been idle for dynamicHostIdleExpiry.
// This preserves health state (e.g. passive fail counts) across requests
// to the same dynamic backend.
var (
	dynamicHosts               = make(map[string]dynamicHostEntry)
	dynamicHostsMu             sync.RWMutex
	dynamicHostsCleanerOnce    sync.Once
	dynamicHostCleanupInterval = 5 * time.Minute
	dynamicHostIdleExpiry      = time.Hour
)

// dynamicHostEntry holds a Host and the last time it was seen
// in a set of dynamic upstreams returned for a request.
type dynamicHostEntry struct {
	host     *Host
	lastSeen time.Time
}

// dialInfoCtxKey is the context key used for the variable that holds
// the dial info for the upstream connection.
const dialInfoCtxKey caddy.CtxKey = "reverse_proxy.dial_info"

// proxyProtocolInfoVarKey is the key used for the variable that holds
// the proxy protocol info for the upstream connection.
const proxyProtocolInfoVarKey = "reverse_proxy.proxy_protocol_info"

// ProxyProtocolInfo contains information needed to write proxy protocol to a
// connection to an upstream host.
type ProxyProtocolInfo struct {
	AddrPort netip.AddrPort
}

// tlsH1OnlyVarKey is the key used that indicates the connection will use h1 only for TLS.
// https://github.com/caddyserver/caddy/issues/7292
const tlsH1OnlyVarKey = "reverse_proxy.tls_h1_only"

// proxyVarKey is the key used that indicates the proxy server used for a request.
const proxyVarKey = "reverse_proxy.proxy"
