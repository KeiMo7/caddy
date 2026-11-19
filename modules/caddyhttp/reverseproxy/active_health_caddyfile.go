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
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// parseFlapDetectionBlock parses the body of a flap detection block. The
// dispenser must currently point at the directive that owns the block.
func parseFlapDetectionBlock(d *caddyfile.Dispenser) (*FlapDetection, error) {
	flap := new(FlapDetection)
	nesting := d.Nesting()
	for d.NextBlock(nesting) {
		if err := parseFlapDetectionDirective(d, flap); err != nil {
			return nil, err
		}
	}
	return flap, nil
}

func parseFlapDetectionDirective(d *caddyfile.Dispenser, flap *FlapDetection) error {
	switch d.Val() {
	case "window":
		duration, err := parseCaddyfilePositiveDuration(d)
		if err != nil {
			return err
		}
		flap.Window = caddy.Duration(duration)
		flap.windowSet = true

	case "threshold":
		value, err := parseCaddyfilePositiveInt(d)
		if err != nil {
			return err
		}
		flap.Threshold = value
		flap.thresholdSet = true

	case "observation":
		duration, err := parseCaddyfilePositiveDuration(d)
		if err != nil {
			return err
		}
		flap.Observation = caddy.Duration(duration)
		flap.observationSet = true

	case "ramp":
		if !d.NextArg() {
			return d.ArgErr()
		}
		duration, err := caddy.ParseDuration(d.Val())
		if err != nil {
			return d.Errf("bad ramp duration %s: %v", d.Val(), err)
		}
		if duration < 0 {
			return d.Errf("ramp duration cannot be negative")
		}
		flap.Ramp = caddy.Duration(duration)
		flap.rampSet = true
		if d.NextArg() {
			return d.ArgErr()
		}

	case "ramp_curve":
		if !d.NextArg() {
			return d.ArgErr()
		}
		curve := strings.ToLower(strings.TrimSpace(d.Val()))
		switch curve {
		case "linear", "exponential", "step":
		default:
			return d.Errf("ramp_curve must be one of linear, exponential, or step")
		}
		flap.RampCurve = curve
		if d.NextArg() {
			return d.ArgErr()
		}

	case "result_history":
		value, err := parseCaddyfilePositiveInt(d)
		if err != nil {
			return err
		}
		flap.ResultHistory = value
		flap.resultHistorySet = true

	case "transition_history":
		value, err := parseCaddyfilePositiveInt(d)
		if err != nil {
			return err
		}
		flap.TransitionHistory = value
		flap.transitionHistorySet = true

	default:
		return d.Errf("unrecognized flap_detection subdirective: %s", d.Val())
	}
	return nil
}

func parseActiveHealthGroupBlock(d *caddyfile.Dispenser, group *ActiveHealthGroup) error {
	nesting := d.Nesting()
	for d.NextBlock(nesting) {
		switch d.Val() {
		case "to", "upstreams":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			group.Upstreams = append(group.Upstreams, args...)

		case "fails", "health_fails":
			value, err := parseCaddyfilePositiveInt(d)
			if err != nil {
				return err
			}
			group.Fails = value

		case "passes", "health_passes":
			value, err := parseCaddyfilePositiveInt(d)
			if err != nil {
				return err
			}
			group.Passes = value

		case "flap_detection":
			if d.NextArg() {
				return d.ArgErr()
			}
			flap, err := parseFlapDetectionBlock(d)
			if err != nil {
				return err
			}
			group.FlapDetection = flap

		default:
			flap := group.FlapDetection
			if flap == nil {
				flap = new(FlapDetection)
				group.FlapDetection = flap
			}
			if err := parseFlapDetectionDirective(d, flap); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseCaddyfilePositiveDuration(d *caddyfile.Dispenser) (caddy.Duration, error) {
	if !d.NextArg() {
		return 0, d.ArgErr()
	}
	duration, err := caddy.ParseDuration(d.Val())
	if err != nil {
		return 0, d.Errf("bad duration value %s: %v", d.Val(), err)
	}
	if duration <= 0 {
		return 0, d.Errf("duration must be greater than zero")
	}
	if d.NextArg() {
		return 0, d.ArgErr()
	}
	return caddy.Duration(duration), nil
}

func parseCaddyfilePositiveInt(d *caddyfile.Dispenser) (int, error) {
	if !d.NextArg() {
		return 0, d.ArgErr()
	}
	value, err := strconv.Atoi(d.Val())
	if err != nil {
		return 0, d.Errf("invalid integer '%s': %v", d.Val(), err)
	}
	if value <= 0 {
		return 0, d.Errf("value must be greater than zero")
	}
	if d.NextArg() {
		return 0, d.ArgErr()
	}
	return value, nil
}
