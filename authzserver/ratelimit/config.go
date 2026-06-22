// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"fmt"
)

type RateLimitConfig struct {
	Domain        string          `yaml:"domain"`
	Authenticated RateLimitValues `yaml:"authenticated"`
	Anonymous     RateLimitValues `yaml:"anonymous"`
}

type RateLimitValues struct {
	Enabled bool   `yaml:"enabled"`
	RPS     uint32 `yaml:"rps"`
	Burst   uint32 `yaml:"burst"`
}

func (c *RateLimitConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.Authenticated.Enabled {
		if c.Authenticated.RPS <= 0 {
			return fmt.Errorf(
				"ratelimit.authenticated.rps must be greater than 0 " +
					"if ratelimit.authenticated.enabled is true",
			)
		}

		if c.Authenticated.Burst <= 0 {
			return fmt.Errorf(
				"ratelimit.authenticated.burst must be greater than 0" +
					"if ratelimit.authenticated.enabled is true",
			)
		}

		if c.Authenticated.RPS > 0 &&
			c.Authenticated.Burst > 0 &&
			c.Authenticated.Burst < c.Authenticated.RPS {
			return fmt.Errorf(
				"ratelimit.authenticated.burst (%d) must be >= ratelimit.authenticated.rps (%d) "+
					"if ratelimit.authenticated.enabled is true",
				c.Authenticated.Burst,
				c.Authenticated.RPS,
			)
		}
	}

	if c.Anonymous.Enabled {
		if c.Anonymous.RPS <= 0 {
			return fmt.Errorf(
				"ratelimit.anonymous.rps must be greater than 0 " +
					"if ratelimit.anonymous.enabled is true",
			)
		}

		if c.Anonymous.Burst <= 0 {
			return fmt.Errorf(
				"ratelimit.anonymous.burst must be greater than 0 " +
					"if ratelimit.anonymous.enabled is true",
			)
		}

		if c.Anonymous.RPS > 0 &&
			c.Anonymous.Burst > 0 &&
			c.Anonymous.Burst < c.Anonymous.RPS {
			return fmt.Errorf(
				"ratelimit.anonymous.burst (%d) must be >= ratelimit.anonymous.rps (%d) "+
					"if ratelimit.anonymous.enabled is true",
				c.Anonymous.Burst,
				c.Anonymous.RPS,
			)
		}
	}

	return nil
}

func (c *RateLimitConfig) Enabled() bool {
	return c != nil && (c.Authenticated.Enabled || c.Anonymous.Enabled)
}
