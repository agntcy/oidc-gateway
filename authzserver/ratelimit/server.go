// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	ratelimitv3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"golang.org/x/time/rate"
)

type RateLimitServer struct {
	ratelimitv3.UnimplementedRateLimitServiceServer

	config                *RateLimitConfig
	logger                *slog.Logger
	authPrincipalHeader   string
	anonymousLimiter      *rate.Limiter
	authenticatedLimiters sync.Map
}

// NewRateLimitServer creates a rate limit service backed by in-memory token buckets.
func NewRateLimitServer(
	config *RateLimitConfig,
	logger *slog.Logger,
	authPrincipalHeader string,
) (*RateLimitServer, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &RateLimitServer{
		config:              config,
		logger:              logger,
		authPrincipalHeader: authPrincipalHeader,
		anonymousLimiter: rate.NewLimiter(
			rate.Limit(config.Anonymous.RPS),
			int(config.Anonymous.Burst),
		),
	}, nil
}

// ShouldRateLimit implements the Envoy RateLimitService API.
func (s *RateLimitServer) ShouldRateLimit(_ context.Context, req *ratelimitv3.RateLimitRequest) (*ratelimitv3.RateLimitResponse, error) {
	if req.GetDomain() != s.config.Domain {
		return overLimitResponse(len(req.GetDescriptors())), nil
	}

	authPrincipal := s.getAuthPrincipal(req)
	limiter := s.getLimiterForRequest(authPrincipal)

	if !limiter.Allow() {
		s.logger.Warn("Rate limit exceeded", "authPrincipal", authPrincipal)

		return overLimitResponse(len(req.GetDescriptors())), nil
	}

	return okResponse(len(req.GetDescriptors())), nil
}

func (s *RateLimitServer) getAuthPrincipal(req *ratelimitv3.RateLimitRequest) string {
	for _, descriptor := range req.GetDescriptors() {
		for _, entry := range descriptor.GetEntries() {
			if strings.EqualFold(entry.GetKey(), s.authPrincipalHeader) {
				return entry.GetValue()
			}
		}
	}

	return ""
}

func (s *RateLimitServer) getLimiterForRequest(authPrincipal string) *rate.Limiter {
	if authPrincipal != "" && s.config.Authenticated.Enabled {
		return s.getOrCreateAuthenticatedLimiter(
			authPrincipal,
			s.config.Authenticated.RPS,
			s.config.Authenticated.Burst,
		)
	}

	return s.anonymousLimiter
}

func (s *RateLimitServer) getOrCreateAuthenticatedLimiter(key string, rps uint32, burst uint32) *rate.Limiter {
	if value, exists := s.authenticatedLimiters.Load(key); exists {
		limiter, ok := value.(*rate.Limiter)
		if !ok {
			// This should never happen as we control what goes into the map
			panic(fmt.Sprintf("invalid type in limiters map: expected *rate.Limiter, got %T", value))
		}

		return limiter
	}

	// If RPS is zero, don't create a limiter (unlimited)
	if rps == 0 {
		return nil
	}

	// Slow path: create new limiter
	// Use LoadOrStore to handle race conditions (multiple goroutines creating for same key)
	newLimiter := rate.NewLimiter(rate.Limit(rps), int(burst))
	actual, loaded := s.authenticatedLimiters.LoadOrStore(key, newLimiter)

	if !loaded {
		s.logger.Debug("Created new rate limiter",
			"key", key,
			"rps", rps,
			"burst", burst,
		)
	}

	limiter, ok := actual.(*rate.Limiter)
	if !ok {
		// This should never happen as we control what goes into the map
		panic(fmt.Sprintf("invalid type in limiters map: expected *rate.Limiter, got %T", actual))
	}

	return limiter
}

func overLimitResponse(descriptorCount int) *ratelimitv3.RateLimitResponse {
	statuses := make([]*ratelimitv3.RateLimitResponse_DescriptorStatus, descriptorCount)
	for i := range statuses {
		statuses[i] = &ratelimitv3.RateLimitResponse_DescriptorStatus{
			Code: ratelimitv3.RateLimitResponse_OVER_LIMIT,
		}
	}

	return &ratelimitv3.RateLimitResponse{
		OverallCode: ratelimitv3.RateLimitResponse_OVER_LIMIT,
		Statuses:    statuses,
	}
}

func okResponse(descriptorCount int) *ratelimitv3.RateLimitResponse {
	statuses := make([]*ratelimitv3.RateLimitResponse_DescriptorStatus, descriptorCount)
	for i := range statuses {
		statuses[i] = &ratelimitv3.RateLimitResponse_DescriptorStatus{
			Code: ratelimitv3.RateLimitResponse_OK,
		}
	}

	return &ratelimitv3.RateLimitResponse{
		OverallCode: ratelimitv3.RateLimitResponse_OK,
		Statuses:    statuses,
	}
}
