// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"log/slog"
	"testing"

	commonrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	ratelimitv3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
)

const authPrincipalHeader = "x-auth-principal"

func rateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Domain: "oidc_gateway",
		Anonymous: RateLimitValues{
			Enabled: true,
			RPS:     1,
			Burst:   1,
		},
		Authenticated: RateLimitValues{
			Enabled: true,
			RPS:     2,
			Burst:   2,
		},
	}
}

func newTestServer(t *testing.T, cfg *RateLimitConfig) *RateLimitServer {
	t.Helper()

	server, err := NewRateLimitServer(cfg, slog.Default(), authPrincipalHeader)
	if err != nil {
		t.Fatalf("NewRateLimitServer() error = %v", err)
	}

	return server
}

func rateLimitRequest(domain string, descriptors ...*commonrlv3.RateLimitDescriptor) *ratelimitv3.RateLimitRequest {
	return &ratelimitv3.RateLimitRequest{
		Domain:      domain,
		Descriptors: descriptors,
	}
}

func anonymousDescriptor() *commonrlv3.RateLimitDescriptor {
	return &commonrlv3.RateLimitDescriptor{}
}

func authenticatedDescriptor(principal string) *commonrlv3.RateLimitDescriptor {
	return &commonrlv3.RateLimitDescriptor{
		Entries: []*commonrlv3.RateLimitDescriptor_Entry{
			{Key: authPrincipalHeader, Value: principal},
		},
	}
}

func TestRateLimitServer_AnonymousAndAuthenticated(t *testing.T) {
	cfg := rateLimitConfig()
	server := newTestServer(t, cfg)

	req := func(descriptor *commonrlv3.RateLimitDescriptor) *ratelimitv3.RateLimitRequest {
		return rateLimitRequest(cfg.Domain, descriptor)
	}

	firstAnonymous, err := server.ShouldRateLimit(t.Context(), req(anonymousDescriptor()))
	if err != nil {
		t.Fatalf("ShouldRateLimit(anonymous) error = %v", err)
	}

	if firstAnonymous.GetOverallCode() != ratelimitv3.RateLimitResponse_OK {
		t.Fatalf("expected first anonymous request to pass, got %v", firstAnonymous.GetOverallCode())
	}

	secondAnonymous, err := server.ShouldRateLimit(t.Context(), req(anonymousDescriptor()))
	if err != nil {
		t.Fatalf("ShouldRateLimit(anonymous) error = %v", err)
	}

	if secondAnonymous.GetOverallCode() != ratelimitv3.RateLimitResponse_OVER_LIMIT {
		t.Fatalf("expected second anonymous request to be over limit, got %v", secondAnonymous.GetOverallCode())
	}

	clientReq := req(authenticatedDescriptor("oidc:dex:admin@example.com"))

	firstClient, err := server.ShouldRateLimit(t.Context(), clientReq)
	if err != nil {
		t.Fatalf("ShouldRateLimit(authenticated) error = %v", err)
	}

	if firstClient.GetOverallCode() != ratelimitv3.RateLimitResponse_OK {
		t.Fatalf("expected first authenticated request to pass, got %v", firstClient.GetOverallCode())
	}

	secondClient, err := server.ShouldRateLimit(t.Context(), clientReq)
	if err != nil {
		t.Fatalf("ShouldRateLimit(authenticated) error = %v", err)
	}

	if secondClient.GetOverallCode() != ratelimitv3.RateLimitResponse_OK {
		t.Fatalf("expected second authenticated request to pass, got %v", secondClient.GetOverallCode())
	}

	thirdClient, err := server.ShouldRateLimit(t.Context(), clientReq)
	if err != nil {
		t.Fatalf("ShouldRateLimit(authenticated) error = %v", err)
	}

	if thirdClient.GetOverallCode() != ratelimitv3.RateLimitResponse_OVER_LIMIT {
		t.Fatalf("expected third authenticated request to be over limit, got %v", thirdClient.GetOverallCode())
	}
}

func TestRateLimitServer_AuthenticatedDisabledUsesAnonymousLimiter(t *testing.T) {
	cfg := rateLimitConfig()
	cfg.Authenticated.Enabled = false

	server := newTestServer(t, cfg)

	req := rateLimitRequest(
		cfg.Domain,
		authenticatedDescriptor("oidc:dex:admin@example.com"),
	)

	first, err := server.ShouldRateLimit(t.Context(), req)
	if err != nil {
		t.Fatalf("ShouldRateLimit() error = %v", err)
	}

	if first.GetOverallCode() != ratelimitv3.RateLimitResponse_OK {
		t.Fatalf("expected first request to pass, got %v", first.GetOverallCode())
	}

	second, err := server.ShouldRateLimit(t.Context(), req)
	if err != nil {
		t.Fatalf("ShouldRateLimit() error = %v", err)
	}

	if second.GetOverallCode() != ratelimitv3.RateLimitResponse_OVER_LIMIT {
		t.Fatalf("expected second request to be over limit, got %v", second.GetOverallCode())
	}
}

func TestRateLimitServer_WrongDomain(t *testing.T) {
	cfg := rateLimitConfig()
	server := newTestServer(t, cfg)

	resp, err := server.ShouldRateLimit(t.Context(), rateLimitRequest("wrong_domain", anonymousDescriptor()))
	if err != nil {
		t.Fatalf("ShouldRateLimit() error = %v", err)
	}

	if resp.GetOverallCode() != ratelimitv3.RateLimitResponse_OVER_LIMIT {
		t.Fatalf("expected wrong domain to be over limit, got %v", resp.GetOverallCode())
	}

	if len(resp.GetStatuses()) != 1 {
		t.Fatalf("expected 1 descriptor status, got %d", len(resp.GetStatuses()))
	}
}
