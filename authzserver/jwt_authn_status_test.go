// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

// withJWTAuthnFailure attaches the dynamic metadata Envoy's jwt_authn filter
// writes via failed_status_in_metadata.
func withJWTAuthnFailure(req *authv3.CheckRequest, code float64, message string) *authv3.CheckRequest {
	req.Attributes.MetadataContext = &corev3.Metadata{
		FilterMetadata: map[string]*structpb.Struct{
			JWTAuthnMetadataNamespace: {
				Fields: map[string]*structpb.Value{
					JWTAuthnFailedStatusKey: structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							jwtAuthnStatusCodeField:    structpb.NewNumberValue(code),
							jwtAuthnStatusMessageField: structpb.NewStringValue(message),
						},
					}),
				},
			},
		},
	}

	return req
}

func TestJWTAuthnFailureFromRequest(t *testing.T) {
	t.Run("reads code and message", func(t *testing.T) {
		req := withJWTAuthnFailure(makeCheckRequest("/api/test", nil), 3, "Jwt expired")

		failure, ok := jwtAuthnFailureFromRequest(req)
		if !ok {
			t.Fatal("expected a recorded failure")
		}

		if failure.Code != 3 || failure.Message != "Jwt expired" {
			t.Fatalf("got code %d message %q", failure.Code, failure.Message)
		}
	})

	t.Run("absent when no metadata context", func(t *testing.T) {
		if _, ok := jwtAuthnFailureFromRequest(makeCheckRequest("/api/test", nil)); ok {
			t.Fatal("expected no failure without metadata")
		}
	})

	t.Run("absent when namespace holds no status", func(t *testing.T) {
		req := makeCheckRequest("/api/test", nil)
		req.Attributes.MetadataContext = &corev3.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				JWTAuthnMetadataNamespace: {Fields: map[string]*structpb.Value{}},
			},
		}

		if _, ok := jwtAuthnFailureFromRequest(req); ok {
			t.Fatal("expected no failure without a status struct")
		}
	})

	t.Run("absent when message is blank", func(t *testing.T) {
		req := withJWTAuthnFailure(makeCheckRequest("/api/test", nil), 3, "   ")

		if _, ok := jwtAuthnFailureFromRequest(req); ok {
			t.Fatal("expected no failure for a blank message")
		}
	})
}

//nolint:cyclop // Test function with multiple subtests; high complexity is acceptable.
func TestOIDCAuthorizationServer_Check_RefusedOIDCToken(t *testing.T) {
	const workloadID = "spiffe://example.org/ns/default/sa/workload"

	cfg := validOIDCConfig()
	ctx := t.Context()

	// An expired OIDC token reaches the SVID path because allow_missing_or_failed
	// lets refused tokens through. The reported reason must be the OIDC one.
	t.Run("expired token reports expiry, not a SPIFFE subject error", func(t *testing.T) {
		validator := &mockJWTValidator{err: fmt.Errorf("jwtsvid: token has an invalid subject claim: scheme is missing or invalid")}

		srv, err := NewOIDCAuthorizationServer(ctx, cfg, slog.Default(), WithJWTValidator(validator))
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		req := withJWTAuthnFailure(
			makeCheckRequest("/api/test", map[string]string{"Authorization": "Bearer expired.github.token"}),
			3, "Jwt expired",
		)

		resp, err := srv.Check(ctx, req)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}

		if resp.GetStatus().GetCode() != int32(codes.Unauthenticated) {
			t.Fatalf("expected Unauthenticated, got code %d", resp.GetStatus().GetCode())
		}

		message := resp.GetStatus().GetMessage()
		if !strings.Contains(message, "Jwt expired") {
			t.Errorf("expected the jwt_authn reason in %q", message)
		}

		if strings.Contains(message, "JWT-SVID") {
			t.Errorf("expected no SVID wording in %q", message)
		}
	})

	t.Run("valid JWT-SVID still authorizes when a provider recorded a failure", func(t *testing.T) {
		srv, err := NewOIDCAuthorizationServer(ctx, cfg, slog.Default(), WithJWTValidator(&mockJWTValidator{spiffeID: workloadID}))
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		// A federated SVID matches no OIDC issuer, so a provider may still record
		// a failure for it. That must not override successful SVID validation.
		req := withJWTAuthnFailure(
			makeCheckRequest("/api/test", map[string]string{"Authorization": "Bearer svid.token"}),
			14, "Jwt issuer is not configured",
		)

		resp, err := srv.Check(ctx, req)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}

		if resp.GetStatus().GetCode() != int32(codes.OK) {
			t.Fatalf("expected OK, got code %d", resp.GetStatus().GetCode())
		}
	})

	t.Run("SVID failure without recorded status keeps the SVID error", func(t *testing.T) {
		srv, err := NewOIDCAuthorizationServer(ctx, cfg, slog.Default(), WithJWTValidator(&mockJWTValidator{err: fmt.Errorf("invalid signature")}))
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		req := makeCheckRequest("/api/test", map[string]string{"Authorization": "Bearer bad.svid"})

		resp, err := srv.Check(ctx, req)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}

		if !strings.Contains(resp.GetStatus().GetMessage(), "invalid JWT-SVID") {
			t.Errorf("expected the SVID error, got %q", resp.GetStatus().GetMessage())
		}
	})

	t.Run("refused token reports expiry when SVID validation is disabled", func(t *testing.T) {
		srv, err := NewOIDCAuthorizationServer(ctx, cfg, slog.Default())
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		req := withJWTAuthnFailure(
			makeCheckRequest("/api/test", map[string]string{"Authorization": "Bearer expired.github.token"}),
			3, "Jwt expired",
		)

		resp, err := srv.Check(ctx, req)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}

		if resp.GetStatus().GetCode() != int32(codes.Unauthenticated) {
			t.Fatalf("expected Unauthenticated, got code %d", resp.GetStatus().GetCode())
		}

		if !strings.Contains(resp.GetStatus().GetMessage(), "Jwt expired") {
			t.Errorf("expected the jwt_authn reason, got %q", resp.GetStatus().GetMessage())
		}
	})
}
