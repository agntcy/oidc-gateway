// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/agntcy/oidc-gateway/identity"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	authorizationHeader      = "authorization"
	authorizationHeaderParts = 2
)

// JWTValidator validates JWT-SVID bearer tokens using SPIRE federation bundles.
type JWTValidator interface {
	ValidateToken(ctx context.Context, token string) (spiffeID string, err error)
	Close() error
}

// WorkloadJWTValidator validates JWT-SVIDs via the SPIRE Workload API.
type WorkloadJWTValidator struct {
	source    *workloadapi.JWTSource
	audiences []string
}

// NewWorkloadJWTValidator creates a validator backed by the SPIRE Workload API.
func NewWorkloadJWTValidator(ctx context.Context, socketPath string, audiences []string) (*WorkloadJWTValidator, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return nil, fmt.Errorf("spiffeJwt.socketPath is required")
	}

	if len(audiences) == 0 {
		return nil, fmt.Errorf("spiffeJwt.audiences must contain at least one entry")
	}

	normalizedAudiences := make([]string, 0, len(audiences))
	for i, audience := range audiences {
		trimmed := strings.TrimSpace(audience)
		if trimmed == "" {
			return nil, fmt.Errorf("spiffeJwt.audiences[%d] must not be empty", i)
		}

		normalizedAudiences = append(normalizedAudiences, trimmed)
	}

	addr := socketPath
	if !strings.HasPrefix(addr, "unix:") {
		addr = "unix://" + addr
	}

	source, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(addr)))
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT source: %w", err)
	}

	return &WorkloadJWTValidator{
		source:    source,
		audiences: normalizedAudiences,
	}, nil
}

// ValidateToken parses and validates a JWT-SVID, returning the SPIFFE ID string.
func (v *WorkloadJWTValidator) ValidateToken(_ context.Context, token string) (string, error) {
	svid, err := jwtsvid.ParseAndValidate(token, v.source, v.audiences)
	if err != nil {
		return "", fmt.Errorf("validate JWT-SVID: %w", err)
	}

	return svid.ID.String(), nil
}

// Close releases the underlying Workload API client.
func (v *WorkloadJWTValidator) Close() error {
	if v.source != nil {
		if err := v.source.Close(); err != nil {
			return fmt.Errorf("close JWT workload source: %w", err)
		}
	}

	return nil
}

func extractBearerToken(headers map[string]string) string {
	auth := strings.TrimSpace(getHeader(headers, authorizationHeader))
	if auth == "" {
		return ""
	}

	parts := strings.Fields(auth)
	if len(parts) != authorizationHeaderParts {
		return ""
	}

	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return parts[1]
}

func principalFromSPIFFEID(spiffeID string) identity.Identity {
	return identity.Identity{
		AuthFamily: identity.AuthFamilySPIFFE,
		Principal:  spiffeID,
	}
}
