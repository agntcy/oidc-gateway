// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"encoding/base64"
	"testing"
)

func TestExtractPrincipalCanonicalOIDC(t *testing.T) {
	config := &OIDCConfig{
		Claims: ClaimsConfig{PrincipalClaim: "email"},
		Issuers: []IssuerConfig{
			{
				ProviderKey: "dex",
				Provider:    "https://dex.example.com",
				AuthFamily:  "oidc",
			},
		},
	}

	principal, err := ExtractPrincipal(`{"iss":"https://dex.example.com","email":"admin@example.com"}`, config)
	if err != nil {
		t.Fatalf("ExtractPrincipal: %v", err)
	}

	if principal != "oidc:dex:admin@example.com" {
		t.Fatalf("principal = %q", principal)
	}
}

func TestExtractPrincipalCanonicalSPIFFEJWT(t *testing.T) {
	config := &OIDCConfig{
		Claims: ClaimsConfig{PrincipalClaim: "sub"},
		Issuers: []IssuerConfig{
			{
				Provider:   "https://spire-oidc.example.org",
				AuthFamily: "spiffe",
			},
		},
	}

	principal, err := ExtractPrincipal(`{"iss":"https://spire-oidc.example.org","sub":"spiffe://example.org/ns/default/sa/backend"}`, config)
	if err != nil {
		t.Fatalf("ExtractPrincipal: %v", err)
	}

	if principal != "spiffe:spiffe://example.org/ns/default/sa/backend" {
		t.Fatalf("principal = %q", principal)
	}
}

func TestExtractPrincipalAcceptsEnvoyForwardedPayload(t *testing.T) {
	config := &OIDCConfig{
		Claims: ClaimsConfig{PrincipalClaim: "sub"},
		Issuers: []IssuerConfig{
			{
				ProviderKey: "dex",
				Provider:    "https://dex.example.com",
				AuthFamily:  "oidc",
			},
		},
	}

	payload := `{"iss":"https://dex.example.com","sub":"user-123"}`
	header := base64.RawURLEncoding.EncodeToString([]byte(payload))

	principal, err := ExtractPrincipal(header, config)
	if err != nil {
		t.Fatalf("ExtractPrincipal: %v", err)
	}

	if principal != "oidc:dex:user-123" {
		t.Fatalf("principal = %q", principal)
	}
}
