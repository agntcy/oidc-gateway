// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"strings"
	"testing"
)

func TestParsePrincipal(t *testing.T) {
	tests := []struct {
		name      string
		principal IdentityPrincipal
		wantErr   bool
	}{
		{name: "oidc principal", principal: "oidc:dex:alice"},
		{name: "spiffe principal", principal: "spiffe:spiffe://example.org/ns/default/sa/app"},
		{name: "invalid format no separator", principal: "oidc", wantErr: true},
		{name: "missing family separator", principal: "spiffe://example.org", wantErr: true},
		{name: "empty value", principal: "", wantErr: true},
		{name: "invalid family", principal: "jwt:alice", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePrincipal(tt.principal)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParsePrincipal_InvalidFormatErrorMessage(t *testing.T) {
	_, err := ParsePrincipal("oidc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "must be <auth-family>:<principal>") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIdentityValidate_EmptyPrincipalErrors(t *testing.T) {
	tests := []struct {
		name string
		in   Identity
		want string
	}{
		{
			name: "oidc empty principal",
			in:   Identity{AuthFamily: AuthFamilyOIDC, Principal: ""},
			want: "oidc principal is empty",
		},
		{
			name: "spiffe empty principal",
			in:   Identity{AuthFamily: AuthFamilySPIFFE, Principal: ""},
			want: "spiffe principal is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestIdentityValidate_OIDCPrincipalMissingProviderKeySeparator(t *testing.T) {
	in := Identity{
		AuthFamily: AuthFamilyOIDC,
		Principal:  "alice",
	}

	err := in.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "must contain provider key and principal value") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrincipalStringRoundTrip(t *testing.T) {
	parsed, err := ParsePrincipal("oidc:github:repo:agntcy/oidc-gateway")
	if err != nil {
		t.Fatalf("ParsePrincipal: %v", err)
	}

	got := parsed.PrincipalString()
	if got != "oidc:github:repo:agntcy/oidc-gateway" {
		t.Fatalf("PrincipalString = %q", got)
	}
}
