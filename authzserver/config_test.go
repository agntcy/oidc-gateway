// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"strings"
	"testing"
)

func validConfig() *OIDCConfig {
	return &OIDCConfig{
		Claims:      ClaimsConfig{PrincipalClaim: "sub"},
		PublicPaths: []string{"/healthz"},
		Issuers: []IssuerConfig{
			{ProviderKey: "dex", Provider: "https://dex.example.com", AuthFamily: "oidc"},
		},
		Roles: map[string]OIDCRole{
			"admin": {
				AllowedMethods: []string{"*"},
				Principals:     []string{"oidc:dex:123"},
			},
		},
	}
}

func TestOIDCConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *OIDCConfig
		expectError bool
		errorMsg    string
	}{
		{name: "valid config", config: validConfig(), expectError: false},
		{
			name: "valid custom auth principal header",
			config: func() *OIDCConfig {
				cfg := validConfig()
				cfg.Headers.AuthPrincipal = "x-custom-principal"

				return cfg
			}(),
			expectError: false,
		},
		{
			name: "invalid auth principal header with colon",
			config: func() *OIDCConfig {
				cfg := validConfig()
				cfg.Headers.AuthPrincipal = "x-custom:principal"

				return cfg
			}(),
			expectError: true,
			errorMsg:    "headers.authPrincipal",
		},
		{
			name: "invalid auth principal header with whitespace",
			config: func() *OIDCConfig {
				cfg := validConfig()
				cfg.Headers.AuthPrincipal = " x-custom-principal"

				return cfg
			}(),
			expectError: true,
			errorMsg:    "whitespace",
		},
		{
			name: "missing claims.principalClaim",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: ""},
				Roles:  map[string]OIDCRole{"admin": {AllowedMethods: []string{"*"}, Principals: []string{"oidc:dex:admin"}}},
			},
			expectError: true,
			errorMsg:    "principalClaim",
		},
		{
			name: "no roles",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles:  map[string]OIDCRole{},
			},
			expectError: true,
			errorMsg:    "at least one role",
		},
		{
			name: "issuer missing provider",
			config: &OIDCConfig{
				Claims:  ClaimsConfig{PrincipalClaim: "sub"},
				Issuers: []IssuerConfig{{ProviderKey: "dex", Provider: "", AuthFamily: "oidc"}},
				Roles:   map[string]OIDCRole{"admin": {AllowedMethods: []string{"*"}, Principals: []string{"oidc:dex:admin"}}},
			},
			expectError: true,
			errorMsg:    "provider",
		},
		{
			name: "oidc issuer missing providerKey",
			config: &OIDCConfig{
				Claims:  ClaimsConfig{PrincipalClaim: "sub"},
				Issuers: []IssuerConfig{{Provider: "https://iss", AuthFamily: "oidc"}},
				Roles:   map[string]OIDCRole{"admin": {AllowedMethods: []string{"*"}, Principals: []string{"oidc:dex:admin"}}},
			},
			expectError: true,
			errorMsg:    "providerKey",
		},
		{
			name: "invalid issuer authFamily",
			config: &OIDCConfig{
				Claims:  ClaimsConfig{PrincipalClaim: "sub"},
				Issuers: []IssuerConfig{{ProviderKey: "dex", Provider: "https://iss", AuthFamily: "jwt"}},
				Roles:   map[string]OIDCRole{"admin": {AllowedMethods: []string{"*"}, Principals: []string{"oidc:dex:admin"}}},
			},
			expectError: true,
			errorMsg:    "authFamily",
		},
		{
			name: "valid github workflow wildcard principal",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"ci": {
						AllowedMethods: []string{"*"},
						Principals: []string{
							"oidc:github:repo:agntcy/oidc-gateway:workflow:oidc-test.yml:ref:refs/heads/feat/*",
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid github wildcard multiple stars",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"ci": {
						AllowedMethods: []string{"*"},
						Principals: []string{
							"oidc:github:repo:agntcy/oidc-gateway:workflow:oidc-test.yml:ref:refs/heads/*/*",
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid github workflow wildcard",
		},
		{
			name: "invalid github wildcard not under refs heads",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"ci": {
						AllowedMethods: []string{"*"},
						Principals: []string{
							"oidc:github:repo:agntcy/oidc-gateway:workflow:oidc-test.yml:ref:refs/tags/*",
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid github workflow wildcard",
		},
		{
			name: "invalid github broad wildcard principal",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"ci": {
						AllowedMethods: []string{"*"},
						Principals:     []string{"oidc:github:*"},
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid github workflow wildcard",
		},
		{
			name: "spiffeJwt enabled without socketPath",
			config: func() *OIDCConfig {
				cfg := validConfig()
				cfg.SpiffeJWT.Enabled = true
				cfg.SpiffeJWT.Audiences = []string{"spiffe://example.org"}

				return cfg
			}(),
			expectError: true,
			errorMsg:    "socketPath",
		},
		{
			name: "spiffeJwt enabled without audiences",
			config: func() *OIDCConfig {
				cfg := validConfig()
				cfg.SpiffeJWT.Enabled = true
				cfg.SpiffeJWT.SocketPath = "/run/spire/agent-sockets/api.sock"

				return cfg
			}(),
			expectError: true,
			errorMsg:    "audiences",
		},
		{
			name: "spiffeJwt socketPath with surrounding whitespace",
			config: func() *OIDCConfig {
				cfg := validConfig()
				cfg.SpiffeJWT.Enabled = true
				cfg.SpiffeJWT.SocketPath = " /run/spire/agent-sockets/api.sock "
				cfg.SpiffeJWT.Audiences = []string{"oidc-gateway"}

				return cfg
			}(),
			expectError: true,
			errorMsg:    "socketPath",
		},
		{
			name: "spiffeJwt audience with surrounding whitespace",
			config: func() *OIDCConfig {
				cfg := validConfig()
				cfg.SpiffeJWT.Enabled = true
				cfg.SpiffeJWT.SocketPath = "/run/spire/agent-sockets/api.sock"
				cfg.SpiffeJWT.Audiences = []string{" oidc-gateway "}

				return cfg
			}(),
			expectError: true,
			errorMsg:    "audiences",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got nil")
				}

				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Fatalf("expected error containing %q, got %v", tt.errorMsg, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if tt.config.Headers.AuthPrincipal == "" {
				t.Fatal("expected auth principal header to be defaulted")
			}
		})
	}
}

func TestOIDCConfig_GetIssuerConfig(t *testing.T) {
	config := &OIDCConfig{
		Issuers: []IssuerConfig{
			{ProviderKey: "dex", Provider: "https://iss-a.example.com", AuthFamily: "oidc"},
			{ProviderKey: "github", Provider: GitHubIssuer, AuthFamily: "oidc"},
		},
	}

	ic := config.GetIssuerConfig("https://iss-a.example.com")
	if ic == nil || ic.ProviderKey != "dex" {
		t.Fatalf("expected dex issuer config, got %+v", ic)
	}

	if config.GetIssuerConfig("https://unknown.example.com") != nil {
		t.Fatal("expected nil for unknown issuer")
	}
}

func TestOIDCConfig_IsPublicPath(t *testing.T) {
	config := &OIDCConfig{PublicPaths: []string{"/healthz", "/grpc.reflection"}}

	tests := []struct {
		path string
		want bool
	}{
		{"/healthz", true},
		{"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", true},
		{"/agntcy.oidc-gateway.store.v1.StoreService/Push", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := config.IsPublicPath(tt.path); got != tt.want {
				t.Fatalf("IsPublicPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
