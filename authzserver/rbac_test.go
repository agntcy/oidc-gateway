// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"log/slog"
	"strings"
	"testing"
)

func TestNewOIDCRoleResolver(t *testing.T) {
	t.Run("nil config returns error", func(t *testing.T) {
		_, err := NewOIDCRoleResolver(nil, slog.Default())
		if err == nil {
			t.Fatal("expected error for nil config")
		}
	})

	t.Run("nil logger uses default", func(t *testing.T) {
		cfg := &OIDCConfig{
			Claims: ClaimsConfig{PrincipalClaim: "sub"},
			Roles: map[string]OIDCRole{
				"admin": {
					AllowedMethods: []string{"*"},
					Principals:     []string{"oidc:dex:admin"},
				},
			},
		}

		resolver, err := NewOIDCRoleResolver(cfg, nil)
		if err != nil {
			t.Fatalf("NewOIDCRoleResolver: %v", err)
		}

		if resolver == nil {
			t.Fatal("expected resolver, got nil")
		}
	})
}

func TestOIDCRoleResolver_LoadPolicies_EmptyMappings(t *testing.T) {
	// Intentionally bypass config.Validate() here to exercise loadPolicies branches
	// where both policies and groupings are empty.
	cfg := &OIDCConfig{
		Claims: ClaimsConfig{PrincipalClaim: "sub"},
		Roles: map[string]OIDCRole{
			"empty": {
				AllowedMethods: []string{},
				Principals:     []string{},
			},
		},
	}

	resolver, err := NewOIDCRoleResolver(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewOIDCRoleResolver: %v", err)
	}

	err = resolver.Authorize("oidc:dex:any", "/any/path")
	if err == nil {
		t.Fatal("expected authorization denial when no policies are loaded")
	}
}

//nolint:gocognit // test table with multiple branches; complexity acceptable for tests
func TestOIDCRoleResolver_Authorize(t *testing.T) {
	tests := []struct {
		name        string
		config      *OIDCConfig
		principal   string
		path        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "user with admin role allows all methods",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"admin": {
						AllowedMethods: []string{"*"},
						Principals:     []string{"oidc:dex:77776025198584418"},
					},
				},
			},
			principal:   "oidc:dex:77776025198584418",
			path:        "/agntcy.dir.store.v1.StoreService/Push",
			expectError: false,
		},
		{
			name: "viewer allows Pull and Lookup only",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"viewer": {
						AllowedMethods: []string{
							"/agntcy.dir.store.v1.StoreService/Pull",
							"/agntcy.dir.store.v1.StoreService/Lookup",
						},
						Principals: []string{"oidc:dex:111"},
					},
				},
			},
			principal:   "oidc:dex:111",
			path:        "/agntcy.dir.store.v1.StoreService/Pull",
			expectError: false,
		},
		{
			name: "viewer denied for Push",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"viewer": {
						AllowedMethods: []string{"/agntcy.dir.store.v1.StoreService/Pull"},
						Principals:     []string{"oidc:dex:111"},
					},
				},
			},
			principal:   "oidc:dex:111",
			path:        "/agntcy.dir.store.v1.StoreService/Push",
			expectError: true,
		},
		{
			name: "client principal with ci-writer role",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"ci-writer": {
						AllowedMethods: []string{
							"/agntcy.dir.store.v1.StoreService/Push",
							"/agntcy.dir.store.v1.StoreService/Pull",
						},
						Principals: []string{"oidc:dex:69234237810729234"},
					},
				},
			},
			principal:   "oidc:dex:69234237810729234",
			path:        "/agntcy.dir.store.v1.StoreService/Push",
			expectError: false,
		},
		{
			name: "GitHub workflow principal with prod-deployer role",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"prod-deployer": {
						AllowedMethods: []string{"*"},
						Principals:     []string{"oidc:github:repo:agntcy/oidc-gateway:workflow:deploy.yml:ref:refs/heads/main:env:prod"},
					},
				},
			},
			principal:   "oidc:github:repo:agntcy/oidc-gateway:workflow:deploy.yml:ref:refs/heads/main:env:prod",
			path:        "/agntcy.dir.store.v1.StoreService/Push",
			expectError: false,
		},
		{
			name: "GitHub workflow wildcard principal matches any branch",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"ci-oidc-test": {
						AllowedMethods: []string{
							"/agntcy.dir.search.v1.SearchService/SearchCIDs",
						},
						Principals: []string{
							"oidc:github:repo:agntcy/oidc-gateway:workflow:oidc-test.yml:ref:refs/heads/*",
						},
					},
				},
			},
			principal:   "oidc:github:repo:agntcy/oidc-gateway:workflow:oidc-test.yml:ref:refs/heads/feat/oidc-auth",
			path:        "/agntcy.dir.search.v1.SearchService/SearchCIDs",
			expectError: false,
		},
		{
			name: "GitHub workflow wildcard does not match other workflow file",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"ci-oidc-test": {
						AllowedMethods: []string{
							"/agntcy.dir.search.v1.SearchService/SearchCIDs",
						},
						Principals: []string{
							"oidc:github:repo:agntcy/oidc-gateway:workflow:oidc-test.yml:ref:refs/heads/*",
						},
					},
				},
			},
			principal:   "oidc:github:repo:agntcy/oidc-gateway:workflow:another.yml:ref:refs/heads/feat/oidc-auth",
			path:        "/agntcy.dir.search.v1.SearchService/SearchCIDs",
			expectError: true,
		},
		{
			name: "principal in deny list is blocked",
			config: &OIDCConfig{
				Claims:   ClaimsConfig{PrincipalClaim: "sub"},
				DenyList: []string{"oidc:dex:77776025198584418"},
				Roles: map[string]OIDCRole{
					"admin": {
						AllowedMethods: []string{"*"},
						Principals:     []string{"oidc:dex:77776025198584418"},
					},
				},
			},
			principal:   "oidc:dex:77776025198584418",
			path:        "/agntcy.dir.store.v1.StoreService/Push",
			expectError: true,
			errorMsg:    "deny list",
		},
		{
			name: "no role assignment - deny",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"admin": {
						AllowedMethods: []string{"*"},
						Principals:     []string{"oidc:dex:other"},
					},
				},
			},
			principal:   "oidc:dex:unknown",
			path:        "/agntcy.dir.store.v1.StoreService/Push",
			expectError: true,
		},
		{
			name: "wildcard method matching",
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: "sub"},
				Roles: map[string]OIDCRole{
					"store-admin": {
						AllowedMethods: []string{"/agntcy.dir.store.v1.StoreService/*"},
						Principals:     []string{"oidc:dex:admin"},
					},
				},
			},
			principal:   "oidc:dex:admin",
			path:        "/agntcy.dir.store.v1.StoreService/AnyMethod",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.PublicPaths = []string{"/healthz"}
			if err := tt.config.Validate(); err != nil {
				t.Fatalf("invalid config: %v", err)
			}

			resolver, err := NewOIDCRoleResolver(tt.config, slog.Default())
			if err != nil {
				t.Fatalf("failed to create resolver: %v", err)
			}

			// Deny list is checked before Authorize
			if resolver.IsDenied(tt.principal, "") {
				if !tt.expectError {
					t.Errorf("principal was denied but expected allow")
				}

				return
			}

			err = resolver.Authorize(tt.principal, tt.path)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got nil")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestOIDCRoleResolver_IsDenied(t *testing.T) {
	config := &OIDCConfig{
		Claims:   ClaimsConfig{PrincipalClaim: "sub"},
		DenyList: []string{"oidc:dex:bad", "oidc:blocked@example.com"},
		Roles: map[string]OIDCRole{
			"admin": {
				AllowedMethods: []string{"*"},
				Principals:     []string{"oidc:dex:good"},
			},
		},
		PublicPaths: []string{},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("invalid config: %v", err)
	}

	resolver, err := NewOIDCRoleResolver(config, slog.Default())
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	if !resolver.IsDenied("oidc:dex:bad", "") {
		t.Error("oidc:dex:bad should be denied")
	}

	if !resolver.IsDenied("other", "blocked@example.com") {
		t.Error("oidc:blocked@example.com should be denied via email")
	}

	if resolver.IsDenied("oidc:dex:good", "") {
		t.Error("oidc:dex:good should not be denied")
	}
}
