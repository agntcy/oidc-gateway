// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParsePayloadJSON(t *testing.T) {
	t.Run("raw json payload", func(t *testing.T) {
		raw, err := parsePayloadJSON(`{"iss":"https://dex.example.com","sub":"abc"}`)
		if err != nil {
			t.Fatalf("parsePayloadJSON: %v", err)
		}

		if string(raw) != `{"iss":"https://dex.example.com","sub":"abc"}` {
			t.Fatalf("unexpected payload: %s", string(raw))
		}
	})

	t.Run("jwt compact form", func(t *testing.T) {
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://dex.example.com","sub":"abc"}`))

		raw, err := parsePayloadJSON("header." + payload + ".sig")
		if err != nil {
			t.Fatalf("parsePayloadJSON: %v", err)
		}

		if !strings.Contains(string(raw), `"sub":"abc"`) {
			t.Fatalf("decoded payload missing claim: %s", string(raw))
		}
	})

	t.Run("empty payload returns error", func(t *testing.T) {
		_, err := parsePayloadJSON("   ")
		if err == nil {
			t.Fatal("expected error for empty payload")
		}
	})
}

func TestDecodeJWTBase64URLSegment(t *testing.T) {
	t.Run("empty segment", func(t *testing.T) {
		_, err := decodeJWTBase64URLSegment("")
		if err == nil {
			t.Fatal("expected error for empty JWT segment")
		}
	})

	t.Run("raw url encoding", func(t *testing.T) {
		in := base64.RawURLEncoding.EncodeToString([]byte(`{"a":"b"}`))

		out, err := decodeJWTBase64URLSegment(in)
		if err != nil {
			t.Fatalf("decodeJWTBase64URLSegment: %v", err)
		}

		if string(out) != `{"a":"b"}` {
			t.Fatalf("unexpected output: %s", string(out))
		}
	})

	t.Run("padded url encoding", func(t *testing.T) {
		in := base64.URLEncoding.EncodeToString([]byte(`{"a":"b"}`))

		out, err := decodeJWTBase64URLSegment(in)
		if err != nil {
			t.Fatalf("decodeJWTBase64URLSegment: %v", err)
		}

		if string(out) != `{"a":"b"}` {
			t.Fatalf("unexpected output: %s", string(out))
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := decodeJWTBase64URLSegment("$$$")
		if err == nil {
			t.Fatal("expected invalid base64 error")
		}
	})
}

func TestExtractPrincipal_Errors(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		config  *OIDCConfig
	}{
		{
			name:    "nil config",
			payload: `{}`,
			config:  nil,
		},
		{
			name:    "invalid json",
			payload: `{`,
			config:  &OIDCConfig{},
		},
		{
			name:    "missing iss",
			payload: `{"sub":"abc"}`,
			config: &OIDCConfig{
				Claims: ClaimsConfig{PrincipalClaim: DefaultPrincipalClaim},
			},
		},
		{
			name:    "unknown issuer",
			payload: `{"iss":"https://unknown.example.com","sub":"abc"}`,
			config: &OIDCConfig{
				Claims:  ClaimsConfig{PrincipalClaim: DefaultPrincipalClaim},
				Issuers: []IssuerConfig{{ProviderKey: testProviderKeyDex, Provider: testDexIssuerURL, AuthFamily: testAuthFamilyOIDC}},
			},
		},
		{
			name:    "spiffe auth family invalid principal",
			payload: `{"iss":"https://spire.example.com","sub":""}`,
			config: &OIDCConfig{
				Claims:  ClaimsConfig{PrincipalClaim: DefaultPrincipalClaim},
				Issuers: []IssuerConfig{{Provider: "https://spire.example.com", AuthFamily: testAuthFamilySPIFFE}},
			},
		},
		{
			name:    "oidc missing providerKey",
			payload: `{"iss":"https://dex.example.com","sub":"abc"}`,
			config: &OIDCConfig{
				Claims:  ClaimsConfig{PrincipalClaim: DefaultPrincipalClaim},
				Issuers: []IssuerConfig{{Provider: testDexIssuerURL, AuthFamily: testAuthFamilyOIDC}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractPrincipal(tt.payload, tt.config)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestExtractPrincipal_GitHubBranches(t *testing.T) {
	config := &OIDCConfig{
		Claims: ClaimsConfig{PrincipalClaim: DefaultPrincipalClaim},
		Issuers: []IssuerConfig{
			{
				ProviderKey: ProviderKeyGitHub,
				Provider:    GitHubIssuer,
				AuthFamily:  testAuthFamilyOIDC,
			},
		},
	}

	t.Run("workflow_ref + env", func(t *testing.T) {
		payload := `{
			"iss":"https://token.actions.githubusercontent.com",
			"repository":"agntcy/oidc-gateway",
			"ref":"refs/heads/main",
			"environment":"prod",
			"workflow_ref":"agntcy/oidc-gateway/.github/workflows/deploy.yml@refs/heads/main"
		}`

		principal, err := ExtractPrincipal(payload, config)
		if err != nil {
			t.Fatalf("ExtractPrincipal: %v", err)
		}

		if string(principal) != testPrincipalGitHubWorkflowProd {
			t.Fatalf("principal = %q, want %q", principal, testPrincipalGitHubWorkflowProd)
		}
	})

	t.Run("job_workflow_ref fallback and default ref", func(t *testing.T) {
		payload := `{
			"iss":"https://token.actions.githubusercontent.com",
			"repository":"agntcy/oidc-gateway",
			"job_workflow_ref":"agntcy/oidc-gateway/.github/workflows/build.yml@refs/heads/main"
		}`

		principal, err := ExtractPrincipal(payload, config)
		if err != nil {
			t.Fatalf("ExtractPrincipal: %v", err)
		}

		want := "oidc:github:repo:agntcy/oidc-gateway:workflow:build.yml:ref:refs/heads/main"
		if string(principal) != want {
			t.Fatalf("principal = %q, want %q", principal, want)
		}
	})

	t.Run("missing repository", func(t *testing.T) {
		payload := `{
			"iss":"https://token.actions.githubusercontent.com",
			"workflow_ref":"agntcy/oidc-gateway/.github/workflows/deploy.yml@refs/heads/main"
		}`

		_, err := ExtractPrincipal(payload, config)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("missing workflow refs", func(t *testing.T) {
		payload := `{
			"iss":"https://token.actions.githubusercontent.com",
			"repository":"agntcy/oidc-gateway"
		}`

		_, err := ExtractPrincipal(payload, config)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestExtractOIDCPrincipalFallbacks(t *testing.T) {
	t.Run("default principal claim uses sub", func(t *testing.T) {
		out, err := extractOIDCPrincipal(map[string]any{DefaultPrincipalClaim: "user-sub"}, "")
		if err != nil {
			t.Fatalf("extractOIDCPrincipal: %v", err)
		}

		if out != "user-sub" {
			t.Fatalf("principal = %q", out)
		}
	})

	t.Run("fallback to client_id", func(t *testing.T) {
		out, err := extractOIDCPrincipal(map[string]any{"client_id": "svc-1"}, "email")
		if err != nil {
			t.Fatalf("extractOIDCPrincipal: %v", err)
		}

		if out != "svc-1" {
			t.Fatalf("principal = %q", out)
		}
	})

	t.Run("fallback to azp", func(t *testing.T) {
		out, err := extractOIDCPrincipal(map[string]any{"azp": "svc-2"}, "email")
		if err != nil {
			t.Fatalf("extractOIDCPrincipal: %v", err)
		}

		if out != "svc-2" {
			t.Fatalf("principal = %q", out)
		}
	})

	t.Run("missing claim and machine identity", func(t *testing.T) {
		_, err := extractOIDCPrincipal(map[string]any{}, "email")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestGetEmailBranches(t *testing.T) {
	if got := GetEmail("", "email"); got != "" {
		t.Fatalf("expected empty for empty payload, got %q", got)
	}

	if got := GetEmail(`{`, "email"); got != "" {
		t.Fatalf("expected empty for invalid json, got %q", got)
	}

	if got := GetEmail(`{"email":"a@b.c"}`, ""); got != "" {
		t.Fatalf("expected empty for empty path, got %q", got)
	}

	if got := GetEmail(`{"claims":{"email":"a@b.c"}}`, "claims.email"); got != "a@b.c" {
		t.Fatalf("unexpected nested email: %q", got)
	}

	if got := GetEmail(`{"claims":{"email":123}}`, "claims.email"); got != "" {
		t.Fatalf("expected empty for non-string email claim, got %q", got)
	}

	if got := GetEmail(`{"claims":"not-an-object"}`, "claims.email"); got != "" {
		t.Fatalf("expected empty for invalid nested object type, got %q", got)
	}
}

func TestGetStringBranches(t *testing.T) {
	m := map[string]any{
		"nilValue":    nil,
		"intValue":    42,
		"stringValue": "ok",
	}

	if got := getString(m, "missing"); got != "" {
		t.Fatalf("expected empty for missing key, got %q", got)
	}

	if got := getString(m, "nilValue"); got != "" {
		t.Fatalf("expected empty for nil value, got %q", got)
	}

	if got := getString(m, "intValue"); got != "" {
		t.Fatalf("expected empty for non-string value, got %q", got)
	}

	if got := getString(m, "stringValue"); got != "ok" {
		t.Fatalf("expected string value, got %q", got)
	}
}

func TestGetNestedValueBranches(t *testing.T) {
	payload := map[string]any{
		"a": map[string]any{
			"b": "value",
		},
		"leaf": "x",
	}

	if got := getNestedValue(payload, []string{}); got != nil {
		t.Fatalf("expected nil for empty path, got %#v", got)
	}

	if got := getNestedValue(payload, []string{"missing"}); got != nil {
		t.Fatalf("expected nil for missing key, got %#v", got)
	}

	if got := getNestedValue(payload, []string{"leaf", "next"}); got != nil {
		t.Fatalf("expected nil when intermediate is not object, got %#v", got)
	}

	if got := getNestedValue(payload, []string{"a", "b"}); got != "value" {
		t.Fatalf("expected nested value, got %#v", got)
	}
}
