// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import "testing"

const testGroupEditorsPrincipal = "oidc:dex:group:editors"

//nolint:gocognit,cyclop // table-style subtests
func TestExtractGroupPrincipals(t *testing.T) {
	baseConfig := func() *OIDCConfig {
		return &OIDCConfig{
			Claims: ClaimsConfig{
				PrincipalClaim:  "email",
				GroupsClaimPath: "groups",
			},
			Issuers: []IssuerConfig{
				{ProviderKey: "dex", Provider: "https://dex.example.com", AuthFamily: "oidc"},
			},
		}
	}

	t.Run("disabled when groupsClaimPath empty", func(t *testing.T) {
		cfg := baseConfig()
		cfg.Claims.GroupsClaimPath = ""

		got, err := ExtractGroupPrincipals(`{"iss":"https://dex.example.com","groups":["editors"]}`, cfg, nil)
		if err != nil {
			t.Fatalf("ExtractGroupPrincipals: %v", err)
		}

		if len(got) != 0 {
			t.Fatalf("expected no groups, got %v", got)
		}
	})

	t.Run("array of groups", func(t *testing.T) {
		got, err := ExtractGroupPrincipals(
			`{"iss":"https://dex.example.com","groups":["editors","admins","editors"]}`,
			baseConfig(),
			nil,
		)
		if err != nil {
			t.Fatalf("ExtractGroupPrincipals: %v", err)
		}

		if len(got) != 2 {
			t.Fatalf("expected 2 unique groups, got %v", got)
		}

		want := map[string]bool{testGroupEditorsPrincipal: true, "oidc:dex:group:admins": true}
		for _, p := range got {
			if !want[string(p)] {
				t.Fatalf("unexpected group principal %q", p)
			}
		}
	})

	t.Run("single string group", func(t *testing.T) {
		got, err := ExtractGroupPrincipals(
			`{"iss":"https://dex.example.com","groups":"editors"}`,
			baseConfig(),
			nil,
		)
		if err != nil {
			t.Fatalf("ExtractGroupPrincipals: %v", err)
		}

		if len(got) != 1 || got[0] != testGroupEditorsPrincipal {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("missing groups claim", func(t *testing.T) {
		got, err := ExtractGroupPrincipals(`{"iss":"https://dex.example.com","email":"a@b.c"}`, baseConfig(), nil)
		if err != nil {
			t.Fatalf("ExtractGroupPrincipals: %v", err)
		}

		if len(got) != 0 {
			t.Fatalf("expected nil groups, got %v", got)
		}
	})

	t.Run("invalid groups type is ignored", func(t *testing.T) {
		got, err := ExtractGroupPrincipals(`{"iss":"https://dex.example.com","groups":123}`, baseConfig(), nil)
		if err != nil {
			t.Fatalf("ExtractGroupPrincipals: %v", err)
		}

		if len(got) != 0 {
			t.Fatalf("expected no groups, got %v", got)
		}
	})

	t.Run("array skips non-string elements", func(t *testing.T) {
		got, err := ExtractGroupPrincipals(
			`{"iss":"https://dex.example.com","groups":["editors",123,null]}`,
			baseConfig(),
			nil,
		)
		if err != nil {
			t.Fatalf("ExtractGroupPrincipals: %v", err)
		}

		if len(got) != 1 || got[0] != testGroupEditorsPrincipal {
			t.Fatalf("got %v", got)
		}
	})
}
