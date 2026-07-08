// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"context"
	"fmt"
	"testing"
)

type mockJWTValidator struct {
	spiffeID string
	err      error
}

func (m *mockJWTValidator) ValidateToken(_ context.Context, token string) (string, error) {
	if m.err != nil {
		return "", m.err
	}

	if token == "" {
		return "", fmt.Errorf("empty token")
	}

	return m.spiffeID, nil
}

func (m *mockJWTValidator) Close() error {
	return nil
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name: "exact Bearer scheme",
			headers: map[string]string{
				"authorization": "Bearer token-123",
			},
			want: "token-123",
		},
		{
			name: "lowercase bearer scheme",
			headers: map[string]string{
				"authorization": "bearer token-123",
			},
			want: "token-123",
		},
		{
			name: "mixed-case bearer scheme and extra spaces",
			headers: map[string]string{
				"authorization": "  BeArEr   token-123  ",
			},
			want: "token-123",
		},
		{
			name: "missing token",
			headers: map[string]string{
				"authorization": "Bearer",
			},
			want: "",
		},
		{
			name: "unsupported scheme",
			headers: map[string]string{
				"authorization": "Basic Zm9vOmJhcg==",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBearerToken(tt.headers)
			if got != tt.want {
				t.Fatalf("extractBearerToken() = %q, want %q", got, tt.want)
			}
		})
	}
}
