// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"context"
	"fmt"
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
