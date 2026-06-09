// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	dexClientID          = "oidc-gateway-test"
	dexClientSecret      = "test-secret"
	dexTestUser          = "admin@example.com"
	dexTestPassword      = "password"
	dexFetchTokenTimeout = 15 * time.Second
)

type DexClient struct {
	BaseURL string
}

type DexToken struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
}

func (c *DexClient) FetchToken(ctx context.Context) (*DexToken, error) {
	ctx, cancel := context.WithTimeout(ctx, dexFetchTokenTimeout)
	defer cancel()

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", dexClientID)
	form.Set("client_secret", dexClientSecret)
	form.Set("username", dexTestUser)
	form.Set("password", dexTestPassword)
	form.Set("scope", "openid email profile")

	tokenURL := c.BaseURL + DexTokenRoute

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create dex token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	//nolint:gosec // G704: e2e tests call a fixed localhost Dex URL or env override.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		DiscardResponse(resp)

		return nil, fmt.Errorf("POST %s: %w", tokenURL, err)
	}

	defer DiscardResponse(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read dex token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dex token endpoint status = %d, want %d (body: %s)",
			resp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var token DexToken
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed to decode Dex token: %w", err)
	}

	return &token, nil
}
