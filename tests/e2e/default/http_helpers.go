// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package _default

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

const (
	defaultEnvoyURL      = "http://127.0.0.1:18080"
	defaultEnvoyAdminURL = "http://127.0.0.1:19901"
	gatewayReadyTimeout  = 2 * time.Minute
	gatewayReadyInterval = 2 * time.Second
	httpCheckTimeout     = 5 * time.Second
)

func envoyBaseURL() string {
	if url := os.Getenv("E2E_ENVOY_URL"); url != "" {
		return url
	}

	return defaultEnvoyURL
}

func envoyAdminURL() string {
	if url := os.Getenv("E2E_ENVOY_ADMIN_URL"); url != "" {
		return url
	}

	return defaultEnvoyAdminURL
}

func discardResponseBody(body io.ReadCloser) {
	if body == nil {
		return
	}

	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}

func waitForGateway(ctx context.Context, baseURL string) {
	ginkgo.GinkgoWriter.Printf("Waiting for gateway at %s...\n", baseURL)

	gomega.Eventually(gatewayHealthCheck).
		WithArguments(baseURL).
		WithPolling(gatewayReadyInterval).
		WithTimeout(gatewayReadyTimeout).
		WithContext(ctx).
		Should(gomega.Succeed())

	ginkgo.GinkgoWriter.Printf("Gateway at %s is ready\n", baseURL)
}

func gatewayHealthCheck(baseURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), httpCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/healthz", nil)
	if err != nil {
		return fmt.Errorf("create healthz request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}

		return fmt.Errorf("GET /healthz: %w", err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /healthz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	return nil
}

func doGET(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	//nolint:gosec // G704: e2e tests call fixed localhost URLs or env overrides.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}

		return nil, fmt.Errorf("GET %s: %w", url, err)
	}

	return resp, nil
}
