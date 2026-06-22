// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

const (
	gatewayReadyTimeout  = 2 * time.Minute
	gatewayReadyInterval = 2 * time.Second
	httpCheckTimeout     = 5 * time.Second
)

func WaitForGateway(ctx context.Context, baseURL string) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+HealthzRoute, nil)
	if err != nil {
		return fmt.Errorf("failed to create healthz request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		DiscardResponse(resp)

		return fmt.Errorf("GET /healthz: %w", err)
	}

	defer DiscardResponse(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /healthz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	return nil
}
