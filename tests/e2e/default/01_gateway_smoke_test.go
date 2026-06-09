// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package _default

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/agntcy/oidc-gateway/tests/e2e/shared"
	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
)

var _ = ginkgo.Describe("smoke tests", ginkgo.Ordered, func() {
	var (
		dexClient  *shared.DexClient
		grpcClient *shared.GrpcClient
	)

	ginkgo.BeforeAll(func(ctx context.Context) {
		dexClient = &shared.DexClient{BaseURL: testConfig.DexURL}
		grpcClient = &shared.GrpcClient{BaseURL: testConfig.GetEnvoyHost(), BearerToken: ""}
	})

	ginkgo.It("/healthz is healthy", func(ctx context.Context) {
		resp, err := shared.DoGET(ctx, testConfig.EnvoyBaseURL+shared.HealthzRoute)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		defer shared.DiscardResponse(resp)

		gomega.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))

		body, err := io.ReadAll(resp.Body)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		var payload struct {
			Status string `json:"status"`
		}

		gomega.Expect(json.Unmarshal(body, &payload)).To(gomega.Succeed())
		gomega.Expect(payload.Status).To(gomega.Equal("healthy"))
	})

	ginkgo.It("/ready is LIVE", func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		resp, err := shared.DoGET(ctx, testConfig.EnvoyAdminURL+shared.ReadyRoute)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		defer shared.DiscardResponse(resp)

		gomega.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))

		body, err := io.ReadAll(resp.Body)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(strings.TrimSpace(string(body))).To(gomega.Equal("LIVE"))
	})

	ginkgo.It("/SearchCIDs unauthenticated", func(ctx context.Context) {
		_, err := grpcClient.SearchCIDs(ctx)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(shared.GRPCStatusCode(err)).To(gomega.Equal(codes.Unauthenticated))
	})

	ginkgo.It("/SearchCIDs authenticated", func(ctx context.Context) {
		token, err := dexClient.FetchToken(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		grpcClient := &shared.GrpcClient{
			BaseURL:     testConfig.GetEnvoyHost(),
			BearerToken: token.IDToken,
		}

		responses, err := grpcClient.SearchCIDs(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(responses).To(gomega.BeEmpty())
	})
})
