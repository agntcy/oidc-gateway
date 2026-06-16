// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package jwtsvid

import (
	"context"
	"testing"
	"time"

	"github.com/agntcy/oidc-gateway/tests/e2e/shared"
	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
)

const (
	workloadReadyWait         = 3 * time.Minute
	invalidJWTSVIDBearerToken = "invalid.jwt.token" //nolint:gosec // G101: deliberate invalid token for negative e2e test
)

var (
	testConfig   *shared.TestConfig
	spiffeClient *shared.SpiffeClient
)

func TestJWTSVIDE2E(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)

	testConfig = shared.NewTestConfig()
	spiffeClient = shared.NewSpiffeClient()

	ginkgo.RunSpecs(t, "JWT-SVID E2E Suite")
}

var _ = ginkgo.BeforeSuite(func(ctx context.Context) {
	shared.WaitForGateway(ctx, testConfig.EnvoyBaseURL)
})

var _ = ginkgo.Describe("JWT-SVID validation", ginkgo.Ordered, func() {
	var grpcClient *shared.GrpcClient

	ginkgo.BeforeAll(func() {
		grpcClient = &shared.GrpcClient{
			BaseURL: testConfig.GetEnvoyHost(),
		}
	})

	ginkgo.It("rejects unauthenticated SearchCIDs", func(ctx context.Context) {
		_, err := grpcClient.SearchCIDs(ctx)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(shared.GRPCStatusCode(err)).To(gomega.Equal(codes.Unauthenticated))
	})

	ginkgo.It("rejects invalid JWT-SVID bearer tokens", func(ctx context.Context) {
		client := &shared.GrpcClient{
			BaseURL:     testConfig.GetEnvoyHost(),
			BearerToken: invalidJWTSVIDBearerToken,
		}

		_, err := client.SearchCIDs(ctx)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(shared.GRPCStatusCode(err)).To(gomega.Equal(codes.Unauthenticated))
	})

	ginkgo.It("authorizes SearchCIDs with a valid JWT-SVID", func(ctx context.Context) {
		token := shared.WaitForJWTSVID(ctx, spiffeClient, workloadReadyWait)

		client := &shared.GrpcClient{
			BaseURL:     testConfig.GetEnvoyHost(),
			BearerToken: token,
		}

		responses, err := client.SearchCIDs(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(responses).To(gomega.BeEmpty())
	})
})
