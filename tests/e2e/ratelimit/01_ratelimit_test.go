// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"time"

	"github.com/agntcy/oidc-gateway/tests/e2e/shared"
	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
)

var _ = ginkgo.Describe("rate limit tests", ginkgo.Ordered, func() {
	var (
		dexClient  *shared.DexClient
		grpcClient *shared.GrpcClient
	)

	ginkgo.BeforeAll(func(ctx context.Context) {
		dexClient = &shared.DexClient{BaseURL: testConfig.DexURL}
		token, err := dexClient.FetchToken(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		grpcClient = &shared.GrpcClient{
			BaseURL:     testConfig.GetEnvoyHost(),
			BearerToken: token.IDToken,
		}
	})

	ginkgo.It("rate limit is enforced", func(ctx context.Context) {
		_, err := grpcClient.SearchCIDs(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "1st request should pass")

		_, err = grpcClient.SearchCIDs(ctx)
		gomega.Expect(err).To(gomega.HaveOccurred(), "2nd request should fail")
		gomega.Expect(shared.GRPCStatusCode(err)).To(
			gomega.BeElementOf(codes.ResourceExhausted, codes.Unavailable),
			"2nd request should fail (err: %v)",
			err,
		)

		time.Sleep(1100 * time.Millisecond)

		_, err = grpcClient.SearchCIDs(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "3rd request should pass")
	})
})
