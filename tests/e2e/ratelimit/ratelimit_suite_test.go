// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"testing"

	"github.com/agntcy/oidc-gateway/tests/e2e/shared"
	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var testConfig *shared.TestConfig

func TestRateLimitE2E(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)

	testConfig = shared.NewTestConfig()

	ginkgo.RunSpecs(t, "Rate Limit E2E Suite")
}

var _ = ginkgo.BeforeSuite(func(ctx context.Context) {
	shared.WaitForGateway(ctx, testConfig.EnvoyBaseURL)
})
