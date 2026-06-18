// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package _default

import (
	"context"
	"testing"

	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var testEnv *env

type env struct {
	EnvoyBaseURL  string
	EnvoyAdminURL string
}

func TestDefaultE2E(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)

	testEnv = &env{
		EnvoyBaseURL:  envoyBaseURL(),
		EnvoyAdminURL: envoyAdminURL(),
	}

	ginkgo.RunSpecs(t, "OIDC Gateway E2E Suite")
}

var _ = ginkgo.BeforeSuite(func(ctx context.Context) {
	waitForGateway(ctx, testEnv.EnvoyBaseURL)
})
