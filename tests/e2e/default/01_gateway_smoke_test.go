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

	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Gateway smoke tests", func() {
	ginkgo.It("returns healthy from /healthz", func(ctx context.Context) {
		resp, err := doGET(ctx, testEnv.EnvoyBaseURL+"/healthz")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		defer discardResponseBody(resp.Body)

		gomega.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))

		body, err := io.ReadAll(resp.Body)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		var payload struct {
			Status string `json:"status"`
		}
		gomega.Expect(json.Unmarshal(body, &payload)).To(gomega.Succeed())
		gomega.Expect(payload.Status).To(gomega.Equal("healthy"))
	})

	ginkgo.It("rejects unauthenticated requests to /api/test", func(ctx context.Context) {
		resp, err := doGET(ctx, testEnv.EnvoyBaseURL+"/api/test")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		defer discardResponseBody(resp.Body)

		gomega.Expect(resp.StatusCode).To(gomega.Equal(http.StatusUnauthorized))
	})

	ginkgo.It("reports LIVE on Envoy admin /ready", func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		resp, err := doGET(ctx, testEnv.EnvoyAdminURL+"/ready")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		defer discardResponseBody(resp.Body)

		gomega.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))

		body, err := io.ReadAll(resp.Body)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(strings.TrimSpace(string(body))).To(gomega.Equal("LIVE"))

		ginkgo.GinkgoWriter.Printf("envoy admin ready at %s\n", testEnv.EnvoyAdminURL)
	})
})
