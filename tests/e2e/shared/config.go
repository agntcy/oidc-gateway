// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"net/url"
	"os"

	"github.com/onsi/gomega"
)

const (
	defaultEnvoyURL      = "http://127.0.0.1:18080"
	defaultEnvoyAdminURL = "http://127.0.0.1:19901"
	defaultDexURL        = "http://127.0.0.1:15556"
)

type TestConfig struct {
	EnvoyBaseURL  string
	EnvoyAdminURL string
	DexURL        string
}

func (c *TestConfig) ParseEnvoyBaseURL() *url.URL {
	_url, err := url.Parse(c.EnvoyBaseURL)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return _url
}

func (c *TestConfig) ParseEnvoyAdminURL() *url.URL {
	_url, err := url.Parse(c.EnvoyAdminURL)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return _url
}

func (c *TestConfig) GetEnvoyHost() string {
	return c.ParseEnvoyBaseURL().Host
}

func NewTestConfig() *TestConfig {
	envoyBaseURL := os.Getenv("ENVOY_BASE_URL")
	if envoyBaseURL == "" {
		envoyBaseURL = defaultEnvoyURL
	}

	envoyAdminURL := os.Getenv("ENVOY_ADMIN_URL")
	if envoyAdminURL == "" {
		envoyAdminURL = defaultEnvoyAdminURL
	}

	dexURL := os.Getenv("DEX_URL")
	if dexURL == "" {
		dexURL = defaultDexURL
	}

	return &TestConfig{
		EnvoyBaseURL:  envoyBaseURL,
		EnvoyAdminURL: envoyAdminURL,
		DexURL:        dexURL,
	}
}
