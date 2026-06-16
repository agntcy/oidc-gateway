// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/onsi/gomega"
)

const (
	defaultKubeContext          = "kind-oidc-gateway-testenv"
	defaultJWTSVIDTestNamespace = "oidc-gateway-test"
	defaultJWTSVIDTestPodLabel  = "app=jwt-svid-e2e-client"
	defaultJWTSVIDAudience      = "oidc-gateway"
	spireAgentBinary            = "/opt/spire/bin/spire-agent"
	spireWorkloadSocket         = "/run/spire/agent-sockets/api.sock"
	jwtSVIDPollInterval         = 2 * time.Second
	kubectlContextArgCount      = 2 // --context and its value
)

type SpiffeClient struct {
	KubeContext string
	Namespace   string
	PodLabel    string
	Audience    string
}

func NewSpiffeClient() *SpiffeClient {
	kubeContext := os.Getenv("KUBE_CONTEXT")
	if kubeContext == "" {
		kubeContext = defaultKubeContext
	}

	return &SpiffeClient{
		KubeContext: kubeContext,
		Namespace:   defaultJWTSVIDTestNamespace,
		PodLabel:    defaultJWTSVIDTestPodLabel,
		Audience:    defaultJWTSVIDAudience,
	}
}

func (c *SpiffeClient) FetchJWTSVID(ctx context.Context) (string, error) {
	podName, err := podNameForLabel(ctx, c.KubeContext, c.Namespace, c.PodLabel)
	if err != nil {
		return "", err
	}

	output, err := runKubectl(ctx, c.KubeContext,
		"exec", "-n", c.Namespace, "-c", "client", podName, "--",
		spireAgentBinary, "api", "fetch", "jwt",
		"-audience", c.Audience,
		"-socketPath", spireWorkloadSocket,
		"-output", "json",
	)
	if err != nil {
		return "", fmt.Errorf("fetch JWT-SVID from pod %s: %w", podName, err)
	}

	token, err := parseJWTSVIDFetchOutput(output)
	if err != nil {
		return "", fmt.Errorf("parse JWT-SVID response: %w", err)
	}

	return token, nil
}

func parseJWTSVIDFetchOutput(output []byte) (string, error) {
	data := bytes.TrimSpace(output)
	if len(data) == 0 {
		return "", fmt.Errorf("empty JWT-SVID response")
	}

	// SPIRE 1.12+ prints JWTSVIDResponse and JWTBundlesResponse as a JSON array.
	if data[0] == '[' {
		var messages []json.RawMessage
		if err := json.Unmarshal(data, &messages); err != nil {
			return "", fmt.Errorf("decode JWT-SVID response array: %w", err)
		}

		for _, message := range messages {
			token, err := jwtSVIDFromFetchMessage(message)
			if err == nil && token != "" {
				return token, nil
			}
		}

		return "", fmt.Errorf("no JWT-SVID found in response array")
	}

	return jwtSVIDFromFetchMessage(data)
}

func jwtSVIDFromFetchMessage(data []byte) (string, error) {
	var payload struct {
		SVIDs []struct {
			SVID string `json:"svid"`
		} `json:"svids"`
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("decode JWT-SVID message: %w", err)
	}

	if len(payload.SVIDs) == 0 || payload.SVIDs[0].SVID == "" {
		return "", fmt.Errorf("no JWT-SVID in message")
	}

	return payload.SVIDs[0].SVID, nil
}

func WaitForJWTSVID(ctx context.Context, client *SpiffeClient, timeout time.Duration) string {
	var token string

	gomega.Eventually(func(g gomega.Gomega) {
		var err error

		token, err = client.FetchJWTSVID(ctx)
		g.Expect(err).NotTo(gomega.HaveOccurred())
		g.Expect(token).NotTo(gomega.BeEmpty())
	}).
		WithContext(ctx).
		WithTimeout(timeout).
		WithPolling(jwtSVIDPollInterval).
		Should(gomega.Succeed())

	return token
}

func podNameForLabel(ctx context.Context, kubeContext, namespace, labelSelector string) (string, error) {
	output, err := runKubectl(ctx, kubeContext,
		"get", "pods",
		"-n", namespace,
		"-l", labelSelector,
		"--field-selector=status.phase=Running",
		"-o", "jsonpath={.items[?(@.status.containerStatuses[0].ready==true)].metadata.name}",
	)
	if err != nil {
		return "", fmt.Errorf("get pod for label %s: %w", labelSelector, err)
	}

	podName := strings.TrimSpace(string(output))
	if podName == "" {
		return "", fmt.Errorf("no ready pod found for label %s in namespace %s", labelSelector, namespace)
	}

	// jsonpath may return multiple names during rollouts; use the first.
	if fields := strings.Fields(podName); len(fields) > 0 {
		podName = fields[0]
	}

	return podName, nil
}

func runKubectl(ctx context.Context, kubeContext string, args ...string) ([]byte, error) {
	kubectlBin := os.Getenv("KUBECTL_BIN")
	if kubectlBin == "" {
		kubectlBin = "kubectl"
	}

	cmdArgs := make([]string, 0, len(args)+kubectlContextArgCount)
	if kubeContext != "" {
		cmdArgs = append(cmdArgs, "--context", kubeContext)
	}

	cmdArgs = append(cmdArgs, args...)

	//nolint:gosec // G702: kubectl is invoked with fixed subcommands and test-controlled args only.
	cmd := exec.CommandContext(ctx, kubectlBin, cmdArgs...)

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return stdout.Bytes(), nil
}
