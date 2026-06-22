// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

func DiscardResponse(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func DoGET(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	//nolint:gosec // G704: e2e tests call fixed localhost URLs or env overrides.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		DiscardResponse(resp)

		return nil, fmt.Errorf("GET %s: %w", url, err)
	}

	return resp, nil
}
