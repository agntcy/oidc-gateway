// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package shared

import "testing"

func TestParseJWTSVIDFetchOutput(t *testing.T) {
	const want = "eyJhbGci.test.token"

	t.Run("array with svid and bundles responses", func(t *testing.T) {
		input := []byte(`[
			{"svids":[{"spiffe_id":"spiffe://example.org/ns/default/sa/workload","svid":"` + want + `"}]},
			{"bundles":{"example.org":"abc"}}
		]`)

		got, err := parseJWTSVIDFetchOutput(input)
		if err != nil {
			t.Fatalf("parseJWTSVIDFetchOutput: %v", err)
		}

		if got != want {
			t.Fatalf("got token %q, want %q", got, want)
		}
	})

	t.Run("single svid response object", func(t *testing.T) {
		input := []byte(`{"svids":[{"spiffe_id":"spiffe://example.org/ns/default/sa/workload","svid":"` + want + `"}]}`)

		got, err := parseJWTSVIDFetchOutput(input)
		if err != nil {
			t.Fatalf("parseJWTSVIDFetchOutput: %v", err)
		}

		if got != want {
			t.Fatalf("got token %q, want %q", got, want)
		}
	})
}
