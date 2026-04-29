// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agntcy/oidc-gateway/identity"
)

// jwtCompactFormParts is the number of segments in a compact JWT: header.payload.signature.
const jwtCompactFormParts = 3

// parsePayloadJSON converts x-jwt-payload (Envoy ext_authz) to raw JSON bytes.
//
// Envoy jwt_authn's forward_payload_header sends the JWT payload segment as base64url
// (often starting with "eyJ"), not decoded JSON. Tests and manual curls may send raw JSON.
// A full JWT (header.payload.sig) is also accepted by decoding the middle segment.
func parsePayloadJSON(headerValue string) ([]byte, error) {
	s := strings.TrimSpace(headerValue)
	if s == "" {
		return nil, fmt.Errorf("empty JWT payload")
	}

	// Raw JSON object/array (tests, dev mocks, proxies that inject claims JSON)
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return []byte(s), nil
	}

	parts := strings.Split(s, ".")
	if len(parts) == jwtCompactFormParts {
		return decodeJWTBase64URLSegment(parts[1])
	}

	return decodeJWTBase64URLSegment(s)
}

func decodeJWTBase64URLSegment(seg string) ([]byte, error) {
	if seg == "" {
		return nil, fmt.Errorf("empty JWT segment")
	}

	// JWT uses unpadded base64url (Envoy forward_payload_header)
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, nil
	}

	// Padded base64url (pad_forward_payload_header / some gateways)
	if b, err := base64.URLEncoding.DecodeString(seg); err == nil {
		return b, nil
	}

	return nil, fmt.Errorf("decode JWT payload segment: invalid base64")
}

// ExtractPrincipal extracts the canonical principal from the JWT payload JSON.
// OIDC principals are normalized as oidc:<providerKey>:<principal>.
// SPIFFE JWT-SVID principals are normalized as spiffe:<spiffe-id>.
// The principal claim is configurable via config.Claims.PrincipalClaim (e.g., "sub" or "email").
func ExtractPrincipal(payloadJSON string, config *OIDCConfig) (identity.IdentityPrincipal, error) {
	if config == nil {
		return "", fmt.Errorf("config is required")
	}

	raw, err := parsePayloadJSON(payloadJSON)
	if err != nil {
		return "", err
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("invalid JWT payload JSON: %w", err)
	}

	iss := getString(payload, "iss")
	if iss == "" {
		return "", fmt.Errorf("missing iss claim")
	}

	issuerCfg := config.GetIssuerConfig(iss)
	if issuerCfg == nil {
		return "", fmt.Errorf("issuer %q is not configured", iss)
	}

	if issuerCfg.AuthFamily == string(identity.AuthFamilySPIFFE) {
		spiffeID := getString(payload, "sub")
		normalized := identity.Identity{
			AuthFamily: identity.AuthFamilySPIFFE,
			Principal:  spiffeID,
		}

		if err := normalized.Validate(); err != nil {
			return "", fmt.Errorf("invalid SPIFFE principal: %w", err)
		}

		return normalized.PrincipalString(), nil
	}

	var principalValue string

	switch {
	case issuerCfg.Provider == GitHubIssuer || issuerCfg.ProviderKey == "github":
		principalValue, err = extractGitHubPrincipal(payload)
	default:
		principalValue, err = extractOIDCPrincipal(payload, config.Claims.PrincipalClaim)
	}

	if err != nil {
		return "", err
	}

	if issuerCfg.ProviderKey == "" {
		return "", fmt.Errorf("providerKey is required for issuer %q", iss)
	}

	normalized := identity.Identity{
		AuthFamily: identity.AuthFamilyOIDC,
		Principal:  fmt.Sprintf("%s:%s", issuerCfg.ProviderKey, principalValue),
	}

	if err := normalized.Validate(); err != nil {
		return "", fmt.Errorf("invalid OIDC principal: %w", err)
	}

	return normalized.PrincipalString(), nil
}

func extractOIDCPrincipal(payload map[string]any, principalClaim string) (string, error) {
	if principalClaim == "" {
		principalClaim = "sub"
	}

	if value := getString(payload, principalClaim); value != "" {
		return value, nil
	}

	// Fallback for machine tokens where principal claim may not exist.
	if value := getMachineIdentity(payload); value != "" {
		return value, nil
	}

	return "", fmt.Errorf("missing %s claim for OIDC principal", principalClaim)
}

func extractGitHubPrincipal(payload map[string]any) (string, error) {
	repo := getString(payload, "repository")
	ref := getString(payload, "ref")
	env := getString(payload, "environment")

	// Prefer workflow_ref, fallback to job_workflow_ref
	workflowRef := getString(payload, "workflow_ref")
	if workflowRef == "" {
		workflowRef = getString(payload, "job_workflow_ref")
	}

	if repo == "" {
		return "", fmt.Errorf("missing repository claim for GitHub principal")
	}

	// Extract workflow file from workflow_ref: owner/repo/.github/workflows/file.yml@ref
	workflowFile := ""

	if workflowRef != "" {
		// Format: owner/repo/.github/workflows/deploy.yml@refs/heads/main
		parts := strings.Split(workflowRef, "@")
		if len(parts) >= 1 {
			path := parts[0]
			if idx := strings.Index(path, ".github/workflows/"); idx >= 0 {
				workflowFile = strings.TrimPrefix(path[idx:], ".github/workflows/")
			}
		}
	}

	if workflowFile == "" {
		return "", fmt.Errorf("missing workflow_ref or job_workflow_ref for GitHub principal")
	}

	if ref == "" {
		ref = "refs/heads/main" // fallback
	}

	principal := fmt.Sprintf("repo:%s:workflow:%s:ref:%s", repo, workflowFile, ref)
	if env != "" {
		principal += ":env:" + env
	}

	return principal, nil
}

func getString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}

	s, _ := v.(string)

	return s
}

func getMachineIdentity(payload map[string]any) string {
	s := getString(payload, "client_id")
	if s != "" {
		return s
	}

	return getString(payload, "azp")
}

// GetEmail extracts email from payload for deny list matching.
// Supports dot notation for nested paths (e.g. "email" or "claims.email").
func GetEmail(payloadJSON, emailClaimPath string) string {
	if payloadJSON == "" || emailClaimPath == "" {
		return ""
	}

	raw, err := parsePayloadJSON(payloadJSON)
	if err != nil {
		return ""
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}

	v := getNestedValue(payload, strings.Split(emailClaimPath, "."))
	if s, ok := v.(string); ok {
		return s
	}

	return ""
}

func getNestedValue(m map[string]any, path []string) any {
	if len(path) == 0 {
		return nil
	}

	v, ok := m[path[0]]
	if !ok {
		return nil
	}

	if len(path) == 1 {
		return v
	}

	next, ok := v.(map[string]any)
	if !ok {
		return nil
	}

	return getNestedValue(next, path[1:])
}
