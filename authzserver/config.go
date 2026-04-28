// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"fmt"
	"strings"

	"github.com/agntcy/oidc-gateway/identity"
)

// GitHub OIDC issuer URL.
const GitHubIssuer = "https://token.actions.githubusercontent.com"

// OIDCConfig holds the OIDC-based authorization configuration.
// Roles come only from config; no roles are extracted from JWT claims.
type OIDCConfig struct {
	Claims      ClaimsConfig        `yaml:"claims"`
	Issuers     []IssuerConfig      `yaml:"issuers"`
	DenyList    []string            `yaml:"denyList"`
	PublicPaths []string            `yaml:"publicPaths"`
	Roles       map[string]OIDCRole `yaml:"roles"`
}

// ClaimsConfig defines which JWT claims to read.
type ClaimsConfig struct {
	PrincipalClaim string `yaml:"principalClaim"` // e.g. "sub"
	EmailClaimPath string `yaml:"emailClaimPath"` // optional; for deny-list email matching
}

// IssuerConfig defines issuer mapping for canonical principal extraction.
// Provider is the OIDC issuer URL (e.g. https://dex.example.com).
type IssuerConfig struct {
	ProviderKey string `yaml:"providerKey"`
	Provider    string `yaml:"provider"`
	AuthFamily  string `yaml:"authFamily"`
}

// GetIssuerConfig returns the IssuerConfig for the given issuer URL, or nil if not found.
func (c *OIDCConfig) GetIssuerConfig(issuerURL string) *IssuerConfig {
	for i := range c.Issuers {
		if c.Issuers[i].Provider == issuerURL {
			return &c.Issuers[i]
		}
	}

	return nil
}

// OIDCRole defines permissions and principal assignments.
// Principals use canonical format: <auth-family>:<canonical-principal>.
type OIDCRole struct {
	AllowedMethods []string `yaml:"allowedMethods"`
	Principals     []string `yaml:"principals"`
}

// Validate validates the OIDC config and returns an error if invalid.
func (c *OIDCConfig) Validate() error {
	if err := c.validateClaims(); err != nil {
		return err
	}

	if err := c.validateIssuers(); err != nil {
		return err
	}

	if err := c.validateRoles(); err != nil {
		return err
	}

	c.normalizePublicPaths()

	return nil
}

func (c *OIDCConfig) validateClaims() error {
	if c.Claims.PrincipalClaim == "" {
		return fmt.Errorf("claims.principalClaim is required")
	}

	return nil
}

var allowedIssuerAuthFamilies = map[string]bool{
	"":                                true,
	string(identity.AuthFamilyOIDC):   true,
	string(identity.AuthFamilySPIFFE): true,
}

func (c *OIDCConfig) validateIssuers() error {
	for i, ic := range c.Issuers {
		if ic.Provider == "" {
			return fmt.Errorf("issuers[%d].provider is required", i)
		}

		if !allowedIssuerAuthFamilies[ic.AuthFamily] {
			return fmt.Errorf(
				"issuers[%q].authFamily must be one of [oidc, spiffe], got %q",
				ic.Provider,
				ic.AuthFamily,
			)
		}

		if ic.AuthFamily != string(identity.AuthFamilySPIFFE) && ic.ProviderKey == "" {
			return fmt.Errorf("issuers[%q].providerKey is required for oidc auth family", ic.Provider)
		}
	}

	return nil
}

func (c *OIDCConfig) validateRoles() error {
	if len(c.Roles) == 0 {
		return fmt.Errorf("at least one role must be defined")
	}

	for roleName, role := range c.Roles {
		if len(role.AllowedMethods) == 0 {
			return fmt.Errorf("role %q has no allowedMethods", roleName)
		}

		for _, principal := range role.Principals {
			if strings.TrimSpace(principal) == "" {
				return fmt.Errorf("role %q contains an empty principal", roleName)
			}

			if strings.HasPrefix(principal, "oidc:github:") && strings.Contains(principal, "*") &&
				!isSupportedGitHubWorkflowWildcard(principal) {
				return fmt.Errorf(
					"role %q has invalid github workflow wildcard principal %q: only one '*' is supported, it must be at the end, and only in oidc:github:repo:...:workflow:...:ref:refs/heads/<branch>*",
					roleName,
					principal,
				)
			}
		}
	}

	return nil
}

// isSupportedGitHubWorkflowWildcard enforces strict wildcard semantics for GitHub workflow principals:
// - principal must start with oidc:github:repo:
// - include :workflow: and :ref:refs/heads/
// - exactly one '*' is allowed
// - '*' must be the final character
// - wildcard must be inside :ref:refs/heads/<branch>* segment.
func isSupportedGitHubWorkflowWildcard(principal string) bool {
	const (
		workflowMarker  = ":workflow:"
		branchRefPrefix = ":ref:refs/heads/"
	)

	if !strings.HasPrefix(principal, "oidc:github:repo:") {
		return false
	}

	if !strings.Contains(principal, workflowMarker) {
		return false
	}

	if strings.Count(principal, "*") != 1 {
		return false
	}

	if !strings.HasSuffix(principal, "*") {
		return false
	}

	refIdx := strings.Index(principal, branchRefPrefix)
	if refIdx < 0 {
		return false
	}

	starPos := len(principal) - 1

	minBranchStart := refIdx + len(branchRefPrefix)

	return starPos >= minBranchStart
}

func (c *OIDCConfig) normalizePublicPaths() {
	if c.PublicPaths == nil {
		c.PublicPaths = []string{}
	}
}

// IsPublicPath returns true if the path is in publicPaths.
// Matching rules:
//   - Exact match: path == publicPath (e.g. "/healthz")
//   - gRPC prefix match: path starts with publicPath+"." or publicPath+"/"
//     This covers gRPC method paths like /grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo
//     matching a publicPath entry of /grpc.reflection.
//
// Note: in typical deployments Envoy handles public routes (healthz, reflection)
// at the route level by disabling ext_authz per-route. publicPaths in this
// config acts as defense-in-depth for any path that reaches the authz server.
func (c *OIDCConfig) IsPublicPath(path string) bool {
	for _, pub := range c.PublicPaths {
		if path == pub {
			return true
		}
		// gRPC package/service prefix: /grpc.reflection matches /grpc.reflection.v1alpha.Service/Method
		if strings.HasPrefix(path, pub+".") || strings.HasPrefix(path, pub+"/") {
			return true
		}
	}

	return false
}
