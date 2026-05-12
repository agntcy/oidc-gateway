// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

// Shared string literals for tests (goconst).
const (
	testPathHealthz                 = "/healthz"
	testProviderKeyDex              = "dex"
	testDexIssuerURL                = "https://dex.example.com"
	testRoleAdmin                   = "admin"
	testRoleViewer                  = "viewer"
	testAuthFamilyOIDC              = "oidc"
	testAuthFamilySPIFFE            = "spiffe"
	testPrincipalOIDCDexAdmin       = "oidc:dex:admin"
	testPrincipalOIDCDexAdminEmail  = "oidc:dex:admin@example.com"
	testErrInvalidGitHubWildcard    = "invalid github workflow wildcard"
	testClaimEmail                  = "email"
	testPrincipalDexNumeric         = "oidc:dex:77776025198584418"
	testPathStorePush               = "/agntcy.dir.store.v1.StoreService/Push"
	testPrincipalDex111             = "oidc:dex:111"
	testPathStorePull               = "/agntcy.dir.store.v1.StoreService/Pull"
	testPrincipalGitHubWorkflowProd = "oidc:github:repo:agntcy/oidc-gateway:workflow:deploy.yml:ref:refs/heads/main:env:prod"
	testPathSearchCIDs              = "/agntcy.dir.search.v1.SearchService/SearchCIDs"
)
