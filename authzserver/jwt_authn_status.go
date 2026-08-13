// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

const (
	// JWTAuthnMetadataNamespace is the dynamic metadata namespace used by Envoy's
	// jwt_authn filter. Envoy only forwards it to ext_authz when the namespace is
	// listed in metadata_context_namespaces.
	JWTAuthnMetadataNamespace = "envoy.filters.http.jwt_authn"

	// JWTAuthnFailedStatusKey must match failed_status_in_metadata as configured
	// on every jwt_authn provider in the Envoy config.
	JWTAuthnFailedStatusKey = "failed_status"

	jwtAuthnStatusCodeField    = "code"
	jwtAuthnStatusMessageField = "message"
)

// jwtAuthnFailure is the verification status jwt_authn recorded for a bearer
// token it refused, for example code 3 with message "Jwt expired".
type jwtAuthnFailure struct {
	Code    int
	Message string
}

// jwtAuthnFailureFromRequest reports why Envoy's jwt_authn filter refused the
// bearer token, when it refused one.
//
// Providers are configured with allow_missing_or_failed so that federated
// JWT-SVIDs, which match no OIDC issuer, reach this server for SPIRE
// validation. The same setting also lets through OIDC tokens that a provider
// matched and then rejected, and those arrive looking exactly like an SVID.
// The recorded status is the only thing that tells the two apart.
func jwtAuthnFailureFromRequest(req *authv3.CheckRequest) (jwtAuthnFailure, bool) {
	namespace := req.GetAttributes().GetMetadataContext().GetFilterMetadata()[JWTAuthnMetadataNamespace]
	if namespace == nil {
		return jwtAuthnFailure{}, false
	}

	status := namespace.GetFields()[JWTAuthnFailedStatusKey].GetStructValue()
	if status == nil {
		return jwtAuthnFailure{}, false
	}

	message := strings.TrimSpace(status.GetFields()[jwtAuthnStatusMessageField].GetStringValue())
	if message == "" {
		return jwtAuthnFailure{}, false
	}

	return jwtAuthnFailure{
		Code:    int(status.GetFields()[jwtAuthnStatusCodeField].GetNumberValue()),
		Message: message,
	}, true
}
