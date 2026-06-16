// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package authzserver

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/agntcy/oidc-gateway/identity"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Header names for JWT and principal propagation.
const (
	HeaderJWTPayload    = "x-jwt-payload"    // verified JWT payload (set by Envoy jwt_authn)
	HeaderAuthPrincipal = "x-auth-principal" // canonical identity forwarded to backend
	HeaderXFCC          = "x-forwarded-client-cert"
)

// OIDCAuthorizationServer implements the Envoy ext_authz gRPC API for OIDC.
// It reads the verified JWT payload from x-jwt-payload, extracts the principal
// using issuer-specific logic, and enforces Casbin RBAC. When configured, it
// also validates JWT-SVID bearer tokens via the SPIRE Workload API.
type OIDCAuthorizationServer struct {
	authv3.UnimplementedAuthorizationServer

	config       *OIDCConfig
	roleResolver *OIDCRoleResolver
	jwtValidator JWTValidator
	logger       *slog.Logger
}

// ServerOption configures optional authorization server behavior.
type ServerOption func(*serverOptions)

type serverOptions struct {
	jwtValidator JWTValidator
}

// WithJWTValidator injects a JWT-SVID validator (used in tests).
func WithJWTValidator(v JWTValidator) ServerOption {
	return func(o *serverOptions) {
		o.jwtValidator = v
	}
}

// NewOIDCAuthorizationServer creates a new OIDC authorization server.
func NewOIDCAuthorizationServer(
	ctx context.Context,
	config *OIDCConfig,
	logger *slog.Logger,
	opts ...ServerOption,
) (*OIDCAuthorizationServer, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if logger == nil {
		logger = slog.Default()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	var options serverOptions
	for _, opt := range opts {
		opt(&options)
	}

	jwtValidator := options.jwtValidator
	if jwtValidator == nil && config.SpiffeJWT.Enabled {
		var err error

		jwtValidator, err = NewWorkloadJWTValidator(ctx, config.SpiffeJWT.SocketPath, config.SpiffeJWT.Audiences)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT-SVID validator: %w", err)
		}
	}

	roleResolver, err := NewOIDCRoleResolver(config, logger)
	if err != nil {
		if jwtValidator != nil {
			_ = jwtValidator.Close()
		}

		return nil, fmt.Errorf("failed to create role resolver: %w", err)
	}

	return &OIDCAuthorizationServer{
		config:       config,
		roleResolver: roleResolver,
		jwtValidator: jwtValidator,
		logger:       logger,
	}, nil
}

// Close releases resources held by the authorization server.
func (s *OIDCAuthorizationServer) Close() error {
	if s.jwtValidator != nil {
		if err := s.jwtValidator.Close(); err != nil {
			return fmt.Errorf("close jwt validator: %w", err)
		}
	}

	return nil
}

// Check implements the ext_authz Check RPC.
func (s *OIDCAuthorizationServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	path := httpReq.GetPath()

	s.logger.Debug("received authorization request", "path", path, "method", httpReq.GetMethod())

	// 1. Public paths -> Allow
	if s.config.IsPublicPath(path) {
		s.logger.Debug("allowed: public path", "path", path)

		return s.allowResponse(""), nil
	}

	headers := httpReq.GetHeaders()
	// 2. Prefer verified client X.509 identity if present; ignore bearer token in this case.
	if spiffeID := extractSPIFFEFromRequest(req, headers); spiffeID != "" {
		principal := identity.Identity{
			AuthFamily: identity.AuthFamilySPIFFE,
			Principal:  spiffeID,
		}.PrincipalString()

		if err := s.roleResolver.Authorize(string(principal), path); err != nil {
			s.logger.Info("authorization denied", "principal", principal, "path", path, "reason", err.Error())

			return s.denyResponse(codes.PermissionDenied, err.Error()), nil
		}

		s.logger.Info("authorization granted via x509", "principal", principal, "path", path)

		return s.allowResponse(string(principal)), nil
	}

	// 3. Verified OIDC / SPIRE-OIDC JWT payload from Envoy jwt_authn.
	payloadJSON := getHeader(headers, HeaderJWTPayload)
	if payloadJSON != "" {
		return s.authorizeFromJWTPayload(ctx, path, payloadJSON)
	}

	// 4. JWT-SVID bearer token validated via SPIRE Workload API (federated bundles).
	if s.jwtValidator != nil {
		return s.authorizeFromJWTSVID(ctx, path, headers)
	}

	s.logger.Warn("missing credentials: neither x509 SPIFFE identity nor verified JWT payload present")

	return s.denyResponse(codes.Unauthenticated, "missing credentials"), nil
}

func (s *OIDCAuthorizationServer) authorizeFromJWTPayload(_ context.Context, path, payloadJSON string) (*authv3.CheckResponse, error) {
	principal, err := ExtractPrincipal(payloadJSON, s.config)
	if err != nil {
		s.logger.Warn("failed to extract principal", "error", err)

		return s.denyResponse(codes.Unauthenticated, "invalid token: "+err.Error()), nil
	}

	email := GetEmail(payloadJSON, s.config.Claims.EmailClaimPath)
	if s.roleResolver.IsDenied(string(principal), email) {
		s.logger.Info("denied: principal in deny list", "principal", principal)

		return s.denyResponse(codes.PermissionDenied, "principal is in the deny list"), nil
	}

	return s.authorizePrincipal(string(principal), path, "jwt-payload")
}

func (s *OIDCAuthorizationServer) authorizeFromJWTSVID(ctx context.Context, path string, headers map[string]string) (*authv3.CheckResponse, error) {
	token := extractBearerToken(headers)
	if token == "" {
		s.logger.Warn("missing credentials: JWT-SVID validation enabled but no bearer token present")

		return s.denyResponse(codes.Unauthenticated, "missing credentials"), nil
	}

	spiffeID, err := s.jwtValidator.ValidateToken(ctx, token)
	if err != nil {
		s.logger.Warn("JWT-SVID validation failed", "error", err)

		return s.denyResponse(codes.Unauthenticated, "invalid JWT-SVID: "+err.Error()), nil
	}

	principal := principalFromSPIFFEID(spiffeID).PrincipalString()

	return s.authorizePrincipal(string(principal), path, "jwt-svid")
}

func (s *OIDCAuthorizationServer) authorizePrincipal(principal, path, via string) (*authv3.CheckResponse, error) {
	if err := s.roleResolver.Authorize(principal, path); err != nil {
		s.logger.Info("authorization denied", "principal", principal, "path", path, "reason", err.Error(), "via", via)

		return s.denyResponse(codes.PermissionDenied, err.Error()), nil
	}

	s.logger.Info("authorization granted", "principal", principal, "path", path, "via", via)

	return s.allowResponse(principal), nil
}

func (s *OIDCAuthorizationServer) allowResponse(principal string) *authv3.CheckResponse {
	headers := []*corev3.HeaderValueOption{}

	if principal != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{Key: s.config.AuthPrincipalHeader(), Value: principal},
			Append: wrapperspb.Bool(false), // overwrite any client-supplied value
		})
	}

	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{Headers: headers},
		},
	}
}

func (s *OIDCAuthorizationServer) denyResponse(code codes.Code, message string) *authv3.CheckResponse {
	httpStatus := typev3.StatusCode_Forbidden
	if code == codes.Unauthenticated {
		httpStatus = typev3.StatusCode_Unauthorized
	}

	return &authv3.CheckResponse{
		Status: &status.Status{
			Code:    int32(code), //nolint:gosec // G115: gRPC codes 0-16 fit in int32; status.Status requires int32
			Message: message,
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: httpStatus},
				Body:   fmt.Sprintf(`{"error": "%s", "message": "%s"}`, code.String(), message),
				Headers: []*corev3.HeaderValueOption{
					{Header: &corev3.HeaderValue{Key: "content-type", Value: "application/json"}},
				},
			},
		},
	}
}

func getHeader(headers map[string]string, key string) string {
	// Envoy headers may be lowercase
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}

	return ""
}

func extractSPIFFEFromRequest(req *authv3.CheckRequest, headers map[string]string) string {
	// 1) Prefer Envoy provided source principal (mTLS authenticated principal).
	if sourcePrincipal := req.GetAttributes().GetSource().GetPrincipal(); strings.HasPrefix(sourcePrincipal, "spiffe://") {
		return sourcePrincipal
	}

	// 2) Fallback to XFCC URI extracted from peer cert details.
	return extractSPIFFEFromXFCC(getHeader(headers, HeaderXFCC))
}

func extractSPIFFEFromXFCC(xfcc string) string {
	for entry := range strings.SplitSeq(xfcc, ",") {
		for field := range strings.SplitSeq(entry, ";") {
			trimmed := strings.TrimSpace(field)
			if !strings.HasPrefix(trimmed, "URI=") {
				continue
			}

			uri := strings.Trim(strings.TrimPrefix(trimmed, "URI="), "\"")
			if strings.HasPrefix(uri, "spiffe://") {
				return uri
			}
		}
	}

	return ""
}
