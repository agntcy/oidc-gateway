# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.1.5] - 2026-09-14

Security maintenance release. No functional changes; upgrading is recommended for the dependency fixes below.

### Security

- **Deps**: Update `google.golang.org/grpc` to v1.83.2, resolving the advisories reported against v1.82.1 (#88, #92, #102, #103).
- **Deps**: Update `golang.org/x/net` to v0.59.0 (#90) and `google.golang.org/protobuf` to v1.36.12 (#83).
- **Deps**: Pick up `golang.org/x/text` v0.42.0 and `golang.org/x/sys` v0.48.0 transitively, clearing the advisories against the earlier releases.
- **Verification**: `govulncheck` reports no known vulnerabilities in `identity`, `authzserver`, or `cmd/oidc-gateway`.

### Changed

- **Runtime**: Build with Go 1.27.1, up from 1.26.3 (#89, #96).
- **Envoy**: Update `github.com/envoyproxy/go-control-plane/envoy` to v1.39.0 (#86).
- **Deps**: Update `golang.org/x/time` to v0.16.0 (#91) and the `google.golang.org/genproto/googleapis/rpc` digest (#82).
- **Image**: Refresh the `gcr.io/distroless/static:nonroot` base image digest (#43).

### Fixed

- **CI**: Unpin the Go toolchain for the Renovate job so Go version bumps can update `go.mod` instead of deadlocking (#97).

## [v1.1.4] - 2026-08-17

### Fixed

- **Gateway**: Report the underlying OIDC token validation error instead of a generic failure (#79).

### Security

- **Deps**: Update `golang.org/x/text` to v0.39.0 (#73) and `google.golang.org/grpc` to v1.82.1 (#74).

### Changed

- **Runtime**: Build with Go 1.26.6 (#58, #60).
- **Deps**: Update `github.com/spiffe/go-spiffe/v2` to v2.8.1 (#69) and `golang.org/x/net` to v0.58.0 (#70).

## [v1.1.3] - 2026-08-06

### Added

- **Authz**: Group-based authentication, allowing authorization rules to match on group membership (#76).

## [v1.1.2] - 2026-07-21

### Added

- **Authz**: JWT-SVID validation, so SPIFFE JWT-SVIDs are verified alongside OIDC tokens (#67).
- **Gateway**: Rate limit service (#61) and local rate limiting (#57).
- **Helm**: `federatesWith` on the authz-server `ClusterSPIFFEID` for cross-trust-domain federation (#71).
- **Helm**: OpenShift install support (#48).
- **CI**: End-to-end test suite (#65) and end-to-end rate limit tests (#66); feature branch release workflow (#56).

### Changed

- **Runtime**: Build with Go 1.26.3 (#45, #46, #53).

### Security

- **Deps**: Update `golang.org/x/net` to v0.55.0 (#49) and `golang.org/x/sys` to v0.44.0 (#50).

## [v1.1.1] - 2026-05-12

### Added

- **Envoy**: Configure ALPN protocols on the Envoy listeners (#40).

### Changed

- **CI**: Replace Dependabot with Renovate for dependency automation (#29, #30, #31).
- **Deps**: Update `google.golang.org/grpc` to v1.81.0 (#38).

### Fixed

- **CI**: Correct the stale workflow configuration (#33).

## [v1.1.0] - 2026-04-30

### Added

- **Helm**: `envoy.endpoints.oidc` and `envoy.endpoints.mtls` for separate Envoy listener ports, `servicePort` mapping, and per-endpoint downstream TLS (including optional client certificate requirement on the mTLS listener).
- **Helm**: `ingress.oidc` and `ingress.mtls` so clusters can expose JWT-oriented and mTLS-oriented hostnames independently (for example TLS termination plus gRPC vs TLS passthrough).
- **Helm**: Refactor Envoy `ConfigMap` generation with a shared `oidc-gateway.envoyListener` template; the mTLS listener omits `jwt_authn` so identities come from the client certificate and ext_authz.

### Changed

- **Helm**: Service and Deployment publish only the ports for enabled endpoints; ingress templates render zero, one, or two ingresses from `ingress.oidc` / `ingress.mtls`.
- **Docs**: README and TESTING describe the two-listener / two-hostname pattern and chart migration from v1.0.0.

### Removed

- **Helm**: Legacy single top-level `ingress` configuration and the prior single-listener-oriented Envoy service port layout; operators must adopt `envoy.endpoints.*` and split ingress values.

## [v1.0.0] - 2026-04-29

### Added

- **Authz**: Support unified authorization for OIDC JWT, SPIFFE JWT-SVID, and SPIFFE X.509-SVID identities.
- **Identity**: Add lightweight `github.com/agntcy/oidc-gateway/identity` module for canonical principal parsing and formatting.
- **Gateway**: Forward a configurable canonical principal header, defaulting to `x-auth-principal`, to upstream services.
- **Helm**: Add configuration for SPIFFE downstream mTLS, principal header forwarding, and principal-based authorization rules.
- **CI**: Add Codecov configuration, coverage upload workflow, and coverage badge.

### Changed
- **Authz**: Prefer verified SPIFFE X.509-SVID identity when present, then fall back to verified bearer JWT payloads.
- **Config**: Replace user/client/workflow-specific role fields with canonical `principals` and principal-centric claim/deny-list names.
- **RBAC**: Enable wildcard matching for canonical principal assignments and enforce strict GitHub workflow wildcard semantics.
- **Docs**: Expand README and testing documentation for local development, Helm deployment, principal formats, and header trust boundaries.

### Fixed
- **Testing**: Align local Envoy integration tests with `x-jwt-payload` and configurable principal header handling.

## [v0.1.1] - 2026-04-21

### Changed
- **Release**: Prepare release v0.1.1 (#11)

### Fixed
- **Gateway**: JWKS matching (#11)

## [v0.1.0] - 2026-04-21

### Added
- **Gateway**: Migrate auth service and Helm chart from Directory (#8)
- **CI**: Go lint and unit tests, Docker build and push, Helm release to GHCR OCI, Renovate, and container security scanning (#9)

### Fixed
- **Helm**: Correct `jwt_authn` rule ordering, default image tag, and SPIRE workload class (#10)
- **Helm**: Address deep review items for reflection, TLS validation, and public paths (#10)

---

[Full Changelog](https://github.com/agntcy/oidc-gateway/compare/v1.1.4...v1.1.5)

---

[Full Changelog](https://github.com/agntcy/oidc-gateway/compare/v1.1.3...v1.1.4)

---

[Full Changelog](https://github.com/agntcy/oidc-gateway/compare/v1.1.2...v1.1.3)

---

[Full Changelog](https://github.com/agntcy/oidc-gateway/compare/v1.1.1...v1.1.2)

---

[Full Changelog](https://github.com/agntcy/oidc-gateway/compare/v1.1.0...v1.1.1)

---

[Full Changelog](https://github.com/agntcy/oidc-gateway/compare/v1.0.0...v1.1.0)

---

[Full Changelog](https://github.com/agntcy/oidc-gateway/compare/v0.1.1...v1.0.0)

---

[Full Changelog](https://github.com/agntcy/oidc-gateway/compare/v0.1.0...v0.1.1)

---

## Legend

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes
