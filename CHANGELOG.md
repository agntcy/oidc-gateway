# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
