# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[Full Changelog](https://github.com/agntcy/oidc-gateway/compare/v0.1.0...v0.1.1)

---

## Legend

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes
