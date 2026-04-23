# Changelog

All notable changes to the OIDC Gateway will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-04-21

### Fixed

- JWKS matching (`feat: prepare Release/v0.1.1` / #11).

### Changed

- Release preparation for v0.1.1 (tag: `chore: prepare release v0.1.1`).

## [0.1.0] - 2026-04-21

### Added

- Initial OIDC Gateway service and Helm chart (`feat: migrate auth service and Helm chart from dir` / #8).
- CI and automation: Go lint and unit tests, Docker build and push, Helm release to GHCR OCI, Renovate, and container security scan workflows (#9).

### Fixed

- Helm chart: correct `jwt_authn` rule ordering, default image tag, and SPIRE workload class (#10).
- Helm chart: address deep review items for reflection, TLS validation, and public paths (#10).
