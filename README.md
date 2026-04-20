# OIDC Gateway

[![Release](https://img.shields.io/github/v/release/agntcy/oidc-gateway?display_name=tag)](CHANGELOG.md)
[![Lint](https://github.com/agntcy/oidc-gateway/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/marketplace/actions/super-linter)
[![Contributor-Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-fbab2c.svg)](CODE_OF_CONDUCT.md)

## About The Project

`oidc-gateway` is a policy-based OIDC authentication and authorization gateway
for [Envoy](https://www.envoyproxy.io/). It implements the Envoy
[ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter)
gRPC API and provides:

- **OIDC/JWT authentication** — verifies that incoming requests carry a valid
  JWT, forwarded by Envoy's `jwt_authn` filter as the `x-jwt-payload` header.
- **Principal extraction** — maps JWT claims to a canonical principal
  (`user:{iss}:{sub}`, `client:{iss}:{client_id}`, or `ghwf:...` for GitHub
  Actions OIDC tokens).
- **Casbin-based RBAC authorization** — evaluates whether the extracted
  principal is allowed to access the requested gRPC method or HTTP path,
  using roles and policies defined in a YAML config file.
- **Deny lists** — blocks specific users or email addresses regardless of role.
- **Public paths** — allows unauthenticated access to configurable paths such
  as `/healthz` and gRPC reflection.

The gateway is designed to be IdP-agnostic within the OIDC/JWT model: any
issuer reachable by Envoy's `jwt_authn` filter can be configured, including
Dex, Keycloak, Okta, GitHub Actions OIDC, and others.

## Getting Started

### Prerequisites

- [Envoy](https://www.envoyproxy.io/) configured with `jwt_authn` and
  `ext_authz` HTTP filters
- A Helm-compatible Kubernetes cluster (for chart-based deployment)

### Installation

Deploy using the Helm chart:

```sh
helm install oidc-gateway oci://ghcr.io/agntcy/oidc-gateway/helm-charts/oidc-gateway \
  --version <version> \
  -f values.yaml
```

Or run the binary directly:

```sh
CONFIG_PATH=/etc/oidc-gateway/config.yaml \
LISTEN_ADDRESS=:9002 \
./oidc-gateway
```

### Configuration

The gateway is configured via a YAML file. Example:

```yaml
claims:
  userID: "sub"
  emailPath: "email"

issuers:
  - provider: "https://dex.example.com"
    principalType: "user"
  - provider: "https://token.actions.githubusercontent.com"
    principalType: "github"

publicPaths:
  - "/healthz"
  - "/grpc.reflection"

roles:
  admin:
    allowedMethods: ["*"]
    users:
      - "user:https://dex.example.com:admin@example.com"
  viewer:
    allowedMethods:
      - "/example.service.v1.ExampleService/Read"
    users: []
```

## Roadmap

See the [open issues](https://github.com/agntcy/oidc-gateway/issues) for a list
of proposed features and known issues.

## Contributing

Contributions are what make the open source community such an amazing place to
learn, inspire, and create. Any contributions you make are **greatly
appreciated**. For detailed contributing guidelines, please see
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Distributed under the Apache-2.0 License. See [LICENSE](LICENSE) for more
information.
