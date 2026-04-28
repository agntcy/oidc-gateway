# OIDC Gateway

[![Release](https://img.shields.io/github/v/release/agntcy/oidc-gateway?display_name=tag)](CHANGELOG.md)
[![Lint](https://github.com/agntcy/oidc-gateway/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/marketplace/actions/super-linter)
[![Coverage](https://codecov.io/gh/agntcy/oidc-gateway/branch/main/graph/badge.svg)](https://codecov.io/gh/agntcy/oidc-gateway)
[![Contributor-Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-fbab2c.svg)](CODE_OF_CONDUCT.md)

`oidc-gateway` is an Envoy-based authentication and authorization gateway for
services that need to accept human, machine, CI/CD, and SPIFFE workload
identities through one consistent backend contract.

The gateway validates credentials at the edge, normalizes the caller into a
canonical principal, evaluates route-level authorization with Casbin, and
forwards only a minimal identity header to the upstream service. This lets
backends avoid auth mechanism-specific code and rely on a single principal
format.

## What It Does

- Accepts OIDC bearer JWTs, SPIFFE JWT-SVIDs, and SPIFFE X.509-SVID client
  certificates.
- Prefers verified SPIFFE X.509-SVID identity when present and ignores bearer
  tokens in that case.
- Falls back to bearer JWT authentication when no X.509-SVID identity is
  available.
- Allows configured public paths such as `/healthz` and gRPC reflection without
  credentials.
- Denies non-public requests when no supported credential is present.
- Extracts canonical principals such as `oidc:dex:alice`,
  `oidc:github:repo:org/repo:workflow:deploy.yml:ref:refs/heads/main`, and
  `spiffe:spiffe://example.org/ns/default/sa/backend`.
- Authorizes those principals against YAML-defined roles and allowed HTTP or
  gRPC paths.
- Sends upstream services exactly one identity header: `x-auth-principal`.

## Request Flow

```text
client
  |
  |  bearer JWT or SPIFFE X.509-SVID client certificate
  v
Envoy
  |  validates bearer JWTs with jwt_authn
  |  validates downstream mTLS when SPIFFE X.509-SVID is enabled
  |  strips client-supplied x-jwt-payload and x-auth-principal
  v
oidc-gateway ext_authz server
  |  prefers X.509 identity, otherwise reads verified x-jwt-payload
  |  normalizes identity to <auth-family>:<canonical-principal>
  |  evaluates Casbin RBAC
  v
backend service
  |
  |  receives x-auth-principal only when authorization succeeds
```

For non-public paths, the precedence is:

1. SPIFFE X.509-SVID from verified downstream mTLS.
2. OIDC JWT or SPIFFE JWT-SVID from Envoy `jwt_authn`.
3. Deny when neither identity source is available.

## Repository Layout

- `cmd/oidc-gateway`: runnable ext_authz server, Dockerfile, local Docker Compose
  test environment, and local test configs.
- `authzserver`: Envoy ext_authz implementation, payload extraction, config
  validation, deny list handling, and Casbin RBAC integration.
- `identity`: lightweight public Go module for parsing and formatting canonical
  identity principals.
- `install/charts/oidc-gateway`: Helm chart that deploys Envoy and the
  authorization server.
- `Taskfile.yml`: build, lint, test, license, dependency, Helm, and release
  automation.

## Canonical Principal Format

Every authenticated caller is represented as:

```text
<auth-family>:<canonical-principal>
```

Supported auth families:

- `oidc`: OIDC-style identity from a configured issuer alias.
- `spiffe`: SPIFFE identity from either JWT-SVID or X.509-SVID.

Examples:

```text
oidc:dex:alice
oidc:dex:sync-service
oidc:github:repo:org/repo:workflow:deploy.yml:ref:refs/heads/main
spiffe:spiffe://example.org/ns/default/sa/backend
```

OIDC issuers use a stable configured `providerKey`, so policy rules do not need
to embed long issuer URLs. SPIFFE principals keep the full SPIFFE ID.

GitHub workflow wildcard rules are intentionally strict. A GitHub wildcard may
contain exactly one `*`, it must be the final character, and it is only supported
inside the branch ref segment:

```text
oidc:github:repo:org/repo:workflow:deploy.yml:ref:refs/heads/release-*
```

## Backend Header Contract

Backends should consume only:

```http
x-auth-principal: <auth-family>:<canonical-principal>
```

Clients must not set this header themselves. Envoy strips client-supplied
`x-auth-principal`, and the ext_authz server sets it only after successful
authentication and authorization.

`x-jwt-payload` is an internal Envoy-to-ext_authz header. In production, Envoy
sets it after `jwt_authn` validates a bearer JWT. It is not a client API.

## Authorization Config

The ext_authz server loads YAML from `CONFIG_PATH`, defaulting to
`/etc/oidc-gateway/config.yaml`.

```yaml
claims:
  principalClaim: "sub"
  emailClaimPath: "email"

issuers:
  - providerKey: "dex"
    provider: "https://dex.example.com"
    authFamily: "oidc"
  - providerKey: "github"
    provider: "https://token.actions.githubusercontent.com"
    authFamily: "oidc"
  - provider: "https://spire-oidc.example.org"
    authFamily: "spiffe"

denyList:
  - "oidc:dex:blocked@example.com"

publicPaths:
  - "/healthz"
  - "/grpc.reflection"

roles:
  admin:
    allowedMethods: ["*"]
    principals:
      - "oidc:dex:admin@example.com"
  workloads:
    allowedMethods:
      - "/example.service.v1.ExampleService/Read"
    principals:
      - "spiffe:*"
      - "oidc:github:repo:org/repo:workflow:deploy.yml:ref:refs/heads/*"
```

Important fields:

- `claims.principalClaim`: JWT claim used as the default OIDC principal value.
- `claims.emailClaimPath`: optional claim path used for email deny-list matching.
- `issuers[].provider`: issuer URL found in the JWT `iss` claim.
- `issuers[].providerKey`: stable alias used in `oidc:<providerKey>:...`
  principals. It is required for OIDC issuers.
- `issuers[].authFamily`: `oidc` or `spiffe`. SPIFFE JWT-SVID issuers produce
  `spiffe:<spiffe-id>` principals.
- `denyList`: principals or email claim values that are always denied.
- `publicPaths`: defense-in-depth public path list for requests that reach the
  authz server. Envoy also disables authz for known public routes.
- `roles`: role definitions. Each role has `allowedMethods` and canonical
  `principals`.

## Helm Deployment

The Helm chart deploys two main workloads:

- Envoy, exposed on `envoy.service.port` and configured with `jwt_authn`,
  `ext_authz`, optional SPIFFE downstream mTLS, and optional SPIFFE upstream mTLS.
- The `oidc-gateway` authorization server, exposed internally on
  `authServer.service.port`.

Install from the published OCI chart:

```sh
helm install oidc-gateway oci://ghcr.io/agntcy/oidc-gateway/helm-charts/oidc-gateway \
  --version <version> \
  -f values.yaml
```

The most important values to set are:

- `envoy.backend.address` and `envoy.backend.port`: upstream backend service.
- `envoy.oidc.issuers`: generic OIDC or SPIFFE JWT-SVID issuers for Envoy
  `jwt_authn`.
- `envoy.oidc.github`: optional GitHub Actions OIDC provider shortcut.
- `envoy.spiffe.enabled`: enables SPIFFE SDS and upstream mTLS to the backend.
- `envoy.spiffe.downstream.enabled`: enables downstream TLS listener support for
  SPIFFE X.509-SVID client certificates.
- `envoy.spiffe.downstream.requireClientCertificate`: controls whether bearer-only
  clients are still allowed.
- `authServer.oidc`: renders the authorization config consumed by the ext_authz
  server.

Minimal values example:

```yaml
envoy:
  backend:
    address: "directory.default.svc.cluster.local"
    port: 8888
  oidc:
    issuers:
      - name: dex
        enabled: true
        issuer: "https://dex.example.com"
        jwksUri: "https://dex.example.com/.well-known/jwks.json"
        jwksHost: "dex.example.com"
  spiffe:
    enabled: true
    trustDomain: example.org
    downstream:
      enabled: true
      requireClientCertificate: false

authServer:
  oidc:
    issuers:
      - providerKey: "dex"
        provider: "https://dex.example.com"
        authFamily: "oidc"
    roles:
      admin:
        allowedMethods: ["*"]
        principals:
          - "oidc:dex:admin@example.com"
```

## Local Development

Prerequisites:

- Go `1.26.2`
- Docker with Buildx
- Docker Compose
- `task` from [Task](https://taskfile.dev/)
- `jq` for the local integration test script

Run the ext_authz server directly:

```sh
cd cmd/oidc-gateway
CONFIG_PATH=./config.yaml \
LISTEN_ADDRESS=:9002 \
LOG_LEVEL=debug \
go run .
```

Run unit tests:

```sh
task test:unit
```

Run all linters:

```sh
task lint
```

Build the container image:

```sh
task build
```

Useful task commands:

- `task deps`: install pinned local tooling into `.bin`.
- `task test:unit`: run unit tests for all Go modules.
- `task test:unit:coverage`: write unit coverage profiles under `.coverage`.
- `task lint:go`: run `golangci-lint`.
- `task lint:helm`: run Helm chart linting.
- `task check`: run lint and license checks.
- `task build`: build the `oidc-gateway` image with Docker Buildx.

## Local Integration Tests

The repository includes a Docker Compose test environment under
`cmd/oidc-gateway`:

- `oidc-gateway` on port `9002`: Envoy ext_authz gRPC server.
- `envoy` on port `8080`: gateway with header mutation, JWT payload forwarding,
  and ext_authz configured.
- `mock-backend` on port `8888`: echoes the identity header received from the
  gateway.
- Envoy admin on port `9901`.

Start the stack:

```sh
cd cmd/oidc-gateway
docker compose up --build
```

Run the test script in another terminal:

```sh
cd cmd/oidc-gateway
./test/test.sh
```

The script checks:

- public health check access without credentials
- rejection when credentials are missing
- rejection of invalid JWT payloads
- successful OIDC principal extraction
- successful SPIFFE JWT-SVID principal extraction
- canonical `x-auth-principal` forwarding to the mock backend
- best-effort XFCC simulation for local X.509-SVID behavior

The local test setup passes `x-jwt-payload` directly for convenience. Production
deployments should rely on Envoy `jwt_authn` to validate bearer JWTs and set that
header. The XFCC test is a simulation; real X.509-SVID validation requires
downstream mTLS and trusted SPIFFE certificate handling.

Inspect logs:

```sh
docker compose logs oidc-gateway
docker compose logs envoy
docker compose logs mock-backend
curl localhost:9901/stats | grep ext_authz
```

Stop the stack:

```sh
docker compose down
```

## Environment Variables

The authorization server reads:

- `CONFIG_PATH`: path to the YAML authorization config. Defaults to
  `/etc/oidc-gateway/config.yaml`.
- `LISTEN_ADDRESS`: gRPC listen address. Defaults to `:9002`.
- `LOG_LEVEL`: `debug`, `info`, `warn`, or `error`. Defaults to `info`.

## Security Notes

- Do not trust client-supplied `x-auth-principal` or `x-jwt-payload` headers.
  Envoy configuration should strip both before authentication processing.
- Keep `failure_mode_allow` disabled for `ext_authz` so authorization service
  failures deny protected traffic.
- Prefer workload identity and short-lived tokens over long-lived credentials.
- Configure issuer audiences in Envoy when your IdP supports stable audience
  values.
- For SPIFFE X.509-SVID, ensure downstream client certificates are validated by
  Envoy through SPIFFE/SPIRE trust bundles before relying on XFCC-derived
  identity.
- Keep public routes explicit and narrow.

## Roadmap

See the [open issues](https://github.com/agntcy/oidc-gateway/issues) for a list
of proposed features and known issues.

## Contributing

Contributions are what make the open source community such an amazing place to
learn, inspire, and create. Any contributions you make are appreciated. For
detailed contributing guidelines, please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Distributed under the Apache-2.0 License. See [LICENSE](LICENSE) for more
information.
