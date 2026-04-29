# Testing Guide

## Quick Start

```bash
cd cmd/oidc-gateway

# Start all services
docker-compose up --build

# In another terminal, run tests
./test/test.sh
```

## What Gets Tested

1. ✅ Health check (no auth)
2. ✅ Request without credentials on non-public path → 401
3. ✅ Request with invalid payload (without x509) → 401
4. ✅ Request with valid OIDC payload → 200
5. ✅ Request with SPIFFE JWT-SVID payload → 200
6. ⚠ XFCC SPIFFE simulation is best-effort in local non-mTLS setup
7. ✅ Configured canonical identity header forwarded (`x-auth-principal` by default)

## Services

- **oidc-gateway** (port 9002) - ExtAuthz service (x509 + bearer fallback, Casbin RBAC)
- **envoy** (port 8080) - Envoy gateway with ext_authz filter
- **mock-backend** (port 8888) - Mock backend (echoes headers)

## Testing Manually

```bash
# Valid request with mock JWT payload (dev/test only)
curl -H "x-jwt-payload: {\"iss\":\"https://dex.example.com\",\"email\":\"admin@example.com\"}" \
     http://localhost:8080/api/test | jq .

# Check logs
docker-compose logs oidc-gateway
docker-compose logs envoy
docker-compose logs mock-backend

# Envoy admin
curl http://localhost:9901/stats | grep ext_authz
```

## Configuration

The test uses `test/config.test.yaml` mounted at `/etc/oidc-gateway/config.yaml`. It allows:

- **Public path**: `/healthz` (no auth)
- **Principal header**: `x-auth-principal`
- **Admin principal**: `oidc:dex:admin@example.com` (all methods)
- **SPIFFE principal**: `spiffe:*` (all methods)

To test deny list or different roles, edit `test/config.test.yaml` and restart:

```yaml
headers:
  authPrincipal: "x-auth-principal"

denyList:
  - "oidc:dex:blocked@example.com"

roles:
  admin:
    allowedMethods: ["*"]
    principals:
      - "oidc:dex:admin@example.com"
```

## Production Flow

In production, Envoy prefers SPIFFE X.509-SVID when present, otherwise validates
Bearer JWTs and sets `x-jwt-payload` before ext_authz. This test setup passes
`x-jwt-payload` directly for simplicity (dev/test only). The local X.509 case in
`test.sh` uses `x-forwarded-client-cert` simulation, which may be rejected unless
downstream mTLS and trusted cert handling are configured.

The Helm chart can expose separate OIDC/JWT and mTLS endpoints from one Envoy
deployment. This Docker Compose setup only exercises the single local listener
and XFCC simulation; it does not configure real downstream SPIFFE mTLS.

## Cleanup

```bash
docker-compose down
```
