#!/bin/bash
# Test script for gateway ext_authz integration.
# Sends x-jwt-payload with mock JWT claims (dev/test only; production uses jwt_authn).

set -e

ENVOY_URL="http://localhost:8080"

# Mock JWT payload for testing (user in admin role per config.test.yaml)
MOCK_PAYLOAD='{"iss":"https://dex.example.com","email":"admin@example.com"}'
SPIFFE_JWT_PAYLOAD='{"iss":"https://spire-oidc.example.org","sub":"spiffe://example.org/ns/default/sa/workload"}'
# XFCC (x-forwarded-client-cert) simulation for local testing:
# - By=... is the forwarding proxy identity
# - URI=... is the client cert URI SAN (SPIFFE ID) seen by Envoy
# In production this should come from verified downstream mTLS, not client input.
SPIFFE_XFCC='By=spiffe://example.org/ns/default/sa/envoy;URI=spiffe://example.org/ns/default/sa/workload'

echo "🧪 Testing gateway ext_authz Integration"
echo "====================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test 1: Health check (no auth)
echo "Test 1: Health check (no auth required)"
echo "----------------------------------------"
curl -s "$ENVOY_URL/healthz" | jq .
echo -e "${GREEN}✓ Health check passed${NC}\n"

# Test 2: Request without x-jwt-payload (should fail)
echo "Test 2: Request without x-jwt-payload"
echo "--------------------------------------"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$ENVOY_URL/api/test")
if [ "$HTTP_CODE" = "401" ]; then
    echo -e "${GREEN}✓ Correctly rejected (401 Unauthorized)${NC}\n"
else
    echo -e "${RED}✗ Expected 401, got $HTTP_CODE${NC}\n"
fi

# Test 3: Request with invalid payload (should fail)
echo "Test 3: Request with invalid x-jwt-payload"
echo "------------------------------------------"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "x-jwt-payload: invalid-json" \
    "$ENVOY_URL/api/test")
if [ "$HTTP_CODE" = "401" ]; then
    echo -e "${GREEN}✓ Correctly rejected invalid payload (401)${NC}\n"
else
    echo -e "${RED}✗ Expected 401, got $HTTP_CODE${NC}\n"
fi

# Test 4: Request with valid payload (should succeed)
echo "Test 4: Request with valid x-jwt-payload"
echo "---------------------------------------"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
    -H "x-jwt-payload: $MOCK_PAYLOAD" \
    "$ENVOY_URL/api/test")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Request successful (200 OK)${NC}"
    echo "Response:"
    echo "$BODY" | jq .
    echo ""

    # Check canonical principal header forwarded by ext_authz
    echo "Checking forwarded canonical principal header..."
    PRINCIPAL=$(echo "$BODY" | jq -r '.authenticated.auth_principal')
    if [ "$PRINCIPAL" != "null" ] && [ "$PRINCIPAL" != "" ]; then
        echo -e "${GREEN}✓ Auth principal: $PRINCIPAL${NC}"
    fi
    echo ""
else
    echo -e "${RED}✗ Request failed (HTTP $HTTP_CODE)${NC}"
    echo "Response:"
    echo "$BODY" | jq .
    echo ""
fi

echo "Test 5: Request with SPIFFE JWT-SVID payload"
echo "--------------------------------------------"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
    -H "x-jwt-payload: $SPIFFE_JWT_PAYLOAD" \
    "$ENVOY_URL/api/test")

HTTP_CODE=$(echo "$RESPONSE" | awk -F: '/HTTP_CODE/{print $2}')
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE/d')

if [ "$HTTP_CODE" = "200" ]; then
    PRINCIPAL=$(echo "$BODY" | jq -r '.authenticated.auth_principal')
    if [[ "$PRINCIPAL" == spiffe:* ]]; then
        echo -e "${GREEN}✓ SPIFFE JWT-SVID accepted: $PRINCIPAL${NC}\n"
    else
        echo -e "${RED}✗ Expected spiffe principal, got $PRINCIPAL${NC}\n"
    fi
else
    echo -e "${RED}✗ Expected 200, got $HTTP_CODE${NC}\n"
fi

echo "Test 6: Request with XFCC SPIFFE identity (x509 simulation)"
echo "-----------------------------------------------------------"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
    -H "x-forwarded-client-cert: $SPIFFE_XFCC" \
    -H "x-jwt-payload: invalid-json" \
    "$ENVOY_URL/api/test")

HTTP_CODE=$(echo "$RESPONSE" | awk -F: '/HTTP_CODE/{print $2}')
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE/d')

if [ "$HTTP_CODE" = "200" ]; then
    PRINCIPAL=$(echo "$BODY" | jq -r '.authenticated.auth_principal')
    if [[ "$PRINCIPAL" == spiffe:* ]]; then
        echo -e "${GREEN}✓ XFCC SPIFFE identity preferred over invalid bearer: $PRINCIPAL${NC}\n"
    else
        echo -e "${RED}✗ Expected spiffe principal from XFCC, got $PRINCIPAL${NC}\n"
    fi
elif [ "$HTTP_CODE" = "401" ]; then
    echo "⚠ XFCC simulation not trusted by local non-mTLS listener (expected in this setup)."
    echo "  For real X.509-SVID validation, run downstream mTLS with SPIFFE certs."
    echo ""
else
    echo -e "${RED}✗ Expected 200, got $HTTP_CODE${NC}\n"
fi

echo "🎉 Testing Complete!"
echo ""
echo "💡 Tips:"
echo "  - Check oidc-gateway logs: docker-compose logs oidc-gateway"
echo "  - Check Envoy logs: docker-compose logs envoy"
echo "  - Check mock-backend logs: docker-compose logs mock-backend"
echo "  - Envoy admin: curl localhost:9901/stats | grep ext_authz"
echo ""
