#!/bin/bash
# Integration test script for Unix (Linux/macOS)
# Usage: ./integration_test.sh [base_url]

set -e

BASE_URL="${1:-http://localhost:8080}"

echo "=== Integration Tests ==="
echo "Base URL: $BASE_URL"
echo ""

PASSED=0
FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

test_endpoint() {
    local name="$1"
    local url="$2"
    local expected_status="$3"
    local expected_content="$4"
    
    printf "Testing %s... " "$name"
    
    response=$(curl -s -w "\n%{http_code}" "$url" 2>/dev/null)
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$status_code" != "$expected_status" ]; then
        echo -e "${RED}FAILED${NC}"
        echo -e "  ${YELLOW}Expected status: $expected_status, got: $status_code${NC}"
        return 1
    fi
    
    if [ -n "$expected_content" ] && ! echo "$body" | grep -q "$expected_content"; then
        echo -e "${RED}FAILED${NC}"
        echo -e "  ${YELLOW}Expected content to contain: $expected_content${NC}"
        echo -e "  ${YELLOW}Got: $body${NC}"
        return 1
    fi
    
    echo -e "${GREEN}PASSED${NC}"
    return 0
}

# Test 1: Health endpoint
if test_endpoint "Health endpoint (GET /health)" "$BASE_URL/health" "200" '"status":"ok"'; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test 2: Classify endpoint (root)
if test_endpoint "Classify endpoint (GET /)" "$BASE_URL/" "200" '"classification"'; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test 3: Debug endpoint
if test_endpoint "Debug endpoint (GET /debug)" "$BASE_URL/debug" "200" '"fingerprint"'; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test 4: Classification using curl (should detect as bot)
if test_endpoint "Curl detection (should be bot)" "$BASE_URL/" "200" '"classification":"bot"'; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test 5: Health via curl
if test_endpoint "Health via curl" "$BASE_URL/health" "200" '"status":"ok"'; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Summary
echo ""
echo -e "${CYAN}=== Results ===${NC}"
echo -e "${GREEN}Passed: $PASSED${NC}"
if [ "$FAILED" -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
    exit 1
else
    echo "Failed: $FAILED"
fi
exit 0
