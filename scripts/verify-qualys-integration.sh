#!/bin/bash
# Verify Qualys integration is working

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Verifying Qualys Integration${NC}"
echo -e "${BLUE}============================${NC}"
echo ""

# Get configuration
QUALYS_POD=${QUALYS_POD:-US2}
AWS_REGION=${AWS_REGION:-us-east-1}

# Determine Qualys URLs based on POD
case $QUALYS_POD in
    US1)
        QUALYS_GUI_URL="https://qualysguard.qg1.apps.qualys.com"
        QUALYS_API_URL="https://qualysapi.qg1.apps.qualys.com"
        QUALYS_GATEWAY_URL="https://gateway.qg1.apps.qualys.com"
        ;;
    US2)
        QUALYS_GUI_URL="https://qualysguard.qg2.apps.qualys.com"
        QUALYS_API_URL="https://qualysapi.qg2.apps.qualys.com"
        QUALYS_GATEWAY_URL="https://gateway.qg2.apps.qualys.com"
        ;;
    US3)
        QUALYS_GUI_URL="https://qualysguard.qg3.apps.qualys.com"
        QUALYS_API_URL="https://qualysapi.qg3.apps.qualys.com"
        QUALYS_GATEWAY_URL="https://gateway.qg3.apps.qualys.com"
        ;;
    EU1)
        QUALYS_GUI_URL="https://qualysguard.qg1.apps.qualys.eu"
        QUALYS_API_URL="https://qualysapi.qg1.apps.qualys.eu"
        QUALYS_GATEWAY_URL="https://gateway.qg1.apps.qualys.eu"
        ;;
    *)
        echo -e "${RED}Unknown POD: $QUALYS_POD${NC}"
        exit 1
        ;;
esac

echo -e "${YELLOW}Qualys Configuration:${NC}"
echo -e "  POD: ${QUALYS_POD}"
echo -e "  GUI URL: ${QUALYS_GUI_URL}"
echo -e "  API URL: ${QUALYS_API_URL}"
echo -e "  Gateway URL: ${QUALYS_GATEWAY_URL}"
echo ""

# Step 1: Check if Qualys credentials are configured
echo -e "${YELLOW}[1/5] Checking Qualys credentials...${NC}"

# Try to get credentials from Secrets Manager
SECRET_NAME="qualys-fargate-scanner-qualys-credentials"
QUALYS_CREDS=$(aws secretsmanager get-secret-value \
    --secret-id ${SECRET_NAME} \
    --region ${AWS_REGION} \
    --query 'SecretString' \
    --output text 2>/dev/null || echo "")

if [ -n "$QUALYS_CREDS" ]; then
    echo -e "${GREEN}Credentials found in Secrets Manager${NC}"

    # Extract POD and token
    STORED_POD=$(echo "$QUALYS_CREDS" | jq -r '.qualys_pod')
    QUALYS_TOKEN=$(echo "$QUALYS_CREDS" | jq -r '.qualys_access_token')

    echo -e "  Stored POD: ${STORED_POD}"

    if [ "$STORED_POD" != "$QUALYS_POD" ]; then
        echo -e "${YELLOW}  Warning: Stored POD ($STORED_POD) differs from configured POD ($QUALYS_POD)${NC}"
    fi
else
    echo -e "${YELLOW}Credentials not found in Secrets Manager${NC}"
    echo -e "${YELLOW}Checking environment variable...${NC}"

    if [ -n "$QUALYS_TOKEN" ]; then
        echo -e "${GREEN}Token found in environment variable${NC}"
    else
        echo -e "${RED}No Qualys credentials found${NC}"
        echo -e "${YELLOW}Set QUALYS_TOKEN environment variable or configure Secrets Manager${NC}"
        exit 1
    fi
fi
echo ""

# Step 2: Test Qualys Gateway connectivity
echo -e "${YELLOW}[2/5] Testing Qualys Gateway connectivity...${NC}"

GATEWAY_TEST=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${QUALYS_TOKEN}" \
    "${QUALYS_GATEWAY_URL}/cspm/v1/runtime/events" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"events":[]}' 2>/dev/null || echo "000")

if [ "$GATEWAY_TEST" = "200" ] || [ "$GATEWAY_TEST" = "202" ] || [ "$GATEWAY_TEST" = "400" ]; then
    echo -e "${GREEN}Gateway is reachable (HTTP $GATEWAY_TEST)${NC}"
    echo -e "  URL: ${QUALYS_GATEWAY_URL}"
elif [ "$GATEWAY_TEST" = "401" ] || [ "$GATEWAY_TEST" = "403" ]; then
    echo -e "${RED}Authentication failed (HTTP $GATEWAY_TEST)${NC}"
    echo -e "${YELLOW}Check your Qualys access token${NC}"
else
    echo -e "${RED}Cannot reach Qualys Gateway (HTTP $GATEWAY_TEST)${NC}"
    echo -e "${YELLOW}Check network connectivity and firewall rules${NC}"
fi
echo ""

# Step 3: Check Lambda scanner logs for Qualys integration
echo -e "${YELLOW}[3/5] Checking Lambda scanner logs...${NC}"

SCANNER_LOGS=$(aws logs filter-log-events \
    --log-group-name /aws/lambda/qualys-fargate-scanner-image-scanner \
    --start-time $(($(date +%s) - 86400))000 \
    --filter-pattern "QScanner" \
    --limit 5 \
    --region ${AWS_REGION} 2>/dev/null || echo "")

if [ -n "$SCANNER_LOGS" ]; then
    SCAN_COUNT=$(echo "$SCANNER_LOGS" | jq '.events | length')
    echo -e "${GREEN}Found ${SCAN_COUNT} recent scanner executions${NC}"

    # Check for successful scans
    SUCCESS_COUNT=$(echo "$SCANNER_LOGS" | jq '[.events[] | select(.message | contains("exit code: 0"))] | length')
    echo -e "  Successful scans: ${SUCCESS_COUNT}"

    # Check for errors
    ERROR_COUNT=$(echo "$SCANNER_LOGS" | jq '[.events[] | select(.message | contains("Error"))] | length')
    if [ "$ERROR_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}  Errors found: ${ERROR_COUNT}${NC}"
    fi
else
    echo -e "${YELLOW}No recent scanner logs found${NC}"
    echo -e "  This is normal if no images have been pushed recently"
fi
echo ""

# Step 4: Check runtime sidecar Qualys integration
echo -e "${YELLOW}[4/5] Checking runtime sidecar Qualys integration...${NC}"

SIDECAR_LOGS=$(aws logs filter-log-events \
    --log-group-name /ecs/fargate-runtime-security \
    --start-time $(($(date +%s) - 3600))000 \
    --filter-pattern "Qualys CRS" \
    --limit 10 \
    --region ${AWS_REGION} 2>/dev/null || echo "")

if [ -n "$SIDECAR_LOGS" ]; then
    echo -e "${GREEN}Runtime sidecar is integrated with Qualys CRS${NC}"

    # Check for successful event submissions
    SENT_EVENTS=$(echo "$SIDECAR_LOGS" | jq '[.events[] | select(.message | contains("Sent") and contains("events to Qualys"))] | length')
    if [ "$SENT_EVENTS" -gt 0 ]; then
        echo -e "  Successfully sent events: ${SENT_EVENTS}"
    fi

    # Check for errors
    ERROR_MSGS=$(echo "$SIDECAR_LOGS" | jq '[.events[] | select(.message | contains("Error sending events"))] | length')
    if [ "$ERROR_MSGS" -gt 0 ]; then
        echo -e "${YELLOW}  Errors sending events: ${ERROR_MSGS}${NC}"
    fi
else
    echo -e "${YELLOW}No runtime sidecar Qualys logs found${NC}"
    echo -e "  This is normal if no Fargate tasks are currently running"
fi
echo ""

# Step 5: Show how to access Qualys dashboard
echo -e "${YELLOW}[5/5] How to view results in Qualys dashboard${NC}"
echo ""

echo -e "${BLUE}Image Scan Results:${NC}"
echo -e "1. Open: ${QUALYS_GUI_URL}"
echo -e "2. Log in with your Qualys credentials"
echo -e "3. Navigate to: Container Security > Images"
echo -e "4. Filter by registry: AWS ECR"
echo -e "5. Search for your repository name"
echo ""

echo -e "${BLUE}Runtime Security Events:${NC}"
echo -e "1. Open: ${QUALYS_GUI_URL}"
echo -e "2. Navigate to: Container Security > Runtime"
echo -e "3. Select: Events or Detections"
echo -e "4. Filter by:"
echo -e "   - Time range"
echo -e "   - Event type (process, file, network)"
echo -e "   - Severity level"
echo ""

echo -e "${BLUE}API Access (Alternative):${NC}"
echo -e "# List container images"
echo -e "curl -u \"USERNAME:PASSWORD\" \\"
echo -e "  \"${QUALYS_API_URL}/cspm/v1.3/images\" \\"
echo -e "  -H \"Content-Type: application/json\""
echo ""
echo -e "# Query runtime events"
echo -e "curl -H \"Authorization: Bearer \${QUALYS_TOKEN}\" \\"
echo -e "  \"${QUALYS_GATEWAY_URL}/cspm/v1/runtime/events\""
echo ""

# Summary
echo -e "${BLUE}============================${NC}"
echo -e "${BLUE}Integration Summary${NC}"
echo -e "${BLUE}============================${NC}"
echo ""

CHECKS_PASSED=0
CHECKS_TOTAL=3

[ -n "$QUALYS_CREDS" ] || [ -n "$QUALYS_TOKEN" ] && ((CHECKS_PASSED++))
[ "$GATEWAY_TEST" = "200" ] || [ "$GATEWAY_TEST" = "202" ] || [ "$GATEWAY_TEST" = "400" ] && ((CHECKS_PASSED++))
[ -n "$SCANNER_LOGS" ] || [ -n "$SIDECAR_LOGS" ] && ((CHECKS_PASSED++))

echo -e "Integration checks passed: ${CHECKS_PASSED}/${CHECKS_TOTAL}"
echo ""

if [ $CHECKS_PASSED -eq $CHECKS_TOTAL ]; then
    echo -e "${GREEN}Qualys integration is working correctly!${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo -e "1. View results in Qualys dashboard at: ${QUALYS_GUI_URL}"
    echo -e "2. Configure alerting in Qualys for critical findings"
    echo -e "3. Set up automated compliance reports"
elif [ $CHECKS_PASSED -ge 1 ]; then
    echo -e "${YELLOW}Partial Qualys integration detected.${NC}"
    echo -e "Some components may still be initializing."
else
    echo -e "${RED}Qualys integration not working.${NC}"
    echo -e "Review the checks above and troubleshoot any failures."
fi
echo ""
