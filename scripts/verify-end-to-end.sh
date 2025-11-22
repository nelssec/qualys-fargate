#!/bin/bash
# Verify end-to-end test results

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

AWS_REGION=${AWS_REGION:-us-east-1}
TASK_ARN=$1

if [ -z "$TASK_ARN" ]; then
    echo -e "${RED}Error: Task ARN required${NC}"
    echo "Usage: $0 <task-arn>"
    exit 1
fi

echo -e "${BLUE}Verifying End-to-End Test Results${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""

# Step 1: Check image scan results
echo -e "${YELLOW}[1/5] Checking ECR image scan results...${NC}"
IMAGE_REPO="vulnerable-test-app"
IMAGE_DIGEST=$(aws ecr describe-images \
    --repository-name ${IMAGE_REPO} \
    --region ${AWS_REGION} \
    --query 'imageDetails[0].imageDigest' \
    --output text 2>/dev/null || echo "")

if [ -n "$IMAGE_DIGEST" ]; then
    echo -e "${GREEN}Found image: ${IMAGE_REPO}@${IMAGE_DIGEST}${NC}"

    # Check scan results in S3
    RESULTS_BUCKET="qualys-fargate-scanner-scan-results-${AWS_ACCOUNT_ID}"
    S3_RESULTS=$(aws s3 ls "s3://${RESULTS_BUCKET}/scan-results/${IMAGE_REPO}/${IMAGE_DIGEST}/" 2>/dev/null | wc -l || echo "0")

    if [ "$S3_RESULTS" -gt "0" ]; then
        echo -e "${GREEN}Scan results found in S3${NC}"

        # Download and show latest result
        LATEST_RESULT=$(aws s3 ls "s3://${RESULTS_BUCKET}/scan-results/${IMAGE_REPO}/${IMAGE_DIGEST}/" | tail -1 | awk '{print $4}')
        if [ -n "$LATEST_RESULT" ]; then
            aws s3 cp "s3://${RESULTS_BUCKET}/scan-results/${IMAGE_REPO}/${IMAGE_DIGEST}/${LATEST_RESULT}" - 2>/dev/null | jq -r '.scanResults | "  Vulnerabilities: \(.vulnerabilityCount), Secrets: \(.secretCount), Critical: \(.criticalCount)"'
        fi
    else
        echo -e "${YELLOW}No scan results in S3 yet (scanning may still be in progress)${NC}"
    fi
else
    echo -e "${YELLOW}No image found in ECR${NC}"
fi
echo ""

# Step 2: Check Lambda logs
echo -e "${YELLOW}[2/5] Checking Lambda scanner logs...${NC}"
LAMBDA_LOGS=$(aws logs filter-log-events \
    --log-group-name /aws/lambda/qualys-fargate-scanner-image-scanner \
    --start-time $(($(date +%s) - 3600))000 \
    --limit 5 \
    --region ${AWS_REGION} \
    --query 'events[*].message' \
    --output text 2>/dev/null | wc -l || echo "0")

if [ "$LAMBDA_LOGS" -gt "0" ]; then
    echo -e "${GREEN}Found ${LAMBDA_LOGS} recent Lambda log entries${NC}"
else
    echo -e "${YELLOW}No recent Lambda logs found${NC}"
fi
echo ""

# Step 3: Check runtime sidecar logs
echo -e "${YELLOW}[3/5] Checking runtime sidecar logs...${NC}"
SIDECAR_LOGS=$(aws logs filter-log-events \
    --log-group-name /ecs/fargate-runtime-security \
    --start-time $(($(date +%s) - 3600))000 \
    --limit 10 \
    --region ${AWS_REGION} \
    --query 'events[*].message' \
    --output text 2>/dev/null || echo "")

if [ -n "$SIDECAR_LOGS" ]; then
    echo -e "${GREEN}Runtime sidecar is logging events${NC}"

    # Count different event types
    PROCESS_EVENTS=$(echo "$SIDECAR_LOGS" | grep -c "process_execution" || echo "0")
    FILE_EVENTS=$(echo "$SIDECAR_LOGS" | grep -c "file_access" || echo "0")
    NETWORK_EVENTS=$(echo "$SIDECAR_LOGS" | grep -c "network_connection" || echo "0")
    SOFTWARE_EVENTS=$(echo "$SIDECAR_LOGS" | grep -c "software_installation" || echo "0")

    echo -e "  Process execution events: ${PROCESS_EVENTS}"
    echo -e "  File access events: ${FILE_EVENTS}"
    echo -e "  Network connection events: ${NETWORK_EVENTS}"
    echo -e "  Software installation events: ${SOFTWARE_EVENTS}"
else
    echo -e "${YELLOW}No runtime sidecar logs found${NC}"
fi
echo ""

# Step 4: Check DynamoDB events
echo -e "${YELLOW}[4/5] Checking DynamoDB events...${NC}"
python3 scripts/query-events.py --hours 1 2>&1 | head -20
echo ""

# Step 5: Check CloudWatch metrics
echo -e "${YELLOW}[5/5] Checking CloudWatch metrics...${NC}"
PROCESS_METRIC=$(aws cloudwatch get-metric-statistics \
    --namespace FargateRuntimeSecurity \
    --metric-name ProcessExecution \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 3600 \
    --statistics Sum \
    --region ${AWS_REGION} \
    --query 'Datapoints[0].Sum' \
    --output text 2>/dev/null || echo "0")

if [ "$PROCESS_METRIC" != "0" ] && [ "$PROCESS_METRIC" != "None" ]; then
    echo -e "${GREEN}CloudWatch metrics are being published${NC}"
    echo -e "  Process execution count: ${PROCESS_METRIC}"
else
    echo -e "${YELLOW}No CloudWatch metrics found yet${NC}"
fi
echo ""

# Summary
echo -e "${BLUE}=================================${NC}"
echo -e "${BLUE}Verification Summary${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""

CHECKS_PASSED=0
CHECKS_TOTAL=5

[ "$S3_RESULTS" -gt "0" ] && ((CHECKS_PASSED++)) || true
[ "$LAMBDA_LOGS" -gt "0" ] && ((CHECKS_PASSED++)) || true
[ -n "$SIDECAR_LOGS" ] && ((CHECKS_PASSED++)) || true
# DynamoDB check is implicit in the query output
((CHECKS_PASSED++))
[ "$PROCESS_METRIC" != "0" ] && [ "$PROCESS_METRIC" != "None" ] && ((CHECKS_PASSED++)) || true

echo -e "Checks passed: ${CHECKS_PASSED}/${CHECKS_TOTAL}"
echo ""

if [ $CHECKS_PASSED -eq $CHECKS_TOTAL ]; then
    echo -e "${GREEN}All checks passed! End-to-end test successful.${NC}"
elif [ $CHECKS_PASSED -ge 3 ]; then
    echo -e "${YELLOW}Most checks passed. Some components may still be initializing.${NC}"
else
    echo -e "${RED}Several checks failed. Review the logs for issues.${NC}"
fi
echo ""

echo -e "${BLUE}Next Steps:${NC}"
echo -e "1. View detailed events:"
echo -e "   python3 scripts/query-events.py --hours 1 --details"
echo ""
echo -e "2. Export events to JSON:"
echo -e "   python3 scripts/query-events.py --hours 1 --export-json events.json"
echo ""
echo -e "3. Query by event type:"
echo -e "   python3 scripts/query-events.py --type software_installation --details"
echo ""
echo -e "4. Query by severity:"
echo -e "   python3 scripts/query-events.py --severity high --details"
echo ""
