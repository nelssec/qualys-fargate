# Viewing Security Scan Results

This guide covers all the locations where security scan results are stored and how to access them.

## Results Storage Locations

### 1. Qualys Platform (Dashboard)

Both the image scanner and runtime monitor send data to Qualys:

#### Image Scan Results in Qualys

The ECR image scanner uses **Qualys QScanner**, which automatically uploads results to your Qualys account.

**To view in Qualys dashboard:**

1. Log in to Qualys at https://qualysguard.qg2.apps.qualys.com (adjust for your POD)
2. Navigate to **Container Security** > **Images**
3. Filter by registry: **AWS ECR**
4. Search for your repository: `vulnerable-test-app`

**What you'll see:**
- Image digest and tags
- Vulnerability count by severity (Critical, High, Medium, Low)
- CVE details with CVSS scores
- Software composition analysis (SCA) results
- Detected secrets and credentials
- Remediation recommendations

**API Access:**
```bash
# Get image scan results via Qualys API
curl -u "USERNAME:PASSWORD" \
  "https://qualysapi.qg2.apps.qualys.com/cspm/v1.3/images" \
  -H "Content-Type: application/json" \
  -d '{
    "filters": {
      "registry": "AWS ECR",
      "repository": "vulnerable-test-app"
    }
  }'

# Or using access token
curl -H "Authorization: Bearer ${QUALYS_ACCESS_TOKEN}" \
  "https://qualysapi.qg2.apps.qualys.com/cspm/v1.3/images"
```

#### Runtime Events in Qualys CRS

The runtime sidecar sends events to **Qualys Container Runtime Security (CRS)**.

**To view in Qualys dashboard:**

1. Log in to Qualys platform
2. Navigate to **Container Security** > **Runtime**
3. Select **Events** or **Detections**
4. Filter by:
   - Time range
   - Event type (process, file, network)
   - Severity
   - Container/Task

**What you'll see:**
- Real-time security events
- Process execution anomalies
- File integrity violations
- Network connection attempts
- Software installation events
- Policy violations

**Event Types Sent to Qualys CRS:**
```json
{
  "eventType": "process_execution",
  "container": {
    "taskArn": "arn:aws:ecs:...",
    "clusterArn": "arn:aws:ecs:..."
  },
  "process": {
    "executable": "/usr/bin/apt",
    "arguments": "install nginx"
  },
  "severity": "medium"
}
```

**Qualys CRS API Endpoint:**
```
POST https://gateway.qg2.apps.qualys.com/cspm/v1/runtime/events
Authorization: Bearer <QUALYS_ACCESS_TOKEN>
```

### 2. AWS S3 (Image Scan Results)

Image scan results are stored in S3 for long-term retention and compliance.

**Bucket Structure:**
```
s3://qualys-fargate-scanner-scan-results-{ACCOUNT_ID}/
└── scan-results/
    └── {repository-name}/
        └── {image-digest}/
            └── {timestamp}.json
```

**View Results:**
```bash
# List all scan results
aws s3 ls s3://qualys-fargate-scanner-scan-results-${AWS_ACCOUNT_ID}/scan-results/ \
  --recursive

# Download specific result
aws s3 cp s3://qualys-fargate-scanner-scan-results-${AWS_ACCOUNT_ID}/scan-results/vulnerable-test-app/sha256:abc.../20250122-120000.json - | jq .
```

**Example Output:**
```json
{
  "repository": "vulnerable-test-app",
  "imageDigest": "sha256:abc123...",
  "imageTag": "latest",
  "accountId": "123456789012",
  "region": "us-east-1",
  "scannedAt": "2025-01-22T12:00:00Z",
  "scanResults": {
    "vulnerabilityCount": 18,
    "secretCount": 3,
    "criticalCount": 5,
    "highCount": 8,
    "mediumCount": 5,
    "lowCount": 0,
    "findings": [
      {
        "type": "vulnerability",
        "id": "CVE-2023-30861",
        "severity": "high",
        "package": "flask",
        "version": "2.0.0"
      },
      {
        "type": "secret",
        "category": "AWS Access Key",
        "file": "Dockerfile",
        "line": 25
      }
    ]
  }
}
```

### 3. DynamoDB (Scan Cache & Runtime Events)

#### Image Scan Cache

**Table:** `qualys-fargate-scanner-scan-cache`

```bash
# Query recent scans
aws dynamodb scan \
  --table-name qualys-fargate-scanner-scan-cache \
  --limit 10

# Get specific image scan
aws dynamodb get-item \
  --table-name qualys-fargate-scanner-scan-cache \
  --key '{"imageDigest": {"S": "sha256:abc123..."}}' | jq .
```

#### Runtime Security Events

**Table:** `fargate-runtime-security-events`

```bash
# Query using our script (recommended)
python3 scripts/query-events.py --hours 24 --details

# Or use AWS CLI directly
aws dynamodb query \
  --table-name fargate-runtime-security-events \
  --index-name eventType-timestamp-index \
  --key-condition-expression "eventType = :type" \
  --expression-attribute-values '{":type": {"S": "software_installation"}}' \
  --scan-index-forward false \
  --limit 10
```

**Query by Severity:**
```bash
# Get all critical events
aws dynamodb query \
  --table-name fargate-runtime-security-events \
  --index-name severity-timestamp-index \
  --key-condition-expression "severity = :sev" \
  --expression-attribute-values '{":sev": {"S": "critical"}}'
```

### 4. CloudWatch Logs

All events are also logged to CloudWatch for real-time monitoring.

#### Image Scanner Logs

```bash
# Stream logs in real-time
aws logs tail /aws/lambda/qualys-fargate-scanner-image-scanner --follow

# Search for specific scans
aws logs filter-log-events \
  --log-group-name /aws/lambda/qualys-fargate-scanner-image-scanner \
  --filter-pattern "Scanning image" \
  --start-time $(($(date +%s) - 3600))000
```

#### Runtime Security Logs

```bash
# Stream runtime events
aws logs tail /ecs/fargate-runtime-security --follow

# Filter for specific event types
aws logs filter-log-events \
  --log-group-name /ecs/fargate-runtime-security \
  --filter-pattern "software_installation"

# Filter for high-severity events
aws logs filter-log-events \
  --log-group-name /ecs/fargate-runtime-security \
  --filter-pattern "\"severity\":\"high\""
```

### 5. CloudWatch Metrics

Custom metrics are published for monitoring and alerting.

```bash
# Get process execution count
aws cloudwatch get-metric-statistics \
  --namespace FargateRuntimeSecurity \
  --metric-name ProcessExecution \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum

# Get software installation count
aws cloudwatch get-metric-statistics \
  --namespace FargateRuntimeSecurity \
  --metric-name SoftwareInstallation \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Sum
```

**Available Metrics:**
- ProcessExecution
- FileIntegrityEvent
- NetworkConnection
- SoftwareInstallation
- FileDownload
- BlockedConnection

### 6. SNS Alerts (Email/SMS)

Critical findings trigger SNS notifications.

**Subscribe to alerts:**
```bash
# Get SNS topic ARN
SNS_TOPIC_ARN=$(aws cloudformation describe-stacks \
  --stack-name qualys-fargate-scanner \
  --query 'Stacks[0].Outputs[?OutputKey==`AlertTopicArn`].OutputValue' \
  --output text)

# Subscribe your email
aws sns subscribe \
  --topic-arn ${SNS_TOPIC_ARN} \
  --protocol email \
  --notification-endpoint your-email@example.com

# Confirm subscription in your email
```

**Alert Format:**
```json
{
  "alertType": "Security Alert: vulnerable-test-app:latest",
  "repository": "vulnerable-test-app",
  "imageDigest": "sha256:abc123...",
  "imageTag": "latest",
  "scannedAt": "2025-01-22T12:00:00Z",
  "summary": {
    "vulnerabilities": 18,
    "critical": 5,
    "high": 8,
    "secrets": 3
  }
}
```

## Comparison: Where to View What

| Data Type | Qualys Dashboard | AWS S3 | DynamoDB | CloudWatch | SNS |
|-----------|-----------------|---------|----------|------------|-----|
| Image vulnerabilities | Yes (Primary) | Yes | Cache only | Logs only | Alerts only |
| Runtime events | Yes (Primary) | No | Yes | Yes | Alerts only |
| Historical analysis | Yes | Yes | 30 days | 90 days | No |
| Real-time monitoring | Yes | No | No | Yes | Yes |
| Compliance reports | Yes | Export | Export | Export | No |
| API access | Yes | Yes | Yes | Yes | Yes |

## Best Practices for Viewing Results

### For Security Teams

**Daily Review:**
```bash
# Check Qualys dashboard for new vulnerabilities
# Review critical events in DynamoDB
python3 scripts/query-events.py --severity critical --hours 24 --details

# Export for reporting
python3 scripts/query-events.py --hours 24 --export-csv daily-events.csv
```

### For DevOps Teams

**Real-time Monitoring:**
```bash
# Watch runtime events as they happen
aws logs tail /ecs/fargate-runtime-security --follow

# Monitor CloudWatch dashboard
# Create CloudWatch dashboard with metrics
```

### For Compliance/Audit

**Generate Reports:**
```bash
# Export all events for audit period
python3 scripts/query-events.py --hours 720 --export-json audit-report.json

# Download scan results from S3
aws s3 sync s3://qualys-fargate-scanner-scan-results-${AWS_ACCOUNT_ID}/scan-results/ ./audit-scans/

# Export Qualys reports via dashboard or API
```

## Creating CloudWatch Dashboard

Create a visual dashboard for monitoring:

```bash
cat > dashboard.json <<'EOF'
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["FargateRuntimeSecurity", "ProcessExecution"],
          [".", "SoftwareInstallation"],
          [".", "FileIntegrityEvent"],
          [".", "NetworkConnection"]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "us-east-1",
        "title": "Security Events by Type"
      }
    },
    {
      "type": "log",
      "properties": {
        "query": "SOURCE '/ecs/fargate-runtime-security' | fields timestamp, eventType, severity | filter severity = 'critical' or severity = 'high' | sort timestamp desc | limit 20",
        "region": "us-east-1",
        "title": "High Severity Events"
      }
    }
  ]
}
EOF

aws cloudwatch put-dashboard \
  --dashboard-name FargateSecurityMonitoring \
  --dashboard-body file://dashboard.json
```

View dashboard:
```
https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=FargateSecurityMonitoring
```

## Troubleshooting: Results Not Appearing

### Qualys Dashboard Empty

**Check 1: Verify QScanner uploaded results**
```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/qualys-fargate-scanner-image-scanner \
  --filter-pattern "QScanner exit code"
```

**Check 2: Verify Qualys credentials**
```bash
aws secretsmanager get-secret-value \
  --secret-id qualys-fargate-scanner-qualys-credentials | jq -r .SecretString
```

**Check 3: Test Qualys connectivity**
```bash
curl -v -H "Authorization: Bearer ${QUALYS_ACCESS_TOKEN}" \
  https://gateway.qg2.apps.qualys.com/cspm/v1/runtime/events
```

### DynamoDB Events Missing

**Check 1: Verify table exists**
```bash
aws dynamodb describe-table \
  --table-name fargate-runtime-security-events
```

**Check 2: Check runtime sidecar logs**
```bash
aws logs filter-log-events \
  --log-group-name /ecs/fargate-runtime-security \
  --filter-pattern "DynamoDB event storage"
```

**Check 3: Verify IAM permissions**
```bash
# Task role must have dynamodb:PutItem permission
aws iam get-role-policy \
  --role-name fargateSecurityTestTaskRole \
  --policy-name DynamoDBEventsAccess
```

## Summary

**Recommended Viewing Strategy:**

1. **Qualys Dashboard**: Primary interface for security teams
   - Comprehensive vulnerability analysis
   - Runtime threat detection
   - Compliance reporting

2. **DynamoDB**: Quick queries and programmatic access
   - Fast event lookups
   - Custom analysis
   - Export capabilities

3. **CloudWatch**: Real-time monitoring and debugging
   - Live event streaming
   - Troubleshooting
   - Alerting

4. **S3**: Long-term storage and compliance
   - Audit trails
   - Historical analysis
   - Regulatory requirements

5. **SNS**: Immediate alerting
   - Critical findings
   - Email/SMS notifications
   - Integration with ticketing systems
