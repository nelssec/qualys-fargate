# End-to-End Testing Guide

This guide walks through deploying and testing the complete Fargate security scanning solution with a deliberately vulnerable application.

## Overview

The end-to-end test includes:

1. **Vulnerable Test Application**: Flask app with known CVEs and hardcoded secrets
2. **Image Scanner**: Detects vulnerabilities and secrets in the container image
3. **Runtime Monitor**: Detects security events during container execution
4. **DynamoDB Storage**: Persists all security events for querying and analysis
5. **Event Triggers**: API endpoints to generate specific security events

## Architecture

```
Vulnerable App (ECR) --> Image Scanner (Lambda) --> S3 + DynamoDB
      |
      v
  Fargate Task
      |
      v
Runtime Sidecar (ptrace) --> DynamoDB Events Table
      |                 \
      v                  v
  CloudWatch            Qualys CRS API
```

## Prerequisites

- AWS CLI configured
- Docker installed
- Python 3.11+
- VPC with public subnet
- Security group allowing inbound port 8080
- Qualys POD and access token (optional)

## Step 1: Deploy Infrastructure

Deploy the DynamoDB table and vulnerable application:

```bash
# Set required variables
export AWS_REGION=us-east-1
export SUBNET_ID=subnet-xxxxxxxxx
export SECURITY_GROUP_ID=sg-xxxxxxxxx
export QUALYS_POD=US2
export QUALYS_TOKEN=your-token  # Optional

# Run deployment script
./scripts/deploy-end-to-end-test.sh
```

The script will:
- Create DynamoDB events table
- Build and push vulnerable test app to ECR (triggers image scan)
- Build and push runtime sidecar to ECR
- Create ECS cluster and task definition
- Launch Fargate task with both containers
- Output the task IP address

Expected output:
```
========================================
Deployment Complete!
========================================

Task ARN: arn:aws:ecs:us-east-1:123456789012:task/...
Task IP: http://54.123.45.67:8080
Events Table: fargate-runtime-security-events

Next Steps:
1. Trigger security events:
   curl http://54.123.45.67:8080/trigger-all
...
```

## Step 2: Verify Image Scan

Check that the image was scanned for vulnerabilities:

```bash
# Check Lambda scanner logs
aws logs tail /aws/lambda/qualys-fargate-scanner-image-scanner --follow

# Expected output:
# Received event: {"detail": {"eventName": "PutImage", ...}}
# Scanning image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/vulnerable-test-app@sha256:...
# QScanner exit code: 0
# Stored scan results in S3: s3://qualys-fargate-scanner-scan-results-123456789012/scan-results/...
```

View scan results:

```bash
# List scan results
aws s3 ls s3://qualys-fargate-scanner-scan-results-${AWS_ACCOUNT_ID}/scan-results/vulnerable-test-app/ --recursive

# Download and view latest result
aws s3 cp s3://qualys-fargate-scanner-scan-results-${AWS_ACCOUNT_ID}/scan-results/vulnerable-test-app/sha256:abc.../timestamp.json - | jq .
```

Expected vulnerabilities:
- Python Flask 2.0.0 (CVE-2023-30861)
- Requests 2.25.0 (CVE-2023-32681)
- PyYAML 5.3.1 (CVE-2020-14343)
- Jinja2 2.11.0 (CVE-2020-28493)
- Hardcoded secrets detected (API keys, passwords)

## Step 3: Trigger Runtime Security Events

Trigger all security events at once:

```bash
# Get task IP from deployment output
TASK_IP="http://54.123.45.67:8080"

# Trigger all events
./scripts/trigger-events.sh ${TASK_IP}
```

Or trigger individual events:

```bash
# Software installation
curl "${TASK_IP}/install/curl"

# File download
curl "${TASK_IP}/download/https://example.com/test.sh"

# Network connection
curl "${TASK_IP}/connect/example.com/443"

# Read sensitive file
curl "${TASK_IP}/read/etc/passwd"

# Write file
curl "${TASK_IP}/write/tmp/test.txt"

# Execute command
curl "${TASK_IP}/exec/whoami"

# Trigger all at once
curl "${TASK_IP}/trigger-all"
```

## Step 4: Monitor Runtime Events

Watch runtime security logs in real-time:

```bash
aws logs tail /ecs/fargate-runtime-security --follow
```

Expected output:
```json
{
  "timestamp": "2025-01-22T12:34:56",
  "type": "software_installation",
  "data": {
    "packageManager": "apt",
    "operation": "install",
    "packages": ["curl"]
  }
}
```

```json
{
  "timestamp": "2025-01-22T12:35:01",
  "type": "file_access",
  "data": {
    "path": "/etc/passwd",
    "operation": "read",
    "severity": "high"
  }
}
```

## Step 5: Query Events from DynamoDB

Query all recent events:

```bash
python3 scripts/query-events.py --hours 1
```

Expected output:
```
Querying events from table: fargate-runtime-security-events

Found 25 events
================================================================================

Events by Type:
  process_execution             :   10
  file_access                   :    7
  network_connection            :    5
  software_installation         :    3

Events by Severity:
  critical                      :    2
  high                          :    8
  medium                        :   12
  low                           :    3
```

Query specific event types:

```bash
# Software installations only
python3 scripts/query-events.py --type software_installation --details

# High severity events only
python3 scripts/query-events.py --severity high --details

# Events for specific task
python3 scripts/query-events.py --task arn:aws:ecs:... --details
```

Export events to JSON or CSV:

```bash
# Export to JSON
python3 scripts/query-events.py --hours 1 --export-json events.json

# Export to CSV for Excel analysis
python3 scripts/query-events.py --hours 1 --export-csv events.csv
```

## Step 6: Verify Complete System

Run the verification script:

```bash
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
./scripts/verify-end-to-end.sh arn:aws:ecs:region:account:task/cluster/task-id
```

This checks:
1. Image scan results in S3
2. Lambda scanner logs
3. Runtime sidecar logs
4. DynamoDB event count
5. CloudWatch metrics

Expected verification output:
```
=================================
Verification Summary
=================================

Checks passed: 5/5

All checks passed! End-to-end test successful.
```

## What Gets Detected

### Image Scan (Pre-deployment)
- **Vulnerabilities**: 15-20 known CVEs in Python packages
- **Secrets**: 3 hardcoded credentials (DATABASE_PASSWORD, API_KEY, AWS_SECRET_ACCESS_KEY)
- **High-risk packages**: Flask 2.0.0, Requests 2.25.0, PyYAML 5.3.1

### Runtime Events (Post-deployment)
- **Software Installations**: apt-get install commands
- **File Access**: Reading /etc/passwd, /etc/shadow, .ssh files
- **Network Connections**: Outbound HTTP/HTTPS requests
- **Process Executions**: Shell commands, package managers
- **File Downloads**: curl/wget file downloads
- **Suspicious Activity**: Reverse shell patterns, crypto miners

## Expected Event Counts

After running `curl ${TASK_IP}/trigger-all`, you should see:

- **process_execution**: 5-10 events (apt, curl, whoami, etc.)
- **file_access**: 3-5 events (/etc/passwd, /tmp writes)
- **network_connection**: 2-4 events (example.com connections)
- **software_installation**: 0-2 events (if apt succeeds)
- **file_download**: 1-2 events (curl downloads)

## Database Schema

DynamoDB table structure:

```
Primary Key: eventId (String)
Sort Key: None

Attributes:
- eventId: Unique event identifier
- timestamp: ISO8601 timestamp
- timestampEpoch: Unix timestamp (for queries)
- eventType: Type of event
- severity: low, medium, high, critical
- action: log, alert, block
- containerId: Container hostname
- taskArn: ECS task ARN
- clusterArn: ECS cluster ARN
- taskFamily: Task definition family
- eventData: Event-specific JSON data
- ttl: Auto-deletion timestamp (30 days)

Global Secondary Indexes:
- eventType-timestamp-index
- severity-timestamp-index
- taskArn-timestamp-index
```

## Query Examples

### Most common events
```bash
python3 scripts/query-events.py --hours 24 | grep "Events by Type:" -A 10
```

### Critical events only
```bash
python3 scripts/query-events.py --severity critical --details
```

### Software installations in last hour
```bash
python3 scripts/query-events.py --type software_installation --hours 1 --details
```

### All events for a specific task
```bash
python3 scripts/query-events.py --task arn:aws:ecs:us-east-1:123:task/... --details
```

### Export for analysis
```bash
# Export to JSON for programmatic analysis
python3 scripts/query-events.py --hours 24 --export-json all-events.json

# Export to CSV for spreadsheet analysis
python3 scripts/query-events.py --hours 24 --export-csv all-events.csv
```

## Cleanup

Remove all test resources:

```bash
# Stop the Fargate task
aws ecs stop-task --cluster fargate-security-test --task ${TASK_ARN}

# Delete CloudFormation stacks
aws cloudformation delete-stack --stack-name fargate-security-events-db
aws cloudformation delete-stack --stack-name qualys-fargate-scanner

# Delete ECR repositories
aws ecr delete-repository --repository-name vulnerable-test-app --force
aws ecr delete-repository --repository-name fargate-runtime-sidecar --force

# Delete log groups
aws logs delete-log-group --log-group-name /ecs/vulnerable-test-app
aws logs delete-log-group --log-group-name /ecs/fargate-runtime-security

# Delete ECS cluster
aws ecs delete-cluster --cluster fargate-security-test
```

## Troubleshooting

### Task won't start
- Check platform version is 1.4.0 or later
- Verify SYS_PTRACE capability is granted
- Check task role has DynamoDB permissions

### No events in DynamoDB
- Verify EVENTS_TABLE_NAME environment variable is set
- Check task role has dynamodb:PutItem permission
- Review sidecar logs for errors

### Image not scanned
- Verify CloudTrail is logging ECR events
- Check EventBridge rule is enabled
- Review Lambda function logs

### Sidecar can't attach to process
- Ensure SYS_PTRACE capability is added
- Check platform version >= 1.4.0
- Verify application container started first

## Advanced Usage

### Custom TracingPolicy

Deploy with a custom security policy:

```yaml
# custom-policy.yaml
apiVersion: security.qualys.com/v1
kind: TracingPolicy
spec:
  fileIntegrityMonitoring:
    enabled: true
    paths:
      - path: /app
        recursive: true
        events: [write]
        severity: high
```

Update task definition to mount custom policy and set environment variable:
```json
{
  "environment": [
    {
      "name": "TRACING_POLICY_PATH",
      "value": "/etc/security/custom-policy.yaml"
    }
  ]
}
```

### Real-time Event Streaming

Process DynamoDB events in real-time using DynamoDB Streams:

```python
import boto3

dynamodb = boto3.client('dynamodb')
streams = boto3.client('dynamodbstreams')

# Get stream ARN from table
response = dynamodb.describe_table(TableName='fargate-runtime-security-events')
stream_arn = response['Table']['LatestStreamArn']

# Process new events
for record in stream_records:
    if record['eventName'] == 'INSERT':
        event = record['dynamodb']['NewImage']
        # Process event in real-time
        print(f"New event: {event['eventType']}")
```

## Summary

This end-to-end test validates:
- Image scanning detects vulnerabilities and secrets
- Runtime monitoring captures security events
- Events are stored in DynamoDB for analysis
- All components integrate correctly
- Queries return expected results

The vulnerable test application provides a controlled environment to verify detection capabilities without deploying actual malware.
