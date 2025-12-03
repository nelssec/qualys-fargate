# Qualys ECR Image Scanner

Automated security scanning for Amazon ECR container images using Qualys QScanner. This solution provides event-driven vulnerability and secret detection for container images when they are pushed to ECR.

## Architecture

```
ECR PutImage --> CloudTrail --> EventBridge --> Lambda --> QScanner --> Results
                                                              |
                                          +-------------------+-------------------+
                                          |                   |                   |
                                        S3              DynamoDB              SNS
                                    (Results)           (Cache)            (Alerts)
```

## Features

- **Automatic Scanning**: Triggers on ECR PutImage events via CloudTrail and EventBridge
- **Vulnerability Detection**: Package vulnerability scanning (SCA) using Qualys QScanner
- **Secret Detection**: Identifies hardcoded credentials and secrets in images
- **Results Caching**: DynamoDB-based caching by image digest to prevent duplicate scans
- **Image Tagging**: Automatically tags scanned ECR images with scan metadata
- **Security Alerts**: SNS notifications for critical/high severity findings
- **Secure by Design**: Least privilege IAM, encrypted storage, input validation

## Prerequisites

- AWS Account with appropriate permissions
- Qualys subscription with Container Security module
- Qualys POD identifier (e.g., US1, US2, EU1)
- Qualys API access token

## Quick Start

### 1. Configure Credentials

```bash
# Set environment variables
export QUALYS_POD=US2
export QUALYS_ACCESS_TOKEN=your-qualys-api-token
export AWS_REGION=us-east-1
```

Or store the token in AWS Secrets Manager:
```bash
aws secretsmanager create-secret \
  --name qualys-token \
  --secret-string "your-qualys-api-token"
```

### 2. Download QScanner

Download the QScanner binary from your Qualys portal and place it in the build directory:
```bash
mkdir -p build/layer/bin
# Copy your QScanner binary to build/layer/bin/qscanner
chmod +x build/layer/bin/qscanner
```

### 3. Deploy

```bash
make deploy
```

### 4. Verify

Push an image to any ECR repository in your account and check:
```bash
# View Lambda logs
make logs

# Check stack status
make status
```

## Configuration

### CloudFormation Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `QualysPod` | Qualys platform POD (US1, US2, EU1, etc.) | US2 |
| `QualysAccessToken` | Qualys API access token | - |
| `ScanTypes` | Scan types (pkg, secret) | pkg,secret |
| `CacheTTLDays` | Cache retention in days | 30 |
| `LambdaMemorySize` | Lambda memory (MB) | 2048 |
| `LambdaTimeout` | Lambda timeout (seconds) | 900 |
| `EnableAlerts` | Enable SNS alerts | true |
| `AlertEmail` | Email for alerts (optional) | - |

### Make Targets

```bash
make help              # Show all targets
make deploy            # Deploy the scanner stack
make update            # Update Lambda code only
make logs              # Tail Lambda logs
make status            # Show stack status
make validate          # Validate CloudFormation
make verify            # Verify Qualys integration
make clean             # Clean build artifacts
make destroy           # Delete the stack
```

## Scan Results

### S3 Storage
Results are stored in S3 at:
```
s3://{stack-name}-scan-results-{account-id}/scan-results/{repo}/{digest}/{timestamp}.json
```

### ECR Image Tags
Scanned images are tagged with:
- `qualys:scanned` = true
- `qualys:scan-date` = YYYY-MM-DD
- `qualys:vulnerabilities` = count
- `qualys:critical` = count

### SNS Alerts
Alerts are sent when:
- Critical vulnerabilities found
- High severity vulnerabilities found
- Secrets/credentials detected

## Security Features

- **Credentials**: Stored in AWS Secrets Manager, never logged
- **IAM**: Least privilege policies scoped to specific resources
- **Encryption**: S3 server-side encryption (AES-256)
- **Transport**: HTTPS enforced on all S3 buckets
- **Input Validation**: All inputs validated before processing
- **Error Handling**: Generic error messages to clients, detailed logs internally
- **Audit**: CloudTrail logging for all ECR API calls

## Directory Structure

```
.
├── cloudformation/
│   └── image-scanner.yaml    # CloudFormation template
├── image-scanner-lambda/
│   ├── lambda_function.py    # Lambda handler
│   └── requirements.txt      # Python dependencies
├── scripts/
│   └── verify-qualys-integration.sh
├── Makefile                  # Build and deploy automation
└── README.md
```

## Troubleshooting

### Lambda Not Triggering
- Verify CloudTrail is enabled and logging ECR events
- Check EventBridge rule is enabled
- Ensure Lambda has correct permissions

### Scan Failures
- Check Lambda logs: `make logs`
- Verify Qualys credentials in Secrets Manager
- Ensure QScanner binary is properly installed in Lambda layer

### Permission Errors
- Verify IAM role has required permissions
- Check resource policies on S3 buckets
- Ensure cross-account access is configured (if applicable)

## Cost Considerations

- Lambda execution: ~5-15 minutes per scan
- S3 storage: Results retained for 90 days (configurable)
- DynamoDB: On-demand pricing, minimal usage
- CloudTrail: Included if already enabled
- SNS: Standard pricing for notifications

## License

MIT
