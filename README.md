# Qualys Fargate Container Security Scanner

Automated security scanning for ECS Fargate containers using Qualys technology. This solution provides comprehensive protection through:

1. **Image Scanning**: Event-driven scanning of ECR container images when pushed
2. **Runtime Security**: Ptrace-based sidecar monitoring for active Fargate tasks

## Architecture

### Image Scanning Flow
```
ECR PutImage → CloudTrail → EventBridge → Scanner Lambda → QScanner → Results (S3/DynamoDB/SNS)
```

### Runtime Security Flow
```
ECS Task Launch → Runtime Sidecar (ptrace) → Monitors syscalls/files/network → Alerts (CloudWatch/SNS)
```

## Features

### Image Scanner
- Automatic scanning of new ECR images
- Package vulnerability detection (SCA)
- Secret/credential detection
- Results caching by image digest
- Tagging of scanned images
- ~5-15 minute event latency

### Runtime Sidecar
- System call monitoring via ptrace
- File access auditing
- Network connection tracking
- Process execution monitoring
- Anomaly detection
- Real-time alerting

## Components

- `image-scanner-lambda/` - Lambda function for ECR image scanning
- `runtime-sidecar/` - Ptrace-based runtime security container
- `cloudformation/` - Infrastructure as Code templates
- `terraform/` - Terraform modules (alternative to CloudFormation)
- `examples/` - Sample ECS task definitions with security sidecar

## Prerequisites

- AWS Account with ECR, ECS Fargate, Lambda permissions
- Qualys subscription with Container Security
- Qualys POD identifier and API token
- Fargate platform version 1.4.0+ (for SYS_PTRACE support)

## Quick Start

### Deploy Image Scanner

```bash
# Set required variables
export QUALYS_POD=US2
export QUALYS_TOKEN=your-token-here
export AWS_REGION=us-east-1

# Deploy infrastructure
make deploy-image-scanner
```

### Deploy Runtime Sidecar

```bash
# Build and push sidecar image
make build-runtime-sidecar
make push-runtime-sidecar

# Update your ECS task definitions to include the sidecar
# See examples/task-definition-with-sidecar.json
```

## Configuration

### Image Scanner Configuration
- **QUALYS_POD**: Your Qualys platform POD (US1, US2, EU1, etc.)
- **SCAN_TYPES**: Comma-separated scan types (pkg,secret)
- **CACHE_TTL_DAYS**: DynamoDB cache retention (default: 30)
- **SNS_TOPIC_ARN**: SNS topic for alerts

### Runtime Sidecar Configuration
- **MONITORING_MODE**: aggressive, balanced, minimal
- **ALERT_THRESHOLD**: Anomaly score threshold for alerts
- **SYSCALL_WHITELIST**: Allowed system calls
- **NETWORK_POLICY**: Allowed network destinations

## Security Features

### Image Scanner
- Credentials stored in AWS Secrets Manager
- Least privilege IAM policies
- Input validation and sanitization
- Encrypted S3 storage
- VPC endpoint support

### Runtime Sidecar
- Read-only root filesystem
- Minimal attack surface
- Isolated PID namespace
- Secure inter-container communication
- Encrypted CloudWatch logs

## Deployment Architectures

### Single Account
Deploy scanner and sidecar in a single AWS account.

### Multi-Account (Hub-Spoke)
- Hub account: Centralized scanner and results storage
- Spoke accounts: ECR repositories and Fargate tasks
- Cross-account IAM roles for scanning

## Limitations

### SYS_PTRACE on Fargate
- Available on platform version 1.4.0+
- Single process attachment per ptrace instance
- Cannot attach to PID 1 in some configurations
- Performance overhead: ~5-10% CPU

### eBPF Alternative
For more advanced monitoring, consider EC2-based ECS with eBPF support (not available on Fargate).

## Cost Optimization

- Image caching prevents duplicate scans
- Configurable Lambda memory/timeout
- On-demand scanning (no continuous polling)
- Sidecar resource limits

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues and solutions.

## License

MIT

## Support

For issues or questions, please open a GitHub issue.
