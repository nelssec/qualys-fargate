# Troubleshooting Guide

Common issues and solutions for Qualys Fargate Container Security Scanner.

## Image Scanner Issues

### Lambda function timing out

**Symptoms**: Lambda execution exceeds timeout, scan incomplete

**Solutions**:
- Increase Lambda memory allocation (more memory = more CPU)
- Increase timeout to maximum (900 seconds)
- Check if QScanner binary is corrupted
- Verify network connectivity to Qualys platform

```bash
# Update Lambda configuration
aws lambda update-function-configuration \
  --function-name qualys-fargate-scanner-image-scanner \
  --memory-size 4096 \
  --timeout 900
```

### EventBridge not triggering Lambda

**Symptoms**: New ECR images not being scanned

**Solutions**:
1. Verify CloudTrail is logging ECR events:
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=PutImage \
     --max-results 10
   ```

2. Check EventBridge rule is enabled:
   ```bash
   aws events describe-rule \
     --name qualys-fargate-scanner-ecr-putimage-trigger
   ```

3. Verify Lambda has EventBridge invoke permissions:
   ```bash
   aws lambda get-policy \
     --function-name qualys-fargate-scanner-image-scanner
   ```

### QScanner authentication failure

**Symptoms**: "Authentication failed" or "Invalid credentials" in logs

**Solutions**:
- Verify Qualys credentials in Secrets Manager
- Check POD identifier is correct (US1, US2, EU1, etc.)
- Ensure access token has Container Security permissions
- Token may have expired - rotate in Qualys portal

```bash
# Verify secret exists and is readable
aws secretsmanager get-secret-value \
  --secret-id qualys-fargate-scanner-qualys-credentials
```

### Images not being tagged

**Symptoms**: ECR images scanned but tags not applied

**Solutions**:
- ECR image tagging API is not available in all regions
- Check Lambda IAM role has `ecr:PutImageTagList` permission
- This is a non-critical feature - scan results still stored in S3/DynamoDB

## Runtime Sidecar Issues

### Sidecar cannot attach to application process

**Symptoms**: "Operation not permitted" or "Could not attach to PID"

**Solutions**:
1. Verify platform version is 1.4.0 or later:
   ```json
   {
     "platformVersion": "1.4.0"
   }
   ```

2. Ensure SYS_PTRACE capability is granted:
   ```json
   {
     "linuxParameters": {
       "capabilities": {
         "add": ["SYS_PTRACE"]
       }
     }
   }
   ```

3. Check if using shared PID namespace:
   ```json
   {
     "pidMode": "task"
   }
   ```

4. Verify sidecar starts AFTER application container:
   ```json
   {
     "dependsOn": [
       {
         "containerName": "application",
         "condition": "START"
       }
     ]
   }
   ```

### Sidecar not finding application process

**Symptoms**: "Could not find application PID" error

**Solutions**:
- Application container may not have started yet
- Increase sidecar startup delay in code
- Customize PID detection logic in `runtime_monitor.py`

Edit `runtime_monitor.py` to match your application:
```python
# Customize process detection
if any(app in command for app in ['your-app-name', 'custom-process']):
    return pid
```

### High CPU usage from sidecar

**Symptoms**: Task using excessive CPU, performance degradation

**Solutions**:
1. Switch to less aggressive monitoring mode:
   ```json
   {
     "name": "MONITORING_MODE",
     "value": "minimal"
   }
   ```

2. Reduce syscall trace list:
   - `minimal`: ~5% overhead
   - `balanced`: ~7% overhead (default)
   - `aggressive`: ~10-15% overhead

3. Set CPU limits for sidecar:
   ```json
   {
     "cpu": 128,
     "memory": 256
   }
   ```

### No logs appearing in CloudWatch

**Symptoms**: Sidecar running but no logs in CloudWatch

**Solutions**:
1. Verify log group exists:
   ```bash
   aws logs describe-log-groups \
     --log-group-name-prefix /ecs/fargate-runtime-security
   ```

2. Create log group if missing:
   ```bash
   aws logs create-log-group \
     --log-group-name /ecs/fargate-runtime-security
   ```

3. Check task role has CloudWatch Logs permissions:
   ```json
   {
     "Effect": "Allow",
     "Action": [
       "logs:CreateLogStream",
       "logs:PutLogEvents"
     ],
     "Resource": "arn:aws:logs:*:*:log-group:/ecs/fargate-runtime-security:*"
   }
   ```

### Alerts not being sent

**Symptoms**: Security events detected but no SNS notifications

**Solutions**:
1. Verify SNS_TOPIC_ARN environment variable is set
2. Check task role has SNS publish permissions
3. Confirm SNS topic exists and subscription is active
4. Check anomaly score threshold - may be too high

## General Issues

### Fargate platform version issues

**Symptoms**: Task fails to start with capability errors

**Solution**: Ensure using platform version 1.4.0 or later:
```bash
aws ecs describe-tasks --tasks TASK_ARN \
  --query 'tasks[0].platformVersion'
```

Update service to use correct platform version:
```bash
aws ecs update-service \
  --cluster my-cluster \
  --service my-service \
  --platform-version 1.4.0
```

### Permission denied errors

**Symptoms**: Various "Access Denied" or "Permission denied" errors

**Solutions**:
1. Check task execution role (for pulling images, secrets):
   - `ecr:GetAuthorizationToken`
   - `ecr:BatchCheckLayerAvailability`
   - `ecr:GetDownloadUrlForLayer`
   - `ecr:BatchGetImage`
   - `secretsmanager:GetSecretValue`

2. Check task role (for runtime operations):
   - `logs:PutLogEvents`
   - `logs:CreateLogStream`
   - `cloudwatch:PutMetricData`
   - `sns:Publish`

### Network connectivity issues

**Symptoms**: Cannot reach Qualys platform, timeouts

**Solutions**:
- Verify Fargate tasks have internet access via NAT Gateway or VPC endpoints
- Check security group allows outbound HTTPS (443)
- Verify VPC routing configuration
- Test connectivity from within container:
  ```bash
  curl -v https://qualysguard.qg2.apps.qualys.com
  ```

## Performance Tuning

### Optimizing image scan performance

1. **Increase Lambda resources**:
   - Memory: 2048 MB minimum, 4096 MB recommended
   - Timeout: 600-900 seconds

2. **Enable caching**:
   - Default cache TTL: 30 days
   - Cache keyed by image digest (sha256)
   - Rebuilding same image won't trigger rescan

3. **Optimize QScanner**:
   - Use `--scan-types pkg` only if secrets not needed
   - Enable local caching with `--cache-dir`

### Optimizing runtime monitoring

1. **Choose appropriate monitoring mode**:
   - Production: `balanced` or `minimal`
   - Security-critical: `aggressive`
   - Development: `minimal`

2. **Tune alert threshold**:
   - Lower threshold (50-60): More alerts, some false positives
   - Higher threshold (75-90): Fewer alerts, may miss some issues
   - Default: 75 (balanced)

3. **Resource allocation**:
   ```json
   {
     "cpu": 128,
     "memory": 256,
     "essential": false
   }
   ```

## Debugging

### Enable verbose logging

**Lambda**:
Set environment variable:
```json
{
  "LOG_LEVEL": "DEBUG"
}
```

**Sidecar**:
Modify runtime_monitor.py to enable verbose output, or run strace with more options.

### View CloudWatch Logs

```bash
# Lambda logs
aws logs tail /aws/lambda/qualys-fargate-scanner-image-scanner --follow

# Sidecar logs
aws logs tail /ecs/fargate-runtime-security --follow

# Filter for errors
aws logs tail /ecs/fargate-runtime-security --follow --filter-pattern "ERROR"
```

### Test components individually

**Test Lambda locally**:
```bash
cd image-scanner-lambda
python3 lambda_function.py
```

**Test sidecar locally**:
```bash
cd runtime-sidecar
docker build -t test-sidecar .
docker run --cap-add SYS_PTRACE test-sidecar
```

## Getting Help

If issues persist:
1. Check CloudWatch Logs for detailed error messages
2. Enable debug logging
3. Review IAM policies and permissions
4. Verify network connectivity
5. Open GitHub issue with logs and configuration

## Known Limitations

1. **Ptrace limitations on Fargate**:
   - Cannot attach to PID 1 in some cases
   - Single attachment per process
   - Platform version 1.4.0+ required

2. **eBPF not available**:
   - Fargate doesn't support eBPF
   - Use ptrace-based monitoring instead
   - Consider EC2-based ECS for eBPF support

3. **Image scanning latency**:
   - CloudTrail to EventBridge: 5-15 minutes typical
   - For faster scanning, trigger Lambda directly via API

4. **Cross-region limitations**:
   - CloudTrail events are region-specific
   - Deploy scanner in each region with ECR repositories
