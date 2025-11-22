# Runtime Security Tracing Policies

This directory contains TracingPolicy definitions for the Fargate runtime security monitor. These policies are similar to Qualys Container Runtime Sensor (CRS) Tetragon policies but designed for ptrace-based monitoring on AWS Fargate.

## Overview

Since AWS Fargate doesn't support eBPF (which Qualys CRS/Tetragon uses), we implement policy-based filtering using ptrace with a similar CRD-style configuration format.

## Policy Structure

Policies are defined in YAML format following this structure:

```yaml
apiVersion: security.qualys.com/v1
kind: TracingPolicy
metadata:
  name: policy-name

spec:
  # File Integrity Monitoring
  fileIntegrityMonitoring:
    enabled: true
    paths:
      - path: /etc/passwd
        events: [open, write]
        severity: critical

  # Process Execution Monitoring
  processExecution:
    enabled: true
    trackedExecutables:
      - name: apt
        severity: medium
        action: alert

  # Network Monitoring
  networkMonitoring:
    enabled: true
    outboundConnections:
      allowlist:
        - 10.0.0.0/8

  # Software Installation Detection
  softwareInstallation:
    enabled: true
    packageManagers:
      - name: apt
        commands: [install, upgrade]

  # System Call Filtering
  syscallFiltering:
    tracedSyscalls:
      - execve
      - open
      - connect

  # Actions
  actions:
    alert:
      enabled: true
      destinations:
        - type: qualys-crs
          enabled: true
```

## Policy Types

### 1. File Integrity Monitoring (FIM)

Monitor file system changes to detect:
- Unauthorized file modifications
- Persistence mechanisms
- Configuration tampering

**Example:**
```yaml
fileIntegrityMonitoring:
  enabled: true
  paths:
    - path: /etc
      recursive: true
      events: [open, write, unlink, chmod]
      severity: high
      action: alert
```

**Supported Events:**
- `open` - File opened for reading
- `write` - File opened for writing
- `unlink` - File deleted
- `chmod` - Permissions changed
- `chown` - Ownership changed

### 2. Process Execution Monitoring

Track process executions to detect:
- Package manager usage (new software)
- Reverse shells
- Privilege escalation attempts
- Crypto miners

**Example:**
```yaml
processExecution:
  enabled: true
  trackedExecutables:
    - name: /bin/bash
      args: ["-i", "-c"]
      severity: high
      action: alert
      captureArgs: true
```

### 3. Network Monitoring

Monitor network connections to detect:
- Connections to unauthorized IPs
- Suspicious port usage
- Data exfiltration attempts

**Example:**
```yaml
networkMonitoring:
  enabled: true
  outboundConnections:
    allowlist:
      - 10.0.0.0/8
    blockedPorts:
      - 22  # SSH
      - 3389  # RDP
```

### 4. Software Installation Detection

Detect new software being installed at runtime via:
- System package managers (apt, yum, dnf, apk)
- Language package managers (pip, npm, gem, cargo)
- Direct downloads (curl, wget)

**Example:**
```yaml
softwareInstallation:
  enabled: true
  packageManagers:
    - name: apt
      commands: [install, upgrade]
      severity: medium
```

**Supported Package Managers:**
- Debian/Ubuntu: `apt`, `apt-get`, `dpkg`
- RHEL/CentOS: `yum`, `dnf`, `rpm`
- Alpine: `apk`
- Python: `pip`, `pip3`
- Node.js: `npm`, `yarn`
- Ruby: `gem`
- Go: `go`
- Rust: `cargo`

## Deploying Policies

### Option 1: Environment Variable

Set the policy path via environment variable in your ECS task definition:

```json
{
  "environment": [
    {
      "name": "TRACING_POLICY_PATH",
      "value": "/etc/runtime-security/my-policy.yaml"
    }
  ]
}
```

### Option 2: ConfigMap (Volume Mount)

Mount policy as a volume in your task definition:

```json
{
  "mountPoints": [
    {
      "sourceVolume": "security-policy",
      "containerPath": "/etc/runtime-security"
    }
  ],
  "volumes": [
    {
      "name": "security-policy",
      "host": {
        "sourcePath": "/path/to/policy.yaml"
      }
    }
  ]
}
```

### Option 3: S3 Bucket

Store policies in S3 and download at container startup:

```dockerfile
RUN aws s3 cp s3://my-bucket/policies/production-policy.yaml /etc/runtime-security/policy.yaml
```

## Example Policies

### Minimal Monitoring
Use `examples/minimal-policy.yaml` for:
- Low overhead (~5% CPU)
- Basic security monitoring
- Production workloads

### Balanced Monitoring
Use `examples/fim-policy.yaml` + `examples/software-detection-policy.yaml` for:
- Moderate overhead (~7% CPU)
- Comprehensive monitoring
- Most production scenarios

### Aggressive Monitoring
Use `tracing-policy-schema.yaml` for:
- Higher overhead (~10-15% CPU)
- Maximum visibility
- Security-critical workloads

## Integration with Qualys CRS

The runtime monitor sends events to Qualys Container Runtime Sensor:

```yaml
actions:
  alert:
    enabled: true
    destinations:
      - type: qualys-crs
        enabled: true
        eventType: process_execution

  qualysIntegration:
    enabled: true
    endpoint: https://gateway.qg2.apps.qualys.com
    sendEvents: true
```

**Event Types Sent to Qualys:**
- `process_execution` - New processes
- `file_change` - File modifications
- `network_connection` - Network activity
- `software_installation` - Package installations

## Performance Tuning

### Sampling Rate

Reduce overhead by sampling events:

```yaml
performance:
  samplingRate: 0.5  # Monitor 50% of events
```

### Syscall Filtering

Only trace required syscalls:

```yaml
syscallFiltering:
  tracedSyscalls:
    - execve
    - open
    - connect
```

**Syscall Overhead:**
- Basic (execve, open, connect): ~5% CPU
- Extended (+chmod, chown, unlink): ~7% CPU
- Full (all syscalls): ~15% CPU

### Batch Configuration

Configure event batching to Qualys:

```yaml
performance:
  batchSize: 10
  batchTimeout: 5  # seconds
```

## Severity Levels

- `low` - Informational events
- `medium` - Potentially suspicious activity
- `high` - Likely malicious activity
- `critical` - Active security incident

## Actions

- `log` - Log event only
- `alert` - Log + send alert to SNS/Qualys
- `block` - Log + alert + terminate process (use with caution)

## Best Practices

1. **Start Minimal**: Begin with basic policies and expand based on needs
2. **Test First**: Test policies in dev/staging before production
3. **Monitor Overhead**: Track CPU usage and adjust sampling if needed
4. **Tune Allowlists**: Customize network allowlists for your environment
5. **Regular Updates**: Update threat detection patterns regularly
6. **Baseline Behavior**: Establish normal behavior baselines before alerting

## Comparison: eBPF vs Ptrace

| Feature | eBPF (EC2) | Ptrace (Fargate) |
|---------|-----------|------------------|
| Overhead | 1-2% | 5-15% |
| Kernel-level | Yes | No |
| Process attach | Not needed | Required |
| Fargate support | No | Yes |
| Complexity | High | Medium |
| Policy format | Similar CRDs | Similar CRDs |

## Troubleshooting

### High CPU Usage
- Reduce `samplingRate` to 0.3-0.5
- Limit `tracedSyscalls` to minimum set
- Switch to `minimal` monitoring mode

### Missing Events
- Check policy syntax with `yamllint`
- Verify environment variable `TRACING_POLICY_PATH`
- Review CloudWatch Logs for policy loading errors

### Not Sending to Qualys
- Verify `QUALYS_POD` and `QUALYS_ACCESS_TOKEN` env vars
- Check network connectivity to Qualys Gateway
- Review CRS client logs

## References

- [Qualys CRS Documentation](https://docs.qualys.com/en/cs/latest/)
- [Tetragon Tracing Policies](https://tetragon.io/docs/concepts/tracing-policy/)
- [AWS Fargate Platform Versions](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform_versions.html)
- [Linux ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html)
