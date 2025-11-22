#!/usr/bin/env python3
"""
Fargate Runtime Security Monitor v2
Policy-based runtime monitoring with Qualys CRS integration
Supports CRD-style tracing policies and software detection
"""

import os
import sys
import json
import time
import signal
import subprocess
import re
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

# Import our modules
from policy_engine import load_policy_from_env, PolicyEngine
from qualys_crs_client import get_crs_client, QualysCRSClient
from software_detector import SoftwareDetector

# AWS Clients
cloudwatch = boto3.client('cloudwatch')
logs_client = boto3.client('logs')
sns_client = boto3.client('sns')

# Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
LOG_GROUP_NAME = os.environ.get('LOG_GROUP_NAME', '/ecs/fargate-runtime-security')
LOG_STREAM_NAME = os.environ.get('LOG_STREAM_NAME', f'runtime-monitor-{int(time.time())}')
NAMESPACE = os.environ.get('CLOUDWATCH_NAMESPACE', 'FargateRuntimeSecurity')

# Initialize components
policy_engine: PolicyEngine = None
crs_client: QualysCRSClient = None
software_detector = SoftwareDetector()


def log_event(event_type, event_data):
    """Log event to CloudWatch Logs"""
    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'type': event_type,
        'data': event_data
    }

    print(json.dumps(log_entry))

    try:
        logs_client.put_log_events(
            logGroupName=LOG_GROUP_NAME,
            logStreamName=LOG_STREAM_NAME,
            logEvents=[
                {
                    'timestamp': int(time.time() * 1000),
                    'message': json.dumps(log_entry)
                }
            ]
        )
    except ClientError as e:
        print(f"Error sending to CloudWatch Logs: {e}", file=sys.stderr)


def send_metric(metric_name, value, unit='Count'):
    """Send custom metric to CloudWatch"""
    try:
        cloudwatch.put_metric_data(
            Namespace=NAMESPACE,
            MetricData=[
                {
                    'MetricName': metric_name,
                    'Value': value,
                    'Unit': unit,
                    'Timestamp': datetime.now()
                }
            ]
        )
    except ClientError as e:
        print(f"Error sending metric: {e}", file=sys.stderr)


def send_alert(alert_type, details):
    """Send security alert via SNS"""
    if not SNS_TOPIC_ARN:
        return

    message = {
        'alertType': alert_type,
        'timestamp': datetime.now().isoformat(),
        'taskArn': os.environ.get('ECS_TASK_ARN', 'unknown'),
        'containerName': os.environ.get('ECS_CONTAINER_NAME', 'unknown'),
        'details': details
    }

    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"Fargate Security Alert: {alert_type}",
            Message=json.dumps(message, indent=2)
        )
        log_event("Alert sent", message)
    except ClientError as e:
        print(f"Error sending alert: {e}", file=sys.stderr)


def monitor_with_strace(pid):
    """
    Monitor a process using strace based on policy configuration
    """
    global policy_engine

    # Get syscalls to trace from policy
    syscalls = policy_engine.get_traced_syscalls()
    syscalls_str = ','.join(syscalls)

    cmd = [
        'strace',
        '-f',  # Follow forks
        '-p', str(pid),
        '-e', f'trace={syscalls_str}',
        '-s', '512',  # Larger string size for better visibility
        '-v'  # Verbose
    ]

    print(f"Starting policy-based monitoring of PID {pid}")
    print(f"Tracing syscalls: {syscalls_str}")
    log_event("Monitoring started", {"pid": pid, "syscalls": syscalls})

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in iter(process.stdout.readline, ''):
            if not line:
                break

            # Only sample events based on policy
            if not policy_engine.should_sample_event():
                continue

            parse_and_enforce_policy(line.strip())

    except Exception as e:
        log_event("Monitoring error", {"error": str(e)})
        raise


def parse_and_enforce_policy(line):
    """
    Parse strace output and enforce policy rules
    """
    try:
        # Parse execve calls (process execution)
        if 'execve(' in line:
            handle_process_execution(line)

        # Parse open/openat calls (file access)
        elif 'open(' in line or 'openat(' in line:
            handle_file_access(line)

        # Parse connect calls (network connections)
        elif 'connect(' in line:
            handle_network_connection(line)

        # Parse other syscalls
        else:
            handle_generic_syscall(line)

    except Exception as e:
        print(f"Error parsing strace output: {e}", file=sys.stderr)


def handle_process_execution(line):
    """Handle process execution events with policy enforcement"""
    global policy_engine, crs_client, software_detector

    # Extract executable and arguments from strace output
    # Example: execve("/usr/bin/apt", ["apt", "install", "nginx"], ...)
    match = re.search(r'execve\("([^"]+)".*\[(.*?)\]', line)
    if not match:
        return

    executable = match.group(1)
    args_str = match.group(2)

    # Reconstruct full command
    command = f"{executable} {args_str}"

    # Check if this matches a process monitoring policy
    rule = policy_engine.should_monitor_process(executable, args_str)

    if rule:
        severity = rule.severity.value
        action = rule.action.value

        event_data = {
            'executable': executable,
            'arguments': args_str,
            'severity': severity,
            'action': action
        }

        log_event('process_execution', event_data)
        send_metric('ProcessExecution', 1)

        # Send to Qualys CRS
        if crs_client:
            crs_client.send_process_event(
                executable=executable,
                arguments=args_str,
                pid=0,  # PID extraction from strace output would require additional parsing
                severity=severity,
                action=action
            )

        # Send alert if policy requires it
        if action in ['alert', 'block']:
            send_alert('Suspicious process execution', event_data)

    # Detect software installation
    installation = software_detector.detect_installation(executable, args_str)
    if installation:
        event_data = {
            'packageManager': installation.package_manager,
            'operation': installation.operation,
            'packages': installation.packages
        }

        log_event('software_installation', event_data)
        send_metric('SoftwareInstallation', 1)

        # Send to Qualys CRS
        if crs_client:
            crs_client.send_software_installation_event(
                package_manager=installation.package_manager,
                operation=installation.operation,
                packages=installation.packages,
                severity='medium'
            )

        # Alert on new software installation
        send_alert('New software installed', event_data)

    # Detect downloads
    download = software_detector.detect_download(executable, args_str)
    if download:
        tool, filename = download
        event_data = {
            'tool': tool,
            'filename': filename,
            'command': command
        }

        log_event('file_download', event_data)
        send_metric('FileDownload', 1)

        # Alert on suspicious downloads
        if any(ext in filename for ext in ['.sh', '.py', '.rb', '.pl', '.exe']):
            send_alert('Suspicious file download', event_data)


def handle_file_access(line):
    """Handle file access events with FIM policy enforcement"""
    global policy_engine, crs_client

    # Extract filepath from strace output
    # Example: open("/etc/passwd", O_RDONLY) = 3
    # Example: openat(AT_FDCWD, "/etc/shadow", O_RDWR) = 3
    match = re.search(r'opena?t?\([^"]*"([^"]+)".*?(O_\w+)', line)
    if not match:
        return

    filepath = match.group(1)
    flags = match.group(2)

    # Determine event type from flags
    if 'WRONLY' in flags or 'RDWR' in flags or 'CREAT' in flags:
        event_type = 'write'
    else:
        event_type = 'open'

    # Check if this file should be monitored
    rule = policy_engine.should_monitor_file(filepath, event_type)

    if rule:
        severity = rule.severity.value
        action = rule.action.value

        event_data = {
            'path': filepath,
            'operation': event_type,
            'severity': severity,
            'action': action
        }

        log_event('file_access', event_data)
        send_metric('FileIntegrityEvent', 1)

        # Send to Qualys CRS
        if crs_client:
            crs_client.send_file_event(
                filepath=filepath,
                event_type=event_type,
                severity=severity,
                pid=0,
                process_name='unknown'
            )

        # Send alert if policy requires it
        if action in ['alert', 'block']:
            send_alert('File integrity violation', event_data)


def handle_network_connection(line):
    """Handle network connection events with policy enforcement"""
    global policy_engine, crs_client

    # Extract network details from strace output
    # Example: connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.168.1.1")}, 16)
    match = re.search(r'sin_port=htons\((\d+)\).*sin_addr=inet_addr\("([^"]+)"\)', line)
    if not match:
        return

    port = int(match.group(1))
    ip = match.group(2)

    # Check if connection is allowed by policy
    allowed = policy_engine.is_network_connection_allowed(ip, port)

    severity = 'low' if allowed else 'high'

    event_data = {
        'destIp': ip,
        'destPort': port,
        'allowed': allowed,
        'severity': severity
    }

    log_event('network_connection', event_data)
    send_metric('NetworkConnection', 1)

    # Send to Qualys CRS
    if crs_client:
        crs_client.send_network_event(
            dest_ip=ip,
            dest_port=port,
            protocol='tcp',
            severity=severity,
            allowed=allowed
        )

    # Alert on blocked connections
    if not allowed:
        send_alert('Blocked network connection', event_data)
        send_metric('BlockedConnection', 1)


def handle_generic_syscall(line):
    """Handle other syscalls that might be policy-relevant"""
    # Additional syscall handling can be added here
    # For example: chmod, chown, unlink, etc.
    pass


def find_application_pid():
    """Find the PID of the application container process"""
    my_pid = os.getpid()

    try:
        ps_output = subprocess.check_output(['ps', 'aux'], text=True)
        lines = ps_output.strip().split('\n')[1:]

        for line in lines:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                pid = int(parts[1])
                command = parts[10]

                if pid != my_pid and pid != 1 and 'runtime_monitor' not in command:
                    if any(app in command for app in ['node', 'python', 'java', 'ruby', 'go', 'nginx', 'apache']):
                        print(f"Found application process: PID {pid}, Command: {command}")
                        return pid

        # Fallback: return first non-system process
        for line in lines:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                pid = int(parts[1])
                if pid != my_pid and pid != 1:
                    print(f"Monitoring PID {pid}")
                    return pid

    except Exception as e:
        print(f"Error finding application PID: {e}", file=sys.stderr)

    return None


def create_log_stream():
    """Create CloudWatch log stream"""
    try:
        logs_client.create_log_stream(
            logGroupName=LOG_GROUP_NAME,
            logStreamName=LOG_STREAM_NAME
        )
    except logs_client.exceptions.ResourceAlreadyExistsException:
        pass
    except ClientError as e:
        print(f"Warning: Could not create log stream: {e}", file=sys.stderr)


def main():
    """Main entry point"""
    global policy_engine, crs_client

    print("Fargate Runtime Security Monitor v2 starting...")

    # Load tracing policy
    try:
        policy_engine = load_policy_from_env()
        print(f"✓ Policy loaded successfully")
    except Exception as e:
        print(f"Error loading policy: {e}", file=sys.stderr)
        sys.exit(1)

    # Initialize Qualys CRS client
    try:
        crs_client = get_crs_client()
        print(f"✓ Qualys CRS client initialized")
    except Exception as e:
        print(f"Warning: Could not initialize Qualys CRS client: {e}", file=sys.stderr)
        crs_client = None

    # Create CloudWatch log stream
    create_log_stream()

    # Wait for application container to start
    print("Waiting for application container to start...")
    time.sleep(10)

    # Find application process to monitor
    target_pid = find_application_pid()

    if not target_pid:
        print("ERROR: Could not find application process to monitor", file=sys.stderr)
        sys.exit(1)

    print(f"Monitoring PID {target_pid}")

    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        print("Shutting down runtime monitor...")
        if crs_client:
            crs_client.close()
        log_event("Monitor stopped", {"reason": "signal"})
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Start monitoring
    try:
        monitor_with_strace(target_pid)
    except KeyboardInterrupt:
        print("Monitoring interrupted")
    except Exception as e:
        print(f"Error during monitoring: {e}", file=sys.stderr)
        log_event("Monitor error", {"error": str(e)})
        sys.exit(1)
    finally:
        if crs_client:
            crs_client.close()


if __name__ == '__main__':
    main()
