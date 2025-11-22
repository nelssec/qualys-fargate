#!/usr/bin/env python3
"""
Fargate Runtime Security Monitor
Uses ptrace to monitor application containers for security threats
"""

import os
import sys
import json
import time
import signal
import subprocess
import re
from datetime import datetime
from collections import defaultdict, deque
import boto3
from botocore.exceptions import ClientError

# AWS Clients
cloudwatch = boto3.client('cloudwatch')
sns_client = boto3.client('sns')
logs_client = boto3.client('logs')

# Configuration from environment variables
MONITORING_MODE = os.environ.get('MONITORING_MODE', 'balanced')  # aggressive, balanced, minimal
ALERT_THRESHOLD = int(os.environ.get('ALERT_THRESHOLD', '75'))
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
LOG_GROUP_NAME = os.environ.get('LOG_GROUP_NAME', '/ecs/fargate-runtime-security')
LOG_STREAM_NAME = os.environ.get('LOG_STREAM_NAME', 'runtime-monitor')
NAMESPACE = os.environ.get('CLOUDWATCH_NAMESPACE', 'FargateRuntimeSecurity')

# Monitoring configuration based on mode
MONITORING_CONFIGS = {
    'minimal': {
        'syscalls': ['execve', 'connect', 'open', 'openat'],
        'sample_rate': 0.1,  # Monitor 10% of calls
        'alert_window': 300  # 5 minutes
    },
    'balanced': {
        'syscalls': ['execve', 'connect', 'bind', 'open', 'openat', 'unlink', 'chmod', 'chown'],
        'sample_rate': 0.5,  # Monitor 50% of calls
        'alert_window': 180  # 3 minutes
    },
    'aggressive': {
        'syscalls': ['execve', 'connect', 'bind', 'open', 'openat', 'unlink', 'chmod', 'chown',
                     'socket', 'sendto', 'recvfrom', 'write', 'read', 'clone', 'fork'],
        'sample_rate': 1.0,  # Monitor 100% of calls
        'alert_window': 60   # 1 minute
    }
}

# Security baselines and policies
SUSPICIOUS_PATTERNS = {
    'crypto_mining': [
        r'xmrig', r'minergate', r'nicehash', r'stratum\+tcp',
        r'cryptonight', r'monero'
    ],
    'reverse_shell': [
        r'/bin/bash.*-i', r'/bin/sh.*-i', r'nc.*-e\s+/bin',
        r'python.*socket.*exec', r'perl.*socket.*exec'
    ],
    'privilege_escalation': [
        r'sudo\s+-S', r'su\s+-', r'pkexec', r'doas',
        r'chmod\s+[47]777', r'chown\s+root'
    ],
    'data_exfiltration': [
        r'curl.*\|.*sh', r'wget.*\|.*sh', r'scp\s+.*@',
        r'rsync.*@', r'base64.*decode'
    ],
    'persistence': [
        r'/etc/rc\.', r'crontab', r'\.ssh/authorized_keys',
        r'/etc/passwd', r'/etc/shadow', r'systemctl.*enable'
    ]
}

# Network policy - allowed destinations (CIDR ranges)
ALLOWED_NETWORKS = os.environ.get('ALLOWED_NETWORKS', '').split(',')
BLOCKED_PORTS = [22, 23, 3389]  # SSH, Telnet, RDP typically not needed in containers

# Anomaly detection
class AnomalyDetector:
    def __init__(self, window_size=100):
        self.syscall_history = deque(maxlen=window_size)
        self.network_history = deque(maxlen=window_size)
        self.file_history = deque(maxlen=window_size)
        self.baseline_established = False
        self.baseline_syscalls = defaultdict(int)
        self.baseline_networks = set()
        self.baseline_files = set()

    def add_syscall(self, syscall_name):
        self.syscall_history.append(syscall_name)
        self.baseline_syscalls[syscall_name] += 1

        # Establish baseline after 100 calls
        if len(self.syscall_history) >= 100 and not self.baseline_established:
            self.baseline_established = True
            log_event("Baseline established", {"syscalls": len(self.baseline_syscalls)})

    def add_network_connection(self, dest_ip, dest_port):
        connection = f"{dest_ip}:{dest_port}"
        self.network_history.append(connection)
        self.baseline_networks.add(connection)

    def add_file_access(self, filepath):
        self.file_history.append(filepath)
        self.baseline_files.add(filepath)

    def calculate_anomaly_score(self, event_type, event_data):
        """Calculate anomaly score (0-100) for an event"""
        score = 0

        if event_type == 'syscall':
            syscall_name = event_data.get('name')

            # Check if syscall is unusual
            if self.baseline_established:
                total_calls = sum(self.baseline_syscalls.values())
                syscall_frequency = self.baseline_syscalls.get(syscall_name, 0) / max(total_calls, 1)

                # Rare syscalls get higher score
                if syscall_frequency < 0.01:  # Less than 1% of calls
                    score += 30

        elif event_type == 'network':
            dest = f"{event_data.get('dest_ip')}:{event_data.get('dest_port')}"

            # Check if destination is new
            if dest not in self.baseline_networks and self.baseline_established:
                score += 40

            # Check against blocked ports
            if event_data.get('dest_port') in BLOCKED_PORTS:
                score += 50

        elif event_type == 'file':
            filepath = event_data.get('path')

            # Check for sensitive file access
            if any(pattern in filepath for pattern in ['/etc/passwd', '/etc/shadow', '.ssh', '/root']):
                score += 60

        # Check for suspicious patterns
        command = event_data.get('command', '')
        for category, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    score += 70
                    log_event("Suspicious pattern detected", {
                        "category": category,
                        "pattern": pattern,
                        "command": command
                    })

        return min(score, 100)  # Cap at 100


# Global anomaly detector
detector = AnomalyDetector()


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
        # Send to CloudWatch Logs
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
            Subject=f"🚨 Fargate Security Alert: {alert_type}",
            Message=json.dumps(message, indent=2)
        )
        log_event("Alert sent", message)
    except ClientError as e:
        print(f"Error sending alert: {e}", file=sys.stderr)


def monitor_with_strace(pid):
    """
    Monitor a process using strace (ptrace wrapper)
    This provides system call tracing
    """
    config = MONITORING_CONFIGS[MONITORING_MODE]
    syscalls_to_trace = ','.join(config['syscalls'])

    cmd = [
        'strace',
        '-f',  # Follow forks
        '-p', str(pid),
        '-e', f'trace={syscalls_to_trace}',
        '-s', '256',  # String size
        '-v'  # Verbose
    ]

    print(f"Starting strace monitoring of PID {pid} in {MONITORING_MODE} mode")
    log_event("Monitoring started", {"pid": pid, "mode": MONITORING_MODE})

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

            parse_strace_output(line.strip())

    except Exception as e:
        log_event("Monitoring error", {"error": str(e)})
        raise


def parse_strace_output(line):
    """Parse strace output and detect suspicious activity"""

    # Example strace output:
    # execve("/bin/sh", ["sh", "-c", "curl attacker.com"], ...) = 0
    # connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("192.168.1.100")}, 16) = 0
    # open("/etc/passwd", O_RDONLY) = 3

    try:
        # Parse execve calls
        if 'execve(' in line:
            match = re.search(r'execve\("([^"]+)".*\[(.*?)\]', line)
            if match:
                executable = match.group(1)
                args = match.group(2)
                command = f"{executable} {args}"

                detector.add_syscall('execve')

                event_data = {
                    'name': 'execve',
                    'executable': executable,
                    'command': command
                }

                score = detector.calculate_anomaly_score('syscall', event_data)

                if score >= ALERT_THRESHOLD:
                    send_alert('Suspicious execution', event_data)

                log_event('execve', event_data)
                send_metric('SyscallCount', 1)

        # Parse connect calls (outbound network)
        elif 'connect(' in line:
            match = re.search(r'sin_port=htons\((\d+)\).*sin_addr=inet_addr\("([^"]+)"\)', line)
            if match:
                port = int(match.group(1))
                ip = match.group(2)

                detector.add_syscall('connect')
                detector.add_network_connection(ip, port)

                event_data = {
                    'name': 'connect',
                    'dest_ip': ip,
                    'dest_port': port
                }

                score = detector.calculate_anomaly_score('network', event_data)

                if score >= ALERT_THRESHOLD:
                    send_alert('Suspicious network connection', event_data)

                log_event('network_connect', event_data)
                send_metric('NetworkConnections', 1)

        # Parse open/openat calls (file access)
        elif 'open(' in line or 'openat(' in line:
            match = re.search(r'opena?t?\([^"]*"([^"]+)"', line)
            if match:
                filepath = match.group(1)

                detector.add_syscall('open')
                detector.add_file_access(filepath)

                event_data = {
                    'name': 'open',
                    'path': filepath
                }

                score = detector.calculate_anomaly_score('file', event_data)

                if score >= ALERT_THRESHOLD:
                    send_alert('Suspicious file access', event_data)

                # Only log sensitive file access to reduce noise
                if any(sensitive in filepath for sensitive in ['/etc', '/root', '.ssh', 'passwd', 'shadow']):
                    log_event('file_access', event_data)
                    send_metric('SensitiveFileAccess', 1)

    except Exception as e:
        print(f"Error parsing strace output: {e}", file=sys.stderr)


def find_application_pid():
    """
    Find the PID of the application container process to monitor
    In Fargate, we need to find the main application process (not our sidecar)
    """
    # Look for processes not owned by this script
    my_pid = os.getpid()

    try:
        # Get all processes
        ps_output = subprocess.check_output(['ps', 'aux'], text=True)
        lines = ps_output.strip().split('\n')[1:]  # Skip header

        for line in lines:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                pid = int(parts[1])
                command = parts[10]

                # Skip our own process and system processes
                if pid != my_pid and pid != 1 and 'runtime_monitor' not in command:
                    # Try to find the main application process
                    # This could be customized based on your application
                    if any(app in command for app in ['node', 'python', 'java', 'ruby', 'go', 'nginx', 'apache']):
                        print(f"Found application process: PID {pid}, Command: {command}")
                        return pid

        # If no specific application found, return first non-system process
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


def main():
    """Main entry point"""
    print(f"Fargate Runtime Security Monitor starting...")
    print(f"Monitoring mode: {MONITORING_MODE}")
    print(f"Alert threshold: {ALERT_THRESHOLD}")

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


if __name__ == '__main__':
    main()
