#!/usr/bin/env python3
"""
Policy Engine for Runtime Security Monitoring
Parses and enforces TracingPolicy definitions (similar to Qualys CRS/Tetragon)
"""

import os
import yaml
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(Enum):
    LOG = "log"
    ALERT = "alert"
    BLOCK = "block"


@dataclass
class FileMonitorRule:
    path: str
    recursive: bool
    events: List[str]
    severity: Severity
    action: Action = Action.ALERT

    def matches_path(self, filepath: str) -> bool:
        """Check if filepath matches this rule"""
        # Handle wildcard patterns
        if '*' in self.path:
            pattern = self.path.replace('*', '.*')
            return bool(re.match(pattern, filepath))

        # Exact match
        if filepath == self.path:
            return True

        # Recursive match
        if self.recursive and filepath.startswith(self.path + '/'):
            return True

        return False

    def matches_event(self, event_type: str) -> bool:
        """Check if event type should be monitored"""
        return event_type in self.events


@dataclass
class ProcessMonitorRule:
    name: str
    args: Optional[List[str]]
    severity: Severity
    action: Action
    capture_args: bool = False

    def matches_execution(self, executable: str, arguments: str) -> bool:
        """Check if process execution matches this rule"""
        # Check executable name
        if not executable.endswith(self.name) and self.name not in executable:
            return False

        # If specific args are required, check them
        if self.args:
            return any(arg in arguments for arg in self.args)

        return True


@dataclass
class NetworkRule:
    allowed_cidrs: List[str]
    blocked_ips: List[str]
    blocked_ports: List[int]
    allowed_ports: List[int]

    def is_allowed_connection(self, dest_ip: str, dest_port: int) -> bool:
        """Check if network connection is allowed"""
        # Check blocked IPs
        if dest_ip in self.blocked_ips:
            return False

        # Check blocked ports
        if dest_port in self.blocked_ports:
            return False

        # Check CIDR allowlist
        if self.allowed_cidrs:
            return self._ip_in_cidrs(dest_ip, self.allowed_cidrs)

        return True

    def _ip_in_cidrs(self, ip: str, cidrs: List[str]) -> bool:
        """Check if IP is in any of the CIDR ranges"""
        try:
            from ipaddress import ip_address, ip_network

            ip_obj = ip_address(ip)
            for cidr in cidrs:
                if ip_obj in ip_network(cidr):
                    return True
        except Exception:
            pass

        return False


@dataclass
class PackageManagerRule:
    name: str
    commands: List[str]
    severity: Severity


class PolicyEngine:
    """
    Policy engine that loads and enforces TracingPolicy definitions
    Similar to Qualys CRS Tetragon policies
    """

    def __init__(self, policy_path: str):
        self.policy_path = policy_path
        self.policy = None
        self.file_rules: List[FileMonitorRule] = []
        self.process_rules: List[ProcessMonitorRule] = []
        self.network_rule: Optional[NetworkRule] = None
        self.package_manager_rules: List[PackageManagerRule] = []
        self.traced_syscalls: List[str] = []
        self.sampling_rate: float = 1.0

        self.load_policy()

    def load_policy(self):
        """Load and parse policy YAML file"""
        try:
            with open(self.policy_path, 'r') as f:
                self.policy = yaml.safe_load(f)

            spec = self.policy.get('spec', {})

            # Load FIM rules
            self._load_fim_rules(spec)

            # Load process execution rules
            self._load_process_rules(spec)

            # Load network rules
            self._load_network_rules(spec)

            # Load software installation rules
            self._load_software_rules(spec)

            # Load syscall filtering
            self._load_syscall_rules(spec)

            # Load performance settings
            self._load_performance_settings(spec)

            print(f"Policy loaded: {self.policy.get('metadata', {}).get('name', 'unknown')}")
            print(f"  File rules: {len(self.file_rules)}")
            print(f"  Process rules: {len(self.process_rules)}")
            print(f"  Package manager rules: {len(self.package_manager_rules)}")
            print(f"  Traced syscalls: {len(self.traced_syscalls)}")

        except Exception as e:
            print(f"Error loading policy: {e}")
            # Use empty policy
            self.policy = {}

    def _load_fim_rules(self, spec: Dict):
        """Load File Integrity Monitoring rules"""
        fim = spec.get('fileIntegrityMonitoring', {})
        if not fim.get('enabled', False):
            return

        for path_spec in fim.get('paths', []):
            try:
                rule = FileMonitorRule(
                    path=path_spec['path'],
                    recursive=path_spec.get('recursive', False),
                    events=path_spec.get('events', ['open', 'write']),
                    severity=Severity(path_spec.get('severity', 'medium')),
                    action=Action(path_spec.get('action', 'alert'))
                )
                self.file_rules.append(rule)
            except Exception as e:
                print(f"Error loading FIM rule: {e}")

    def _load_process_rules(self, spec: Dict):
        """Load process execution monitoring rules"""
        proc_exec = spec.get('processExecution', {})
        if not proc_exec.get('enabled', False):
            return

        for proc_spec in proc_exec.get('trackedExecutables', []):
            try:
                rule = ProcessMonitorRule(
                    name=proc_spec['name'],
                    args=proc_spec.get('args'),
                    severity=Severity(proc_spec.get('severity', 'medium')),
                    action=Action(proc_spec.get('action', 'alert')),
                    capture_args=proc_spec.get('captureArgs', False)
                )
                self.process_rules.append(rule)
            except Exception as e:
                print(f"Error loading process rule: {e}")

    def _load_network_rules(self, spec: Dict):
        """Load network monitoring rules"""
        net_mon = spec.get('networkMonitoring', {})
        if not net_mon.get('enabled', False):
            return

        outbound = net_mon.get('outboundConnections', {})
        inbound = net_mon.get('inboundConnections', {})

        try:
            self.network_rule = NetworkRule(
                allowed_cidrs=outbound.get('allowlist', []),
                blocked_ips=outbound.get('blockedIPs', []),
                blocked_ports=outbound.get('blockedPorts', []),
                allowed_ports=inbound.get('allowedPorts', [])
            )
        except Exception as e:
            print(f"Error loading network rule: {e}")

    def _load_software_rules(self, spec: Dict):
        """Load software installation detection rules"""
        sw_install = spec.get('softwareInstallation', {})
        if not sw_install.get('enabled', False):
            return

        for pkg_spec in sw_install.get('packageManagers', []):
            try:
                rule = PackageManagerRule(
                    name=pkg_spec['name'],
                    commands=pkg_spec.get('commands', []),
                    severity=Severity(pkg_spec.get('severity', 'medium'))
                )
                self.package_manager_rules.append(rule)
            except Exception as e:
                print(f"Error loading package manager rule: {e}")

    def _load_syscall_rules(self, spec: Dict):
        """Load syscall filtering configuration"""
        syscall_filter = spec.get('syscallFiltering', {})
        self.traced_syscalls = syscall_filter.get('tracedSyscalls', [
            'execve', 'open', 'openat', 'connect', 'bind'
        ])

    def _load_performance_settings(self, spec: Dict):
        """Load performance tuning settings"""
        perf = spec.get('performance', {})
        self.sampling_rate = perf.get('samplingRate', 1.0)

    def should_monitor_file(self, filepath: str, event_type: str) -> Optional[FileMonitorRule]:
        """Check if file should be monitored based on policy"""
        for rule in self.file_rules:
            if rule.matches_path(filepath) and rule.matches_event(event_type):
                return rule
        return None

    def should_monitor_process(self, executable: str, arguments: str) -> Optional[ProcessMonitorRule]:
        """Check if process execution should be monitored"""
        for rule in self.process_rules:
            if rule.matches_execution(executable, arguments):
                return rule
        return None

    def is_network_connection_allowed(self, dest_ip: str, dest_port: int) -> bool:
        """Check if network connection is allowed by policy"""
        if not self.network_rule:
            return True  # No policy = allow all

        return self.network_rule.is_allowed_connection(dest_ip, dest_port)

    def is_package_manager(self, executable: str, arguments: str) -> Optional[PackageManagerRule]:
        """Check if execution is a package manager operation"""
        for rule in self.package_manager_rules:
            if executable.endswith(rule.name) or rule.name in executable:
                # Check if it's an installation/removal command
                if any(cmd in arguments for cmd in rule.commands):
                    return rule
        return None

    def get_traced_syscalls(self) -> List[str]:
        """Get list of syscalls to trace"""
        return self.traced_syscalls

    def should_sample_event(self) -> bool:
        """Determine if event should be sampled based on sampling rate"""
        import random
        return random.random() < self.sampling_rate

    def get_action_config(self) -> Dict[str, Any]:
        """Get action configuration from policy"""
        return self.policy.get('spec', {}).get('actions', {})


def load_policy_from_env() -> PolicyEngine:
    """
    Load policy from environment variable or default location
    """
    policy_path = os.environ.get(
        'TRACING_POLICY_PATH',
        '/etc/runtime-security/policy.yaml'
    )

    # If file doesn't exist, use default policy
    if not os.path.exists(policy_path):
        policy_path = os.path.join(
            os.path.dirname(__file__),
            'policies/tracing-policy-schema.yaml'
        )

    return PolicyEngine(policy_path)


# Example usage
if __name__ == '__main__':
    engine = PolicyEngine('policies/tracing-policy-schema.yaml')

    # Test FIM
    print("\nTesting FIM rules:")
    rule = engine.should_monitor_file('/etc/passwd', 'write')
    if rule:
        print(f"  /etc/passwd write: {rule.severity.value} - {rule.action.value}")

    # Test process monitoring
    print("\nTesting process rules:")
    rule = engine.should_monitor_process('/usr/bin/apt', 'install nginx')
    if rule:
        print(f"  apt install: {rule.severity.value} - {rule.action.value}")

    # Test package manager detection
    print("\nTesting package manager detection:")
    rule = engine.is_package_manager('/usr/bin/apt-get', 'install nginx')
    if rule:
        print(f"  apt-get install: {rule.severity.value}")

    # Test network connection
    print("\nTesting network rules:")
    allowed = engine.is_network_connection_allowed('10.0.1.50', 443)
    print(f"  10.0.1.50:443 allowed: {allowed}")

    print(f"\nTraced syscalls: {', '.join(engine.get_traced_syscalls()[:10])}...")
