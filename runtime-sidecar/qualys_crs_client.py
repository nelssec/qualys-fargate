#!/usr/bin/env python3
"""
Qualys Container Runtime Sensor (CRS) API Client
Sends runtime security events to Qualys platform
"""

import os
import json
import time
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum


class EventType(Enum):
    PROCESS_EXECUTION = "process_execution"
    FILE_CHANGE = "file_change"
    NETWORK_CONNECTION = "network_connection"
    SOFTWARE_INSTALLATION = "software_installation"
    ANOMALY = "anomaly"


class QualysCRSClient:
    """
    Client for sending runtime security events to Qualys Container Runtime Sensor
    """

    def __init__(self):
        # Qualys API configuration
        self.pod = os.environ.get('QUALYS_POD', 'US2')
        self.access_token = os.environ.get('QUALYS_ACCESS_TOKEN', '')

        # Determine Qualys gateway endpoint based on POD
        self.gateway_url = self._get_gateway_url()

        # Container/Task metadata
        self.container_id = os.environ.get('HOSTNAME', 'unknown')
        self.task_arn = os.environ.get('ECS_TASK_ARN', 'unknown')
        self.cluster_arn = os.environ.get('ECS_CLUSTER_ARN', 'unknown')
        self.task_family = os.environ.get('ECS_TASK_DEFINITION_FAMILY', 'unknown')
        self.container_name = os.environ.get('ECS_CONTAINER_NAME', 'runtime-sidecar')

        # Batching configuration
        self.batch_size = int(os.environ.get('EVENT_BATCH_SIZE', '10'))
        self.batch_timeout = int(os.environ.get('EVENT_BATCH_TIMEOUT', '5'))
        self.event_queue: List[Dict] = []
        self.last_flush = time.time()

        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        })

        print(f"Qualys CRS Client initialized: POD={self.pod}, Gateway={self.gateway_url}")

    def _get_gateway_url(self) -> str:
        """Get Qualys Gateway URL based on POD"""
        pod_gateways = {
            'US1': 'https://gateway.qg1.apps.qualys.com',
            'US2': 'https://gateway.qg2.apps.qualys.com',
            'US3': 'https://gateway.qg3.apps.qualys.com',
            'US4': 'https://gateway.qg4.apps.qualys.com',
            'EU1': 'https://gateway.qg1.apps.qualys.eu',
            'EU2': 'https://gateway.qg2.apps.qualys.eu',
            'IN1': 'https://gateway.qg1.apps.qualys.in',
            'CA1': 'https://gateway.qg1.apps.qualys.ca',
            'AE1': 'https://gateway.qg1.apps.qualys.ae',
            'UK1': 'https://gateway.qg1.apps.qualys.co.uk',
        }

        return pod_gateways.get(self.pod, pod_gateways['US2'])

    def send_process_event(self, executable: str, arguments: str, pid: int,
                          severity: str, action: str):
        """Send process execution event"""
        event = {
            'eventType': EventType.PROCESS_EXECUTION.value,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'severity': severity,
            'action': action,
            'container': {
                'id': self.container_id,
                'name': self.container_name,
                'taskArn': self.task_arn,
                'clusterArn': self.cluster_arn,
                'taskFamily': self.task_family
            },
            'process': {
                'executable': executable,
                'arguments': arguments,
                'pid': pid
            }
        }

        self._queue_event(event)

    def send_file_event(self, filepath: str, event_type: str, severity: str,
                       pid: int, process_name: str):
        """Send file integrity monitoring event"""
        event = {
            'eventType': EventType.FILE_CHANGE.value,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'severity': severity,
            'container': {
                'id': self.container_id,
                'name': self.container_name,
                'taskArn': self.task_arn,
                'clusterArn': self.cluster_arn,
                'taskFamily': self.task_family
            },
            'file': {
                'path': filepath,
                'operation': event_type
            },
            'process': {
                'name': process_name,
                'pid': pid
            }
        }

        self._queue_event(event)

    def send_network_event(self, dest_ip: str, dest_port: int, protocol: str,
                          severity: str, allowed: bool):
        """Send network connection event"""
        event = {
            'eventType': EventType.NETWORK_CONNECTION.value,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'severity': severity,
            'container': {
                'id': self.container_id,
                'name': self.container_name,
                'taskArn': self.task_arn,
                'clusterArn': self.cluster_arn,
                'taskFamily': self.task_family
            },
            'network': {
                'destIp': dest_ip,
                'destPort': dest_port,
                'protocol': protocol,
                'allowed': allowed
            }
        }

        self._queue_event(event)

    def send_software_installation_event(self, package_manager: str, operation: str,
                                        packages: List[str], severity: str):
        """Send software installation event"""
        event = {
            'eventType': EventType.SOFTWARE_INSTALLATION.value,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'severity': severity,
            'container': {
                'id': self.container_id,
                'name': self.container_name,
                'taskArn': self.task_arn,
                'clusterArn': self.cluster_arn,
                'taskFamily': self.task_family
            },
            'software': {
                'packageManager': package_manager,
                'operation': operation,
                'packages': packages
            }
        }

        self._queue_event(event)

    def send_anomaly_event(self, anomaly_type: str, score: int, details: Dict):
        """Send anomaly detection event"""
        event = {
            'eventType': EventType.ANOMALY.value,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'severity': self._score_to_severity(score),
            'container': {
                'id': self.container_id,
                'name': self.container_name,
                'taskArn': self.task_arn,
                'clusterArn': self.cluster_arn,
                'taskFamily': self.task_family
            },
            'anomaly': {
                'type': anomaly_type,
                'score': score,
                'details': details
            }
        }

        self._queue_event(event)

    def _queue_event(self, event: Dict):
        """Add event to queue and flush if needed"""
        self.event_queue.append(event)

        # Flush if batch size reached or timeout exceeded
        if (len(self.event_queue) >= self.batch_size or
            time.time() - self.last_flush >= self.batch_timeout):
            self.flush()

    def flush(self):
        """Send all queued events to Qualys"""
        if not self.event_queue:
            return

        try:
            # Send events to Qualys CRS API
            response = self.session.post(
                f'{self.gateway_url}/cspm/v1/runtime/events',
                json={'events': self.event_queue},
                timeout=10
            )

            if response.status_code == 200:
                print(f"Sent {len(self.event_queue)} events to Qualys CRS")
            else:
                print(f"Error sending events to Qualys: {response.status_code} - {response.text}")

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to Qualys CRS: {e}")

        finally:
            # Clear queue regardless of success
            self.event_queue = []
            self.last_flush = time.time()

    def _score_to_severity(self, score: int) -> str:
        """Convert anomaly score to severity level"""
        if score >= 90:
            return 'critical'
        elif score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'

    def close(self):
        """Flush remaining events and close session"""
        self.flush()
        self.session.close()


# Singleton instance
_crs_client: Optional[QualysCRSClient] = None


def get_crs_client() -> QualysCRSClient:
    """Get or create Qualys CRS client singleton"""
    global _crs_client

    if _crs_client is None:
        _crs_client = QualysCRSClient()

    return _crs_client


# Example usage
if __name__ == '__main__':
    client = get_crs_client()

    # Test sending events
    client.send_process_event(
        executable='/usr/bin/apt',
        arguments='install nginx',
        pid=12345,
        severity='medium',
        action='alert'
    )

    client.send_file_event(
        filepath='/etc/passwd',
        event_type='write',
        severity='critical',
        pid=12345,
        process_name='vi'
    )

    client.send_network_event(
        dest_ip='192.168.1.100',
        dest_port=4444,
        protocol='tcp',
        severity='high',
        allowed=False
    )

    client.send_software_installation_event(
        package_manager='apt',
        operation='install',
        packages=['nginx', 'curl'],
        severity='medium'
    )

    # Flush and close
    client.close()

    print("Test events sent successfully")
