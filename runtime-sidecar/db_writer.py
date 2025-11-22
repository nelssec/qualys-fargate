#!/usr/bin/env python3
"""
DynamoDB Event Writer
Stores runtime security events in DynamoDB for querying and analysis
"""

import os
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

# DynamoDB client
dynamodb = boto3.resource('dynamodb')

# Configuration
EVENTS_TABLE_NAME = os.environ.get('EVENTS_TABLE_NAME', 'fargate-runtime-security-events')
BATCH_SIZE = int(os.environ.get('DB_BATCH_SIZE', '25'))

# Event table
events_table = None


def initialize_table():
    """Initialize DynamoDB table connection"""
    global events_table

    try:
        events_table = dynamodb.Table(EVENTS_TABLE_NAME)
        # Verify table exists
        events_table.load()
        print(f"Connected to DynamoDB table: {EVENTS_TABLE_NAME}")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Warning: DynamoDB table {EVENTS_TABLE_NAME} not found")
            print("Events will not be persisted to database")
        else:
            print(f"Error connecting to DynamoDB: {e}")
        return False


def write_event(event_type: str, event_data: Dict[str, Any],
                severity: str = 'medium', action: str = 'log') -> bool:
    """
    Write a single event to DynamoDB

    Args:
        event_type: Type of event (file_access, process_execution, etc.)
        event_data: Event-specific data
        severity: Severity level (low, medium, high, critical)
        action: Action taken (log, alert, block)

    Returns:
        True if successful, False otherwise
    """
    if not events_table:
        return False

    try:
        # Generate event ID and timestamp
        timestamp = datetime.utcnow()
        timestamp_str = timestamp.isoformat() + 'Z'
        timestamp_epoch = int(timestamp.timestamp())

        # Create unique event ID: timestamp_type_random
        import uuid
        event_id = f"{timestamp_epoch}_{event_type}_{str(uuid.uuid4())[:8]}"

        # Get container/task metadata
        container_id = os.environ.get('HOSTNAME', 'unknown')
        task_arn = os.environ.get('ECS_TASK_ARN', 'unknown')
        cluster_arn = os.environ.get('ECS_CLUSTER_ARN', 'unknown')
        task_family = os.environ.get('ECS_TASK_DEFINITION_FAMILY', 'unknown')

        # Build item
        item = {
            'eventId': event_id,
            'timestamp': timestamp_str,
            'timestampEpoch': timestamp_epoch,
            'eventType': event_type,
            'severity': severity,
            'action': action,
            'containerId': container_id,
            'taskArn': task_arn,
            'clusterArn': cluster_arn,
            'taskFamily': task_family,
            'eventData': event_data,
            'ttl': timestamp_epoch + (30 * 24 * 60 * 60)  # 30 days TTL
        }

        # Write to DynamoDB
        events_table.put_item(Item=item)

        return True

    except ClientError as e:
        print(f"Error writing event to DynamoDB: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error writing to DynamoDB: {e}")
        return False


def write_batch_events(events: list) -> int:
    """
    Write multiple events to DynamoDB in batch

    Args:
        events: List of event dictionaries with keys:
                - event_type
                - event_data
                - severity
                - action

    Returns:
        Number of successfully written events
    """
    if not events_table or not events:
        return 0

    success_count = 0

    try:
        # Process in batches of 25 (DynamoDB limit)
        for i in range(0, len(events), BATCH_SIZE):
            batch = events[i:i + BATCH_SIZE]

            with events_table.batch_writer() as batch_writer:
                for event in batch:
                    # Generate item
                    timestamp = datetime.utcnow()
                    timestamp_str = timestamp.isoformat() + 'Z'
                    timestamp_epoch = int(timestamp.timestamp())

                    import uuid
                    event_id = f"{timestamp_epoch}_{event['event_type']}_{str(uuid.uuid4())[:8]}"

                    container_id = os.environ.get('HOSTNAME', 'unknown')
                    task_arn = os.environ.get('ECS_TASK_ARN', 'unknown')
                    cluster_arn = os.environ.get('ECS_CLUSTER_ARN', 'unknown')
                    task_family = os.environ.get('ECS_TASK_DEFINITION_FAMILY', 'unknown')

                    item = {
                        'eventId': event_id,
                        'timestamp': timestamp_str,
                        'timestampEpoch': timestamp_epoch,
                        'eventType': event['event_type'],
                        'severity': event.get('severity', 'medium'),
                        'action': event.get('action', 'log'),
                        'containerId': container_id,
                        'taskArn': task_arn,
                        'clusterArn': cluster_arn,
                        'taskFamily': task_family,
                        'eventData': event['event_data'],
                        'ttl': timestamp_epoch + (30 * 24 * 60 * 60)
                    }

                    batch_writer.put_item(Item=item)
                    success_count += 1

        return success_count

    except ClientError as e:
        print(f"Error writing batch to DynamoDB: {e}")
        return success_count
    except Exception as e:
        print(f"Unexpected error in batch write: {e}")
        return success_count


def query_events_by_type(event_type: str, limit: int = 100) -> list:
    """
    Query events by type

    Args:
        event_type: Type of event to query
        limit: Maximum number of events to return

    Returns:
        List of events
    """
    if not events_table:
        return []

    try:
        response = events_table.query(
            IndexName='eventType-timestamp-index',
            KeyConditionExpression='eventType = :type',
            ExpressionAttributeValues={
                ':type': event_type
            },
            Limit=limit,
            ScanIndexForward=False  # Most recent first
        )

        return response.get('Items', [])

    except ClientError as e:
        print(f"Error querying events: {e}")
        return []


def query_events_by_severity(severity: str, limit: int = 100) -> list:
    """
    Query events by severity

    Args:
        severity: Severity level (low, medium, high, critical)
        limit: Maximum number of events to return

    Returns:
        List of events
    """
    if not events_table:
        return []

    try:
        response = events_table.query(
            IndexName='severity-timestamp-index',
            KeyConditionExpression='severity = :sev',
            ExpressionAttributeValues={
                ':sev': severity
            },
            Limit=limit,
            ScanIndexForward=False
        )

        return response.get('Items', [])

    except ClientError as e:
        print(f"Error querying events: {e}")
        return []


def scan_recent_events(hours: int = 1, limit: int = 100) -> list:
    """
    Scan for events in the last N hours

    Args:
        hours: Number of hours to look back
        limit: Maximum number of events to return

    Returns:
        List of events
    """
    if not events_table:
        return []

    try:
        # Calculate timestamp cutoff
        cutoff_epoch = int(time.time()) - (hours * 3600)

        response = events_table.scan(
            FilterExpression='timestampEpoch > :cutoff',
            ExpressionAttributeValues={
                ':cutoff': cutoff_epoch
            },
            Limit=limit
        )

        items = response.get('Items', [])

        # Sort by timestamp (most recent first)
        items.sort(key=lambda x: x.get('timestampEpoch', 0), reverse=True)

        return items

    except ClientError as e:
        print(f"Error scanning events: {e}")
        return []


# Example usage
if __name__ == '__main__':
    # Initialize table
    initialize_table()

    # Test writing an event
    print("\nTesting event write...")
    success = write_event(
        event_type='process_execution',
        event_data={
            'executable': '/usr/bin/apt',
            'arguments': 'install nginx',
            'pid': 12345
        },
        severity='medium',
        action='alert'
    )
    print(f"Write result: {'Success' if success else 'Failed'}")

    # Test batch write
    print("\nTesting batch write...")
    test_events = [
        {
            'event_type': 'file_access',
            'event_data': {'path': '/etc/passwd', 'operation': 'read'},
            'severity': 'high',
            'action': 'alert'
        },
        {
            'event_type': 'network_connection',
            'event_data': {'dest_ip': '192.168.1.100', 'dest_port': 443},
            'severity': 'low',
            'action': 'log'
        }
    ]
    count = write_batch_events(test_events)
    print(f"Wrote {count} events")

    # Test querying
    print("\nQuerying recent events...")
    time.sleep(2)  # Wait for consistency
    recent = scan_recent_events(hours=1, limit=10)
    print(f"Found {len(recent)} recent events")
    for event in recent[:3]:
        print(f"  - {event['eventType']} at {event['timestamp']} (severity: {event['severity']})")
