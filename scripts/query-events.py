#!/usr/bin/env python3
"""
Query Runtime Security Events from DynamoDB
Provides various views and analysis of detected security events
"""

import sys
import os
import argparse
import json
from datetime import datetime, timedelta
from collections import Counter
import boto3
from botocore.exceptions import ClientError

# Add runtime-sidecar to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'runtime-sidecar'))
from db_writer import initialize_table, scan_recent_events, query_events_by_type, query_events_by_severity

dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ.get('EVENTS_TABLE_NAME', 'fargate-runtime-security-events')


def print_event_summary(events):
    """Print summary of events"""
    if not events:
        print("No events found")
        return

    print(f"\nFound {len(events)} events")
    print("=" * 80)

    # Count by type
    type_counts = Counter(e['eventType'] for e in events)
    print("\nEvents by Type:")
    for event_type, count in type_counts.most_common():
        print(f"  {event_type:30s}: {count:4d}")

    # Count by severity
    severity_counts = Counter(e['severity'] for e in events)
    print("\nEvents by Severity:")
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"  {severity:30s}: {count:4d}")

    # Count by action
    action_counts = Counter(e['action'] for e in events)
    print("\nEvents by Action:")
    for action, count in action_counts.most_common():
        print(f"  {action:30s}: {count:4d}")


def print_event_details(events, limit=20):
    """Print detailed event information"""
    print(f"\nRecent Events (showing {min(limit, len(events))} of {len(events)}):")
    print("=" * 80)

    for i, event in enumerate(events[:limit], 1):
        timestamp = event.get('timestamp', 'unknown')
        event_type = event.get('eventType', 'unknown')
        severity = event.get('severity', 'unknown')
        task_arn = event.get('taskArn', 'unknown')

        # Shorten task ARN for display
        task_short = task_arn.split('/')[-1] if '/' in task_arn else task_arn

        print(f"\n{i}. [{timestamp}] {event_type.upper()} (severity: {severity})")
        print(f"   Task: {task_short}")

        # Print event-specific data
        event_data = event.get('eventData', {})

        if event_type == 'process_execution':
            print(f"   Executable: {event_data.get('executable', 'unknown')}")
            print(f"   Arguments: {event_data.get('arguments', 'unknown')}")

        elif event_type == 'file_access':
            print(f"   Path: {event_data.get('path', 'unknown')}")
            print(f"   Operation: {event_data.get('operation', 'unknown')}")

        elif event_type == 'network_connection':
            print(f"   Destination: {event_data.get('destIp', 'unknown')}:{event_data.get('destPort', 'unknown')}")
            print(f"   Allowed: {event_data.get('allowed', 'unknown')}")

        elif event_type == 'software_installation':
            packages = event_data.get('packages', [])
            print(f"   Package Manager: {event_data.get('packageManager', 'unknown')}")
            print(f"   Operation: {event_data.get('operation', 'unknown')}")
            print(f"   Packages: {', '.join(packages[:5])}")


def export_to_json(events, filename):
    """Export events to JSON file"""
    with open(filename, 'w') as f:
        json.dump(events, f, indent=2, default=str)
    print(f"\nExported {len(events)} events to {filename}")


def export_to_csv(events, filename):
    """Export events to CSV file"""
    import csv

    if not events:
        print("No events to export")
        return

    with open(filename, 'w', newline='') as f:
        # Define columns
        fieldnames = ['timestamp', 'eventId', 'eventType', 'severity', 'action',
                     'taskArn', 'containerId', 'eventData']

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for event in events:
            row = {
                'timestamp': event.get('timestamp', ''),
                'eventId': event.get('eventId', ''),
                'eventType': event.get('eventType', ''),
                'severity': event.get('severity', ''),
                'action': event.get('action', ''),
                'taskArn': event.get('taskArn', ''),
                'containerId': event.get('containerId', ''),
                'eventData': json.dumps(event.get('eventData', {}))
            }
            writer.writerow(row)

    print(f"\nExported {len(events)} events to {filename}")


def query_by_task(task_arn):
    """Query events for a specific task"""
    try:
        table = dynamodb.Table(TABLE_NAME)

        response = table.query(
            IndexName='taskArn-timestamp-index',
            KeyConditionExpression='taskArn = :arn',
            ExpressionAttributeValues={
                ':arn': task_arn
            },
            ScanIndexForward=False
        )

        return response.get('Items', [])

    except ClientError as e:
        print(f"Error querying by task: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description='Query runtime security events from DynamoDB')
    parser.add_argument('--hours', type=int, default=1, help='Number of hours to look back (default: 1)')
    parser.add_argument('--type', type=str, help='Filter by event type')
    parser.add_argument('--severity', type=str, choices=['low', 'medium', 'high', 'critical'], help='Filter by severity')
    parser.add_argument('--task', type=str, help='Filter by task ARN')
    parser.add_argument('--limit', type=int, default=100, help='Maximum number of events to retrieve (default: 100)')
    parser.add_argument('--details', action='store_true', help='Show detailed event information')
    parser.add_argument('--export-json', type=str, help='Export results to JSON file')
    parser.add_argument('--export-csv', type=str, help='Export results to CSV file')
    parser.add_argument('--table', type=str, default=TABLE_NAME, help=f'DynamoDB table name (default: {TABLE_NAME})')

    args = parser.parse_args()

    # Override table name if specified
    global TABLE_NAME
    TABLE_NAME = args.table
    os.environ['EVENTS_TABLE_NAME'] = TABLE_NAME

    # Initialize table connection
    if not initialize_table():
        print(f"Error: Could not connect to DynamoDB table '{TABLE_NAME}'")
        return 1

    print(f"Querying events from table: {TABLE_NAME}")

    # Query events based on filters
    events = []

    if args.task:
        print(f"Filtering by task: {args.task}")
        events = query_by_task(args.task)

    elif args.type:
        print(f"Filtering by type: {args.type}")
        events = query_events_by_type(args.type, limit=args.limit)

    elif args.severity:
        print(f"Filtering by severity: {args.severity}")
        events = query_events_by_severity(args.severity, limit=args.limit)

    else:
        print(f"Scanning events from last {args.hours} hour(s)")
        events = scan_recent_events(hours=args.hours, limit=args.limit)

    # Print summary
    print_event_summary(events)

    # Print details if requested
    if args.details:
        print_event_details(events)

    # Export if requested
    if args.export_json:
        export_to_json(events, args.export_json)

    if args.export_csv:
        export_to_csv(events, args.export_csv)

    return 0


if __name__ == '__main__':
    sys.exit(main())
