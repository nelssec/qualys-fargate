"""
ECR Image Scanner Lambda Function
Scans container images in ECR using Qualys QScanner when images are pushed.
Triggered by EventBridge rules monitoring ECR PutImage API calls.
"""

import json
import os
import subprocess
import boto3
import hashlib
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# AWS Clients
ecr_client = boto3.client('ecr')
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
sns_client = boto3.client('sns')
secretsmanager = boto3.client('secretsmanager')

# Environment Variables
QUALYS_SECRET_ARN = os.environ['QUALYS_SECRET_ARN']
RESULTS_BUCKET = os.environ['RESULTS_BUCKET']
CACHE_TABLE_NAME = os.environ['CACHE_TABLE_NAME']
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
SCAN_TYPES = os.environ.get('SCAN_TYPES', 'pkg,secret')
CACHE_TTL_DAYS = int(os.environ.get('CACHE_TTL_DAYS', '30'))

# DynamoDB Table
cache_table = dynamodb.Table(CACHE_TABLE_NAME)

# QScanner paths
QSCANNER_PATH = '/opt/bin/qscanner'
OUTPUT_DIR = '/tmp/qscanner-output'
CACHE_DIR = '/tmp/qscanner-cache'


def lambda_handler(event, context):
    """
    Main Lambda handler for ECR image scanning

    Event format from EventBridge:
    {
        "detail": {
            "eventName": "PutImage",
            "requestParameters": {
                "repositoryName": "my-app",
                "imageManifest": {...},
                "imageTag": "latest"
            },
            "responseElements": {
                "image": {
                    "imageId": {
                        "imageDigest": "sha256:...",
                        "imageTag": "latest"
                    }
                }
            }
        }
    }
    """
    try:
        print(f"Received event: {json.dumps(event)}")

        # Extract image information from event
        detail = event.get('detail', {})
        request_params = detail.get('requestParameters', {})
        response_elements = detail.get('responseElements', {})

        repository_name = request_params.get('repositoryName')
        image_info = response_elements.get('image', {}).get('imageId', {})
        image_digest = image_info.get('imageDigest')
        image_tag = image_info.get('imageTag', 'untagged')

        if not repository_name or not image_digest:
            raise ValueError("Missing repository name or image digest in event")

        # Check cache to avoid duplicate scans
        if is_scan_cached(image_digest):
            print(f"Scan results for {image_digest} found in cache, skipping scan")
            return {
                'statusCode': 200,
                'body': json.dumps({'status': 'cached', 'imageDigest': image_digest})
            }

        # Get Qualys credentials from Secrets Manager
        qualys_creds = get_qualys_credentials()

        # Construct image URI
        account_id = context.invoked_function_arn.split(':')[4]
        region = os.environ['AWS_REGION']
        image_uri = f"{account_id}.dkr.ecr.{region}.amazonaws.com/{repository_name}@{image_digest}"

        print(f"Scanning image: {image_uri}")

        # Run QScanner
        scan_results = run_qscanner(image_uri, qualys_creds)

        # Process and store results
        process_scan_results(
            scan_results,
            repository_name,
            image_digest,
            image_tag,
            account_id,
            region
        )

        # Cache the scan results
        cache_scan_results(image_digest, scan_results)

        # Tag the ECR image with scan metadata
        tag_ecr_image(repository_name, image_digest, scan_results)

        # Send SNS notification if configured
        if SNS_TOPIC_ARN and has_critical_findings(scan_results):
            send_sns_notification(repository_name, image_digest, image_tag, scan_results)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'status': 'scanned',
                'imageDigest': image_digest,
                'vulnerabilities': scan_results.get('vulnerabilityCount', 0),
                'secrets': scan_results.get('secretCount', 0)
            })
        }

    except Exception as e:
        print(f"Error scanning image: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def get_qualys_credentials():
    """Retrieve Qualys credentials from Secrets Manager"""
    try:
        response = secretsmanager.get_secret_value(SecretId=QUALYS_SECRET_ARN)
        secret = json.loads(response['SecretString'])
        return {
            'pod': secret['qualys_pod'],
            'access_token': secret['qualys_access_token']
        }
    except ClientError as e:
        print(f"Error retrieving Qualys credentials: {e}")
        raise


def run_qscanner(image_uri, qualys_creds):
    """
    Execute QScanner binary to scan the container image
    Returns parsed scan results
    """
    # Ensure output directories exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    # Construct QScanner command
    cmd = [
        QSCANNER_PATH,
        '--pod', qualys_creds['pod'],
        '--access-token', qualys_creds['access_token'],
        '--output-dir', OUTPUT_DIR,
        '--cache-dir', CACHE_DIR,
        '--scan-types', SCAN_TYPES,
        '--format', 'json',
        'image', image_uri
    ]

    print(f"Executing QScanner command: {' '.join(cmd[:8])} [credentials redacted]")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
            check=False
        )

        print(f"QScanner exit code: {result.returncode}")
        print(f"QScanner stdout: {result.stdout}")

        if result.returncode != 0:
            print(f"QScanner stderr: {result.stderr}")

        # Parse JSON output
        return parse_qscanner_output(OUTPUT_DIR)

    except subprocess.TimeoutExpired:
        print("QScanner execution timed out")
        raise
    except Exception as e:
        print(f"Error running QScanner: {e}")
        raise


def parse_qscanner_output(output_dir):
    """Parse QScanner JSON output files"""
    results = {
        'vulnerabilityCount': 0,
        'secretCount': 0,
        'criticalCount': 0,
        'highCount': 0,
        'mediumCount': 0,
        'lowCount': 0,
        'findings': []
    }

    # Look for JSON output files
    for filename in os.listdir(output_dir):
        if filename.endswith('.json'):
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'r') as f:
                data = json.load(f)

                # Parse vulnerability data
                if 'vulnerabilities' in data:
                    vulns = data['vulnerabilities']
                    results['vulnerabilityCount'] = len(vulns)

                    for vuln in vulns:
                        severity = vuln.get('severity', 'unknown').lower()
                        if severity == 'critical':
                            results['criticalCount'] += 1
                        elif severity == 'high':
                            results['highCount'] += 1
                        elif severity == 'medium':
                            results['mediumCount'] += 1
                        elif severity == 'low':
                            results['lowCount'] += 1

                        results['findings'].append({
                            'type': 'vulnerability',
                            'id': vuln.get('id'),
                            'severity': severity,
                            'package': vuln.get('package'),
                            'version': vuln.get('version')
                        })

                # Parse secret detection data
                if 'secrets' in data:
                    secrets = data['secrets']
                    results['secretCount'] = len(secrets)

                    for secret in secrets:
                        results['findings'].append({
                            'type': 'secret',
                            'category': secret.get('category'),
                            'file': secret.get('file'),
                            'line': secret.get('line')
                        })

    return results


def is_scan_cached(image_digest):
    """Check if scan results exist in DynamoDB cache"""
    try:
        response = cache_table.get_item(Key={'imageDigest': image_digest})

        if 'Item' in response:
            # Check if cache is still valid (not expired)
            ttl = response['Item'].get('ttl', 0)
            current_time = int(datetime.now().timestamp())

            if ttl > current_time:
                return True

        return False
    except ClientError as e:
        print(f"Error checking cache: {e}")
        return False


def cache_scan_results(image_digest, scan_results):
    """Store scan results in DynamoDB with TTL"""
    try:
        ttl = int((datetime.now() + timedelta(days=CACHE_TTL_DAYS)).timestamp())

        cache_table.put_item(
            Item={
                'imageDigest': image_digest,
                'scanResults': scan_results,
                'scannedAt': datetime.now().isoformat(),
                'ttl': ttl
            }
        )
        print(f"Cached scan results for {image_digest}")
    except ClientError as e:
        print(f"Error caching results: {e}")


def process_scan_results(scan_results, repository_name, image_digest, image_tag, account_id, region):
    """Store scan results in S3"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        s3_key = f"scan-results/{repository_name}/{image_digest}/{timestamp}.json"

        result_data = {
            'repository': repository_name,
            'imageDigest': image_digest,
            'imageTag': image_tag,
            'accountId': account_id,
            'region': region,
            'scannedAt': datetime.now().isoformat(),
            'scanResults': scan_results
        }

        s3_client.put_object(
            Bucket=RESULTS_BUCKET,
            Key=s3_key,
            Body=json.dumps(result_data, indent=2),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )

        print(f"Stored scan results in S3: s3://{RESULTS_BUCKET}/{s3_key}")
    except ClientError as e:
        print(f"Error storing results in S3: {e}")


def tag_ecr_image(repository_name, image_digest, scan_results):
    """Add tags to ECR image with scan metadata"""
    try:
        ecr_client.put_image_tag_list(
            repositoryName=repository_name,
            imageDigest=image_digest,
            tags=[
                {
                    'Key': 'qualys:scanned',
                    'Value': 'true'
                },
                {
                    'Key': 'qualys:scan-date',
                    'Value': datetime.now().strftime('%Y-%m-%d')
                },
                {
                    'Key': 'qualys:vulnerabilities',
                    'Value': str(scan_results.get('vulnerabilityCount', 0))
                },
                {
                    'Key': 'qualys:critical',
                    'Value': str(scan_results.get('criticalCount', 0))
                }
            ]
        )
        print(f"Tagged ECR image {repository_name}@{image_digest}")
    except ClientError as e:
        # ECR tagging may not be supported in all regions/configurations
        print(f"Warning: Could not tag ECR image: {e}")


def has_critical_findings(scan_results):
    """Check if scan has critical or high severity findings"""
    critical = scan_results.get('criticalCount', 0)
    high = scan_results.get('highCount', 0)
    secrets = scan_results.get('secretCount', 0)

    return critical > 0 or high > 0 or secrets > 0


def send_sns_notification(repository_name, image_digest, image_tag, scan_results):
    """Send SNS notification for critical findings"""
    try:
        message = {
            'repository': repository_name,
            'imageDigest': image_digest,
            'imageTag': image_tag,
            'scannedAt': datetime.now().isoformat(),
            'summary': {
                'vulnerabilities': scan_results.get('vulnerabilityCount', 0),
                'critical': scan_results.get('criticalCount', 0),
                'high': scan_results.get('highCount', 0),
                'secrets': scan_results.get('secretCount', 0)
            }
        }

        subject = f"🚨 Security Alert: {repository_name}:{image_tag}"

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=json.dumps(message, indent=2)
        )

        print(f"Sent SNS notification for {repository_name}:{image_tag}")
    except ClientError as e:
        print(f"Error sending SNS notification: {e}")
