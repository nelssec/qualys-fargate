"""
ECR Image Scanner Lambda Function
Scans container images in ECR using Qualys QScanner when images are pushed.
Triggered by EventBridge rules monitoring ECR PutImage API calls.
"""

import json
import os
import subprocess
import re
import boto3
import logging
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# Configure logging - avoid logging sensitive data
logger = logging.getLogger()
logger.setLevel(logging.INFO)

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

# Input validation patterns
REPOSITORY_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9._/-]{0,255}$')
IMAGE_DIGEST_PATTERN = re.compile(r'^sha256:[a-f0-9]{64}$')
IMAGE_TAG_PATTERN = re.compile(r'^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$')


def validate_repository_name(name: str) -> bool:
    """Validate ECR repository name format"""
    if not name or not isinstance(name, str):
        return False
    return bool(REPOSITORY_NAME_PATTERN.match(name))


def validate_image_digest(digest: str) -> bool:
    """Validate image digest format (sha256:hex)"""
    if not digest or not isinstance(digest, str):
        return False
    return bool(IMAGE_DIGEST_PATTERN.match(digest))


def validate_image_tag(tag: str) -> bool:
    """Validate image tag format"""
    if not tag or not isinstance(tag, str):
        return True  # Tag is optional
    if tag == 'untagged':
        return True
    return bool(IMAGE_TAG_PATTERN.match(tag))


def sanitize_for_logging(data: dict) -> dict:
    """Remove sensitive fields from data before logging"""
    sensitive_keys = {'access_token', 'secret', 'password', 'credential', 'token', 'key'}
    sanitized = {}
    for k, v in data.items():
        if any(sensitive in k.lower() for sensitive in sensitive_keys):
            sanitized[k] = '[REDACTED]'
        elif isinstance(v, dict):
            sanitized[k] = sanitize_for_logging(v)
        else:
            sanitized[k] = v
    return sanitized


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
        # Log event metadata only (not full event to avoid logging sensitive data)
        logger.info(f"Processing ECR image scan event, source: {event.get('source', 'unknown')}")

        # Extract image information from event
        detail = event.get('detail', {})
        request_params = detail.get('requestParameters', {})
        response_elements = detail.get('responseElements', {})

        repository_name = request_params.get('repositoryName')
        image_info = response_elements.get('image', {}).get('imageId', {})
        image_digest = image_info.get('imageDigest')
        image_tag = image_info.get('imageTag', 'untagged')

        # Validate required fields
        if not repository_name or not image_digest:
            logger.error("Missing required fields in event")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing required fields'})
            }

        # Validate input formats to prevent injection attacks
        if not validate_repository_name(repository_name):
            logger.error(f"Invalid repository name format")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid repository name format'})
            }

        if not validate_image_digest(image_digest):
            logger.error(f"Invalid image digest format")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid image digest format'})
            }

        if not validate_image_tag(image_tag):
            logger.error(f"Invalid image tag format")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid image tag format'})
            }

        # Check cache to avoid duplicate scans
        if is_scan_cached(image_digest):
            logger.info(f"Scan results for digest found in cache, skipping scan")
            return {
                'statusCode': 200,
                'body': json.dumps({'status': 'cached', 'imageDigest': image_digest})
            }

        # Get Qualys credentials from Secrets Manager
        qualys_creds = get_qualys_credentials()

        # Construct image URI - use validated inputs
        account_id = context.invoked_function_arn.split(':')[4]
        region = os.environ['AWS_REGION']

        # Validate account_id format (12 digit number)
        if not re.match(r'^\d{12}$', account_id):
            logger.error("Invalid account ID extracted from context")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': 'Internal configuration error'})
            }

        image_uri = f"{account_id}.dkr.ecr.{region}.amazonaws.com/{repository_name}@{image_digest}"

        logger.info(f"Starting scan for repository: {repository_name}")

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

    except ClientError as e:
        # Log the full error for debugging but return generic message
        logger.error(f"AWS service error during scan: {e.response['Error']['Code']}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Service error during scan'})
        }
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid input'})
        }
    except subprocess.TimeoutExpired:
        logger.error("Scan timed out")
        return {
            'statusCode': 504,
            'body': json.dumps({'error': 'Scan timed out'})
        }
    except Exception as e:
        # Log error type but not details that might expose internals
        logger.error(f"Unexpected error during scan: {type(e).__name__}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal error during scan'})
        }


def get_qualys_credentials():
    """Retrieve Qualys credentials from Secrets Manager"""
    try:
        response = secretsmanager.get_secret_value(SecretId=QUALYS_SECRET_ARN)
        secret = json.loads(response['SecretString'])

        # Validate required credential fields exist
        if 'qualys_pod' not in secret or 'qualys_access_token' not in secret:
            raise ValueError("Missing required fields in Qualys secret")

        return {
            'pod': secret['qualys_pod'],
            'access_token': secret['qualys_access_token']
        }
    except ClientError as e:
        logger.error(f"Error retrieving Qualys credentials: {e.response['Error']['Code']}")
        raise
    except json.JSONDecodeError:
        logger.error("Invalid JSON in Qualys secret")
        raise ValueError("Invalid secret format")


def run_qscanner(image_uri, qualys_creds):
    """
    Execute QScanner binary to scan the container image
    Returns parsed scan results
    """
    # Ensure output directories exist with restricted permissions
    os.makedirs(OUTPUT_DIR, mode=0o700, exist_ok=True)
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)

    # Validate POD value to prevent command injection
    valid_pods = {'US1', 'US2', 'US3', 'US4', 'EU1', 'EU2', 'IN1', 'CA1', 'AE1', 'UK1'}
    if qualys_creds['pod'] not in valid_pods:
        raise ValueError(f"Invalid Qualys POD value")

    # Construct QScanner command - credentials passed securely
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

    logger.info("Executing QScanner [credentials redacted]")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
            check=False,
            env={**os.environ, 'HOME': '/tmp'}  # Ensure clean environment
        )

        logger.info(f"QScanner exit code: {result.returncode}")

        if result.returncode != 0:
            # Log error without exposing sensitive details
            logger.warning(f"QScanner returned non-zero exit code: {result.returncode}")

        # Parse JSON output
        return parse_qscanner_output(OUTPUT_DIR)

    except subprocess.TimeoutExpired:
        logger.error("QScanner execution timed out")
        raise
    except Exception as e:
        logger.error(f"Error running QScanner: {type(e).__name__}")
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
        logger.warning(f"Error checking cache: {e.response['Error']['Code']}")
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
        logger.info("Cached scan results successfully")
    except ClientError as e:
        logger.error(f"Error caching results: {e.response['Error']['Code']}")


def process_scan_results(scan_results, repository_name, image_digest, image_tag, account_id, region):
    """Store scan results in S3"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        # Use validated inputs - repository_name and image_digest already validated
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

        logger.info(f"Stored scan results in S3 for repository: {repository_name}")
    except ClientError as e:
        logger.error(f"Error storing results in S3: {e.response['Error']['Code']}")


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
        logger.info(f"Tagged ECR image for repository: {repository_name}")
    except ClientError as e:
        # ECR tagging may not be supported in all regions/configurations
        logger.warning(f"Could not tag ECR image: {e.response['Error']['Code']}")


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

        # Truncate subject to SNS limit (100 chars) and sanitize
        subject = f"Security Alert: {repository_name}:{image_tag}"[:100]

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=json.dumps(message, indent=2)
        )

        logger.info(f"Sent SNS notification for repository: {repository_name}")
    except ClientError as e:
        logger.error(f"Error sending SNS notification: {e.response['Error']['Code']}")
