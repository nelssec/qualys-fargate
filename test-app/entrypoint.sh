#!/bin/bash
set -e

echo "Starting vulnerable test application..."
echo "Container ID: $(hostname)"
echo "Running as: $(whoami)"

# Generate some initial activity
echo "Reading system files..."
cat /etc/passwd > /dev/null
cat /etc/group > /dev/null

echo "Checking network connectivity..."
curl -I https://example.com 2>&1 || true

# Start the application
exec "$@"
