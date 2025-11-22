#!/bin/bash
# Trigger all security events on the vulnerable test application

if [ -z "$1" ]; then
    echo "Usage: $0 <task-ip-or-hostname>"
    echo "Example: $0 http://54.123.45.67:8080"
    exit 1
fi

APP_URL=$1

echo "Triggering security events on ${APP_URL}"
echo "========================================="
echo ""

# Test 1: Trigger all events at once
echo "[1] Triggering all events..."
curl -s "${APP_URL}/trigger-all" | jq '.'
echo ""
sleep 2

# Test 2: Software installation
echo "[2] Installing package (software_installation event)..."
curl -s "${APP_URL}/install/net-tools" | jq '.'
echo ""
sleep 2

# Test 3: File download
echo "[3] Downloading file (file_download event)..."
curl -s "${APP_URL}/download/https://example.com/test.sh" | jq '.'
echo ""
sleep 2

# Test 4: Network connection
echo "[4] Testing network connection (network_connection event)..."
curl -s "${APP_URL}/connect/example.com/80" | jq '.'
echo ""
sleep 2

# Test 5: Read sensitive file
echo "[5] Reading sensitive file (file_access event)..."
curl -s "${APP_URL}/read/etc/passwd" | jq '.'
echo ""
sleep 2

# Test 6: Write file
echo "[6] Writing file (file_write event)..."
curl -s "${APP_URL}/write/tmp/test.txt" | jq '.'
echo ""
sleep 2

# Test 7: Execute command
echo "[7] Executing command (process_execution event)..."
curl -s "${APP_URL}/exec/whoami" | jq '.'
echo ""

echo "========================================="
echo "All events triggered successfully!"
echo ""
echo "Wait 30 seconds for events to be processed, then run:"
echo "  python3 scripts/query-events.py --hours 1 --details"
echo ""
