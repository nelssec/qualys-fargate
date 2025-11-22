#!/usr/bin/env python3
"""
Vulnerable Test Application
Generates various runtime security events for testing
"""

from flask import Flask, request, jsonify
import subprocess
import os
import time
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({
        "status": "running",
        "message": "Vulnerable test application",
        "endpoints": [
            "/install/<package>",
            "/download/<url>",
            "/connect/<host>/<port>",
            "/read/<filepath>",
            "/write/<filepath>",
            "/exec/<command>",
            "/trigger-all"
        ]
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/install/<package>')
def install_package(package):
    """Trigger software installation event"""
    try:
        # This will be detected by the runtime monitor
        result = subprocess.run(
            ['apt-get', 'update'],
            capture_output=True,
            text=True,
            timeout=30
        )

        result = subprocess.run(
            ['apt-get', 'install', '-y', package],
            capture_output=True,
            text=True,
            timeout=60
        )

        return jsonify({
            "event": "software_installation",
            "package": package,
            "status": "success" if result.returncode == 0 else "failed",
            "output": result.stdout[:500]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/download/<path:url>')
def download_file(url):
    """Trigger file download event"""
    try:
        # Download using curl (suspicious activity)
        filename = f"/tmp/downloaded_{int(time.time())}.bin"
        result = subprocess.run(
            ['curl', '-o', filename, url],
            capture_output=True,
            text=True,
            timeout=30
        )

        return jsonify({
            "event": "file_download",
            "url": url,
            "filename": filename,
            "status": "success" if result.returncode == 0 else "failed"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/connect/<host>/<int:port>')
def test_connection(host, port):
    """Trigger network connection event"""
    try:
        # Attempt network connection (will be monitored)
        result = subprocess.run(
            ['nc', '-zv', host, str(port)],
            capture_output=True,
            text=True,
            timeout=10
        )

        return jsonify({
            "event": "network_connection",
            "host": host,
            "port": port,
            "status": "reachable" if result.returncode == 0 else "unreachable"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/read/<path:filepath>')
def read_file(filepath):
    """Trigger file access event"""
    try:
        # Read sensitive files (FIM will detect)
        with open(f'/{filepath}', 'r') as f:
            content = f.read(500)

        return jsonify({
            "event": "file_access",
            "filepath": filepath,
            "content_length": len(content),
            "preview": content[:100]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/write/<path:filepath>')
def write_file(filepath):
    """Trigger file write event"""
    try:
        # Write to sensitive locations
        with open(f'/{filepath}', 'w') as f:
            f.write(f"Test write at {time.time()}\n")

        return jsonify({
            "event": "file_write",
            "filepath": filepath,
            "status": "success"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/exec/<path:command>')
def exec_command(command):
    """Trigger process execution event (dangerous!)"""
    try:
        # Execute arbitrary command (very insecure, for testing only)
        result = subprocess.run(
            command.split(),
            capture_output=True,
            text=True,
            timeout=10
        )

        return jsonify({
            "event": "process_execution",
            "command": command,
            "stdout": result.stdout[:500],
            "stderr": result.stderr[:500],
            "returncode": result.returncode
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/trigger-all')
def trigger_all_events():
    """Trigger all security events in sequence"""
    events = []

    # 1. File access to sensitive files
    try:
        with open('/etc/passwd', 'r') as f:
            f.read(100)
        events.append({"event": "file_access", "file": "/etc/passwd", "status": "success"})
    except:
        events.append({"event": "file_access", "file": "/etc/passwd", "status": "failed"})

    # 2. File write to /tmp
    try:
        with open('/tmp/test_write.txt', 'w') as f:
            f.write("test data")
        events.append({"event": "file_write", "file": "/tmp/test_write.txt", "status": "success"})
    except:
        events.append({"event": "file_write", "status": "failed"})

    # 3. Network connection
    try:
        subprocess.run(['curl', '-I', 'https://example.com'], timeout=5, capture_output=True)
        events.append({"event": "network_connection", "host": "example.com", "status": "success"})
    except:
        events.append({"event": "network_connection", "status": "failed"})

    # 4. Process execution
    try:
        result = subprocess.run(['whoami'], capture_output=True, text=True)
        events.append({"event": "process_execution", "command": "whoami", "output": result.stdout.strip()})
    except:
        events.append({"event": "process_execution", "status": "failed"})

    # 5. Download file
    try:
        subprocess.run(['curl', '-o', '/tmp/test_download.html', 'https://example.com'], timeout=10, capture_output=True)
        events.append({"event": "file_download", "status": "success"})
    except:
        events.append({"event": "file_download", "status": "failed"})

    return jsonify({
        "triggered_events": len(events),
        "events": events,
        "timestamp": time.time()
    })

if __name__ == '__main__':
    print("Starting vulnerable test application...")
    print("WARNING: This application is intentionally insecure for testing purposes")
    app.run(host='0.0.0.0', port=8080, debug=True)
