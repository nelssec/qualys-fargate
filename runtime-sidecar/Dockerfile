# Fargate Runtime Security Sidecar
# Uses ptrace to monitor application containers for security threats
#
# SECURITY NOTICE:
# This container requires SYS_PTRACE capability to monitor other containers.
# It must run as root to attach to processes in other containers.
# Minimize exposure by:
# - Only granting SYS_PTRACE capability (drop ALL others)
# - Using in controlled environments only
# - Ensuring secrets are injected via AWS Secrets Manager (not env vars)

FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Security: Set labels for container identification
LABEL maintainer="security-team" \
      description="Fargate Runtime Security Monitor" \
      version="1.0.0" \
      security.privileged="SYS_PTRACE required"

# Install only required runtime packages with minimal footprint
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && rm -rf /var/cache/apt/archives/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory with appropriate permissions
WORKDIR /app

# Copy monitoring scripts with explicit ownership
COPY --chown=root:root runtime_monitor.py .
COPY --chown=root:root runtime_monitor_v2.py .
COPY --chown=root:root policy_engine.py .
COPY --chown=root:root db_writer.py .
COPY --chown=root:root software_detector.py .
COPY --chown=root:root qualys_crs_client.py .
RUN chmod 755 runtime_monitor.py runtime_monitor_v2.py

# Copy policy files
COPY --chown=root:root policies/ ./policies/

# Create directories for logs with restricted permissions
RUN mkdir -p /var/log/runtime-monitor && \
    chmod 750 /var/log/runtime-monitor

# Security: Read-only filesystem for logs volume
VOLUME ["/var/log/runtime-monitor"]

# SECURITY NOTICE: This container requires root to use ptrace
# The task definition MUST:
# 1. Add only SYS_PTRACE capability
# 2. Drop ALL other capabilities
# 3. Use secrets from AWS Secrets Manager (not environment variables)
# 4. Enable initProcessEnabled for proper process reaping
USER root

# Health check - verify monitor is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD pgrep -f runtime_monitor.py || exit 1

# Default environment variables (non-sensitive only)
# IMPORTANT: Sensitive values (QUALYS_ACCESS_TOKEN) should be injected
# via AWS Secrets Manager in the task definition, not set here
ENV MONITORING_MODE=balanced \
    ALERT_THRESHOLD=75 \
    CLOUDWATCH_NAMESPACE=FargateRuntimeSecurity \
    LOG_GROUP_NAME=/ecs/fargate-runtime-security \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Start the runtime monitor with unbuffered output
ENTRYPOINT ["python3", "-u"]
CMD ["runtime_monitor.py"]
