# Fargate Runtime Security Sidecar
# Uses ptrace to monitor application containers for security threats

FROM python:3.11-slim

# Install required system packages
RUN apt-get update && apt-get install -y \
    strace \
    procps \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r monitor && useradd -r -g monitor monitor

# Set working directory
WORKDIR /app

# Copy Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy monitoring script
COPY runtime_monitor.py .
RUN chmod +x runtime_monitor.py

# Create directories for logs and cache
RUN mkdir -p /var/log/runtime-monitor && \
    chown -R monitor:monitor /var/log/runtime-monitor

# Security: Use read-only filesystem where possible
VOLUME ["/var/log/runtime-monitor"]

# Note: We need to run as root to use ptrace, but we minimize privileges
# In production, use security contexts to limit capabilities to just SYS_PTRACE

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -f runtime_monitor.py || exit 1

# Default environment variables
ENV MONITORING_MODE=balanced \
    ALERT_THRESHOLD=75 \
    CLOUDWATCH_NAMESPACE=FargateRuntimeSecurity \
    LOG_GROUP_NAME=/ecs/fargate-runtime-security

# Start the runtime monitor
CMD ["python3", "-u", "runtime_monitor.py"]
