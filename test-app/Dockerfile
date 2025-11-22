# Deliberately Vulnerable Test Application
# This image contains known vulnerabilities and triggers runtime security events
FROM python:3.9-slim

# Install vulnerable packages (old versions with known CVEs)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat-traditional \
    procps \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages with known vulnerabilities
RUN pip install --no-cache-dir \
    flask==2.0.0 \
    requests==2.25.0 \
    pyyaml==5.3.1 \
    jinja2==2.11.0

# Create app directory
WORKDIR /app

# Add application code
COPY app.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Hardcoded secrets (will be detected by image scanner)
ENV DATABASE_PASSWORD="super_secret_password_123"
ENV API_KEY="sk-1234567890abcdefghijklmnopqrstuvwxyz"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Create a file with sensitive data
RUN echo "password=admin123" > /app/config.ini
RUN echo "db_password=P@ssw0rd!" >> /app/config.ini

# Expose port
EXPOSE 8080

# Run as root (insecure but helps with testing)
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python3", "app.py"]
