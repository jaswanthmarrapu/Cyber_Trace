# CyberTrace Forensics Platform - Production Backend Dockerfile
FROM python:3.11-slim

# System dependencies for forensic libraries and PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . /app

# Create persistent storage directories and assign non-root examiner user
RUN mkdir -p /app/uploads /app/reports /data /var/data && \
    useradd -u 1000 -m -s /bin/bash forensic_user && \
    chown -R forensic_user:forensic_user /app /data /var/data

USER forensic_user

ENV PYTHONUNBUFFERED=1 \
    ENVIRONMENT=production \
    PYTHONPATH=/app \
    PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["sh", "-c", "gunicorn -w 2 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:${PORT:-8000} app.main:app"]
