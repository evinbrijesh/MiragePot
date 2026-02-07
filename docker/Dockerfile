# MiragePot Dockerfile
# Optimized Python image for production deployment

FROM python:3.11-slim

# Set labels
LABEL maintainer="Evin Brijesh <evinbrijesh@example.com>"
LABEL description="MiragePot - AI-Driven Adaptive SSH Honeypot"
LABEL version="1.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt pyproject.toml ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir prometheus-client requests

# Copy application code
COPY miragepot/ ./miragepot/
COPY dashboard/ ./dashboard/
COPY data/ ./data/
COPY run.py ./

# Create necessary directories
RUN mkdir -p /app/data/logs && \
    chmod 755 /app/data/logs

# Expose ports
EXPOSE 2222 8501 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 2222)); s.close()"

# Run MiragePot
CMD ["python", "-m", "miragepot.server"]
