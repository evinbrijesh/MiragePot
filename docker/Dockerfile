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

# Create non-root user for running the application
RUN groupadd -r miragepot && useradd -r -g miragepot -u 1000 -d /app -s /sbin/nologin miragepot

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
COPY data/system_prompt.txt ./data/
COPY data/cache.json ./data/
COPY run.py ./

# Create necessary directories and transfer ownership to non-root user
RUN mkdir -p /app/data/logs && \
    chown -R miragepot:miragepot /app

# Switch to non-root user
USER miragepot

# Expose ports
EXPOSE 2222 8501 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 2222)); s.close()"

# Run MiragePot
CMD ["python", "run.py"]
