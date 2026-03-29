# MiragePot Dockerfile
# Multi-stage build for faster builds and smaller images

# ═══════════════════════════════════════════════════════════
# Stage 1: Build dependencies (cached layer)
# ═══════════════════════════════════════════════════════════
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies in a virtual environment
WORKDIR /build
COPY requirements.txt pyproject.toml ./
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /opt/venv/bin/pip install --no-cache-dir prometheus-client requests

# ═══════════════════════════════════════════════════════════
# Stage 2: Runtime image (minimal, fast startup)
# ═══════════════════════════════════════════════════════════
FROM python:3.11-slim

# Set labels
LABEL maintainer="Evin Brijesh <evinbrijesh@example.com>"
LABEL description="MiragePot - AI-Driven Adaptive SSH Honeypot"
LABEL version="0.2.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create non-root user
RUN groupadd -r miragepot && \
    useradd -r -g miragepot -u 1000 -d /app -s /sbin/nologin miragepot && \
    mkdir -p /app/data/logs && \
    chown -R miragepot:miragepot /app

# Set working directory
WORKDIR /app

# Copy application code (order matters for layer caching)
# Static assets first (rarely change)
COPY miragepot/cache.json ./miragepot/
COPY miragepot/system_prompt.txt ./miragepot/

# Application code (changes more frequently)
COPY --chown=miragepot:miragepot miragepot/ ./miragepot/
COPY --chown=miragepot:miragepot dashboard/ ./dashboard/
COPY --chown=miragepot:miragepot run.py ./

# Switch to non-root user
USER miragepot

# Expose ports
EXPOSE 2222 8501 9090

# Optimized health check (fast socket check)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=2 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 2222)); s.close()"

# Run MiragePot
CMD ["python", "-u", "run.py"]
