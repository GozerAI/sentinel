# Sentinel Security Platform
# Multi-stage build for production deployment

# =============================================================================
# Build stage
# =============================================================================
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

# =============================================================================
# Production stage
# =============================================================================
FROM python:3.11-slim as production

LABEL maintainer="GozerAI"
LABEL description="Sentinel AI-Native Security Platform"
LABEL version="0.1.0"

# Create non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iproute2 \
    iputils-ping \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create directories
RUN mkdir -p /var/lib/sentinel /var/log/sentinel /etc/sentinel && \
    chown -R sentinel:sentinel /var/lib/sentinel /var/log/sentinel /etc/sentinel

# Copy application code
WORKDIR /app
COPY --chown=sentinel:sentinel src/ src/
COPY --chown=sentinel:sentinel config/ config/

# Set environment
ENV PYTHONPATH=/app/src
ENV SENTINEL_CONFIG=/etc/sentinel/config.yaml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Switch to non-root user
USER sentinel

# Expose API port
EXPOSE 8080

# Default command
CMD ["python", "-m", "sentinel.cli.commands", "start", "--config", "/etc/sentinel/config.yaml"]

# =============================================================================
# Development stage
# =============================================================================
FROM production as development

USER root

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-asyncio \
    pytest-cov \
    black \
    ruff \
    mypy \
    ipython

# Switch back to sentinel user
USER sentinel

# Override command for development
CMD ["python", "-m", "sentinel.cli.commands", "start", "--config", "/etc/sentinel/config.yaml"]
