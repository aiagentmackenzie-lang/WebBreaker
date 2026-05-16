# WebBreaker Scanner — Python 3.12 slim
FROM python:3.12-slim

LABEL maintainer="WebBreaker Security"
LABEL description="WebBreaker — Web Application Penetration Testing Toolkit"

# System deps for WeasyPrint (PDF generation)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 \
        libffi-dev \
        libcairo2 \
        curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY core/ ./core/
COPY reports/ ./reports/
COPY templates/ ./templates/
COPY integrations/ ./integrations/
COPY ai/ ./ai/
COPY payloads/ ./payloads/
COPY cli.py ./
COPY api/ ./api/

# Default database location
ENV WEBBREAKER_DB=/data/webbreaker.db

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python3 -c "from core.config import ScanConfig; print('healthy')" || exit 1

ENTRYPOINT ["python3", "cli.py"]
CMD ["--help"]