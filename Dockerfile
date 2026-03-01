FROM python:3.12-slim

LABEL maintainer="GRC Toolkit"
LABEL description="Automated GRC evidence collection and compliance assessment"

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY modules/ modules/
COPY scripts/ scripts/
COPY config/ config/
COPY lambda_handler.py .

# Create directories for evidence and reports
RUN mkdir -p evidence reports

# Non-root user for security
RUN useradd -m -s /bin/bash grc-user && \
    chown -R grc-user:grc-user /app
USER grc-user

# Default: run full collection + assessment pipeline
ENTRYPOINT ["python"]
CMD ["scripts/run_collection.py", "--config", "config/settings.yaml"]
