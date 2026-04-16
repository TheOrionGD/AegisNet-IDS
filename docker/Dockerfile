FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    iptables \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first for better layer caching
COPY back-end/requirements.txt ./back-end/
RUN pip install --no-cache-dir -r ./back-end/requirements.txt

# Copy all project files
COPY . .

# Ensure shared volumes exist
RUN mkdir -p data logs models

ENV PYTHONPATH=/app/back-end:/app

WORKDIR /app/back-end
EXPOSE 8000

# Default command is API (Can be overridden in docker-compose.yml)
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
