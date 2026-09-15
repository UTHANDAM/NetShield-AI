FROM python:3.12-slim

WORKDIR /app

# Install system utilities and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY backend/app/ ./app/

# Copy the database file if available
COPY netshield.db .

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    DATABASE_URL="sqlite+aiosqlite:///./netshield.db" \
    PORT=8000 \
    HOST=0.0.0.0

EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:$PORT/api/health || exit 1

# Start FastAPI application using the PORT environment variable
CMD uvicorn app.main:app --host 0.0.0.0 --port $PORT
