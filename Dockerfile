# SentinelAI Production Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install combined backend & dashboard requirements
COPY backend/requirements.txt backend-requirements.txt
COPY dashboard/requirements.txt dashboard-requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r backend-requirements.txt -r dashboard-requirements.txt

# Copy application sources
COPY backend/ /app/backend/
COPY dashboard/ /app/dashboard/
COPY scripts/ /app/scripts/
COPY data/ /app/data/

# Initialize baseline ML model
RUN python scripts/train_model.py --count 2000

ENV PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0

EXPOSE 8000 8501

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
