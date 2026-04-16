FROM python:3.10-slim

WORKDIR /app

# System dependencies (optimized)
RUN apt-get update && apt-get install -y \
    build-essential \
    libjpeg-dev \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install pip packages
COPY src/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY src/ .

# Alembic folders
RUN mkdir -p /app/models/db_schemes/minirag/

COPY docker/rag/alembic.ini /app/models/db_schemes/rag_app/alembic.ini

COPY docker/rag/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]