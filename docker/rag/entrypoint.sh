#!/bin/bash
set -e

echo "Running database migrations..."
cd /app/models/db_schemes/rag_app/
alembic upgrade head

cd /app

echo "Starting FastAPI..."
exec "$@"