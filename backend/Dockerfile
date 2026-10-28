# Multi-stage production Dockerfile for VulnReason Backend
FROM python:3.11-slim as base

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    fastapi==0.139.0 \
    uvicorn==0.54.0 \
    pydantic==2.14.1 \
    pydantic-settings==2.15.0 \
    sqlalchemy==2.0.51 \
    alembic==1.18.4 \
    asyncpg==0.32.0 \
    psycopg2-binary==2.9.13 \
    aiosqlite==0.22.1 \
    argon2-cffi==25.1.0 \
    pyjwt==2.15.1 \
    email-validator==2.3.0 \
    networkx==3.6.1 \
    httpx==0.28.1 \
    redis==8.0.0 \
    celery==5.6.3

COPY . /app/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
