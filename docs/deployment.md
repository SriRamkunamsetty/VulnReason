# Production Deployment Guide: VulnReason

## 1. Prerequisites
- Docker Engine 24.0+ and Docker Compose v2+
- Or Kubernetes 1.28+ with Helm 3
- Domain with TLS termination (Let's Encrypt / Cloudflare)

---

## 2. Infrastructure Setup
VulnReason uses a hardened container architecture:

```
[ Ingress / Nginx Reverse Proxy ]
       |
       +--> [ Frontend (Static React SPA in Nginx) ]
       |
       +--> [ Backend (FastAPI / Uvicorn) ]
                 |
                 +--> [ PostgreSQL 16 ] (Persistent Volume)
                 +--> [ Redis 7 ] (Task Broker & Rate Limits)
```

### Environment Configuration
Copy `.env.example` to `.env` on production host:
```bash
cp .env.example .env
# Set secure random strings:
# SECRET_KEY=$(openssl rand -hex 32)
# POSTGRES_PASSWORD=$(openssl rand -hex 24)
```

---

## 3. Launching via Docker Compose
```bash
docker compose up -d --build
```

### Post-Deployment Verification
```bash
# Verify database migrations
docker compose exec backend alembic upgrade head

# Check system health endpoint
curl -s http://localhost:8000/api/v1/health/readiness | jq .
```
Expected output:
```json
{
  "status": "ready",
  "database_connected": true,
  "workers_ready": true
}
```
