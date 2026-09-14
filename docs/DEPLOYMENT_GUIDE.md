# NetShield AI — Deployment & Operations Guide

This guide provides step-by-step instructions for deploying NetShield AI in local development, containerized environments, and enterprise production setups.

---

## 1. System Requirements

| Component | Minimum Specification | Recommended Specification |
|-----------|------------------------|---------------------------|
| **OS** | Windows 10/11, Ubuntu 20.04+, macOS 12+ | Ubuntu 22.04 LTS or Debian 12 |
| **CPU** | 2 Cores (x86_64) | 4+ Cores |
| **RAM** | 4 GB | 8 GB+ |
| **Storage** | 2 GB Free Disk Space | 10 GB+ SSD |
| **Python** | Python 3.12+ | Python 3.12 |
| **Node.js** | Node.js 18.x or 20.x | Node.js 20.x LTS |

---

## 2. Option A: Quick 1-Click Startup (Recommended)

### On Windows
Double-click `START_NETSHIELD.bat` or run:
```cmd
START_NETSHIELD.bat
```
- Automatically verifies Python and Node dependencies.
- Starts FastAPI Backend on `http://localhost:8000`.
- Starts Next.js Frontend on `http://localhost:3000`.
- Opens your default web browser to the NetShield AI Web Console.
- To stop: Run `STOP_NETSHIELD.bat`.

### On Linux / macOS
Make the scripts executable and run:
```bash
chmod +x START_NETSHIELD.sh STOP_NETSHIELD.sh
./START_NETSHIELD.sh
```
- Starts both backend and frontend processes in background.
- To stop: Run `./STOP_NETSHIELD.sh`.

---

## 3. Option B: Docker & Docker Compose

Deploy the entire SOC stack in isolated containers with one command:
```bash
docker-compose up --build -d
```

### Checking Container Health
```bash
docker-compose ps
docker-compose logs -f backend
```

### Accessing Endpoints
- **Frontend Dashboard**: `http://localhost:3000`
- **Backend REST API**: `http://localhost:8000/api`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`

### Teardown
```bash
docker-compose down
```

---

## 4. Option C: Manual Development Setup

### Backend Setup
1. Navigate to the backend folder:
   ```bash
   cd backend
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run FastAPI with auto-reload:
   ```bash
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

### Frontend Setup
1. Open a new terminal in the frontend folder:
   ```bash
   cd frontend
   ```
2. Install Node dependencies:
   ```bash
   npm install
   ```
3. Start the Next.js dev server:
   ```bash
   npm run dev
   ```

---

## 5. Production Nginx Reverse Proxy Configuration

For production deployment with SSL (HTTPS) and WebSocket support:

```nginx
server {
    listen 80;
    server_name netshield.yourcompany.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name netshield.yourcompany.com;

    ssl_certificate /etc/letsencrypt/live/netshield/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/netshield/privkey.pem;

    # Frontend Next.js Proxy
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # Backend REST API Proxy
    location /api/ {
        proxy_pass http://localhost:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Backend WebSocket Stream Proxy
    location /api/traffic/ws {
        proxy_pass http://localhost:8000/api/traffic/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

---

## 6. Environment Variables Reference

| Variable | Default Value | Description |
|----------|---------------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./netshield.db` | SQLAlchemy Async database connection URI (SQLite or PostgreSQL) |
| `SECRET_KEY` | `netshield-ai-enterprise-secret-key-prod-2026` | Cryptographic secret for signing JWT tokens |
| `ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` (24h) | JWT Token expiration lifetime |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000/api` | Base REST API URL used by the frontend |
| `CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Allowed CORS origins for browser security |

---

## 7. Default Credentials

| Role | Email | Password | Permissions |
|------|-------|----------|-------------|
| **Administrator** | `admin@netshield.ai` | `Admin@123456` | Full system access, SOAR execution, user & rule management |
| **SOC Analyst** | `analyst@netshield.ai` | `Analyst@123456` | Incident triage, timeline notes, alert disposition, report generation |
| **Security Viewer** | `viewer@netshield.ai` | `Viewer@123456` | Read-only telemetry, dashboard metrics, report downloading |
