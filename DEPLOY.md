# ThreatLens — Deployment Guide

## Cheapest Production Stack (~$7–12/month total)

| Service          | Provider          | Cost       | What it runs         |
|-----------------|-------------------|------------|----------------------|
| Backend API     | Railway           | ~$5/mo     | FastAPI + scheduler  |
| Frontend        | Vercel            | Free       | Next.js              |
| Database        | Railway PostgreSQL | included  | Bundled with backend |
| Email           | Resend.com        | Free       | 3000 emails/mo       |

**Total: ~$5/month** (Railway hobby plan)

---

## Step 1 — Local setup

```bash
# Clone / unzip the project
cd threatlens

# Backend
cd backend
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Download spaCy model (free, ~12MB)
python -m spacy download en_core_web_sm

# Database (PostgreSQL must be running)
createdb threatlens
cp .env.example .env
# Edit .env — set DATABASE_URL, SMTP credentials

# Start backend (MITRE ingestion runs automatically on first start)
uvicorn main:app --reload --port 8000
# → http://localhost:8000/docs

# Frontend (separate terminal)
cd ../frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1 npm run dev
# → http://localhost:3000
```

---

## Step 2 — Get free API keys (optional but recommended)

- **OTX AlienVault**: https://otx.alienvault.com (sign up → My Profile → API Key)
  Add to `.env`: `OTX_API_KEY=your_key`
- **Email**: Resend.com → free 3000 emails/mo
  Add SMTP_HOST=smtp.resend.com, SMTP_PORT=587

---

## Step 3 — Deploy to Railway (backend + DB)

```bash
# Install Railway CLI
npm install -g @railway/cli
railway login

# In backend/ directory
railway init
railway add postgresql          # provisions free PostgreSQL

# Set environment variables in Railway dashboard or:
railway variables set DATABASE_URL=${{Postgres.DATABASE_URL}}
railway variables set OTX_API_KEY=your_key
railway variables set APP_URL=https://your-frontend.vercel.app
railway variables set SMTP_HOST=smtp.resend.com
railway variables set SMTP_USER=resend
railway variables set SMTP_PASS=your_resend_key

# Deploy
railway up
# → Railway gives you: https://threatlens-backend.up.railway.app
```

Create `Procfile` in backend/:
```
web: uvicorn main:app --host 0.0.0.0 --port $PORT
```

---

## Step 4 — Deploy frontend to Vercel (free)

```bash
cd frontend
npm install -g vercel
vercel

# Set env variable:
# NEXT_PUBLIC_API_URL = https://your-railway-url.up.railway.app/api/v1

vercel --prod
# → https://threatlens.vercel.app
```

---

## API Usage Examples

```bash
# 1. Register (get verification email)
curl -X POST https://your-api.railway.app/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "analyst@company.com"}'

# 2. After clicking email link, use your API key:
export KEY=tl_your_api_key_here

# 3. List all threat actors
curl -H "X-API-Key: $KEY" https://your-api.railway.app/api/v1/actors

# 4. Get APT28 full profile (find ID from list)
curl -H "X-API-Key: $KEY" https://your-api.railway.app/api/v1/actors/1

# 5. Get all IOCs for an actor
curl -H "X-API-Key: $KEY" "https://your-api.railway.app/api/v1/actors/1/indicators?ioc_type=ip"

# 6. Pivot from any IOC to linked actors
curl -H "X-API-Key: $KEY" "https://your-api.railway.app/api/v1/indicators/pivot/185.220.101.47"

# 7. Cross-entity search
curl -H "X-API-Key: $KEY" "https://your-api.railway.app/api/v1/search?q=lazarus"

# 8. Platform stats
curl -H "X-API-Key: $KEY" https://your-api.railway.app/api/v1/stats

# 9. Check your usage
curl -H "X-API-Key: $KEY" https://your-api.railway.app/api/v1/auth/me
```

---

## Rate Limits by Plan

| Plan       | Per Minute | Per Day  |
|-----------|------------|----------|
| Free       | 10         | 500      |
| Pro        | 60         | 10,000   |
| Enterprise | 300        | 100,000  |

Rate limit headers returned on every response:
```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
Retry-After: 60  (on 429)
```

---

## Data Sources (all free)

| Source            | Data                          | Update Frequency |
|------------------|-------------------------------|-----------------|
| MITRE ATT&CK      | 130+ actor profiles, TTPs     | Weekly           |
| AlienVault OTX    | Live IOCs tagged to actors    | Every 6 hours    |
| Mandiant Blog     | IOCs from research posts      | Every 12 hours   |
| Unit 42 Blog      | Palo Alto threat research     | Every 12 hours   |
| Microsoft MSTIC   | Nation-state campaign intel   | Every 12 hours   |
| CISA Alerts       | US govt actor-attributed IOCs | Every 12 hours   |
| Secureworks Blog  | CTU threat research           | Every 12 hours   |
| The DFIR Report   | Detailed intrusion reports    | Every 12 hours   |

---

## Scaling path

When you grow past Railway hobby:
- **Backend**: Railway Pro ($20/mo) or Hetzner VPS ($5/mo, more control)
- **DB**: Supabase free tier (500MB) → paid, or Neon.tech (serverless postgres, free tier)
- **Search**: Add Elasticsearch on same VPS when indicator count > 1M
- **Caching**: Upstash Redis (free 10k requests/day) for rate limiting at scale
