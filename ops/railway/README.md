# Railway staging / demo deploy

Deploy the AstraNull control plane (API + web UI) on [Railway](https://railway.app) for **internal staging and demos only**. This is **not** production configuration: it uses `dev-headers` auth and simulated probes.

## Prerequisites

- Railway account
- [Railway CLI](https://docs.railway.app/develop/cli) (optional): `npm i -g @railway/cli`

## One-time setup

### 1. Create project

```bash
cd /path/to/astranull
railway login
railway init
```

Or: New Project → Deploy from GitHub repo.

### 2. Add Postgres

In the Railway dashboard:

1. **+ New** → **Database** → **PostgreSQL**
2. Open the **web service** → **Variables**
3. Add reference: `ASTRANULL_DATABASE_URL` = `${{Postgres.DATABASE_URL}}`

### 3. Set staging variables

Copy from [`staging.env.example`](staging.env.example) into the web service variables. Minimum required:

| Variable | Value |
|----------|--------|
| `NODE_ENV` | `development` |
| `ASTRANULL_DATABASE_URL` | `${{Postgres.DATABASE_URL}}` |
| `ASTRANULL_PERSISTENCE_MODE` | `postgres` |
| `ASTRANULL_AUTH_MODE` | `dev-headers` |
| `ASTRANULL_PROBE_MODE` | `simulation` |
| `ASTRANULL_HIGH_SCALE_ADAPTER_MODE` | `dry-run` |

### 4. Deploy

Railway reads [`railway.toml`](../../railway.toml) at the repo root and builds `ops/railway/Dockerfile.staging`.

On each deploy/start the container:

1. Runs `scripts/migrate-postgres.mjs`
2. Seeds demo tenant (`ten_demo`) via `scripts/seed-local-staging-tenant.mjs`
3. Starts `src/index.mjs`

Health check: `GET /health`

## Using the demo

1. Open the Railway-generated **public URL** for the web service.
2. In **Settings**, set:
   - **Tenant ID:** `ten_demo`
   - **User ID:** `usr_admin`
   - **Role:** `admin` (or `soc` for SOC console)
3. Explore Dashboard, Target Groups, WAF Posture, Test Runs, etc.

Pre-seeded data includes a demo target group `tg_demo_origin` and target `origin.demo.customer.example`.

## What is not included

Railway staging runs **only the control plane**. These are not deployed here:

- Signed external probe workers
- WAF orchestrator / drift / connector cron runners
- Agent mTLS gateway
- Production OIDC / MFA

That matches the project's external production blockers; this path is for demos and gap-audit walkthroughs.

## Local parity

Same behavior as `npm run staging:local:up` but hosted on Railway Postgres instead of Docker Compose on your machine.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Crash on start | `ASTRANULL_DATABASE_URL` set and Postgres plugin healthy |
| 401 on API | UI tenant/user/role headers match seeded tenant (`ten_demo` / `usr_admin` / `admin`) |
| Migrate errors | Railway Postgres logs; ensure DB is reachable from web service |
| Slow first boot | Migrations on cold start — health check allows 120s |