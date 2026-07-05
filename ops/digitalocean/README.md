# Deploy AstraNull on DigitalOcean (`astranull.site`)

Minimal production-like stack:

| Component | Choice |
|-----------|--------|
| Compute | App Platform (`basic-xxs`) |
| Database | Managed Postgres 16 (`db-s-dev`) |
| UI | React/shadcn SPA (`react-app.js`) |
| Auth (first launch) | Bundled staging OIDC at `/login` |
| Domain | `astranull.site` + `www.astranull.site` |

## Security first

- **Never** commit API tokens, GitHub PATs, or encryption keys to git.
- If a token was pasted into chat or code, **revoke it immediately** in GitHub → Settings → Developer settings → Personal access tokens.
- CI/CD uses **GitHub repository secrets** only (see below).

## One-time setup

### 1. DigitalOcean API token

1. [DigitalOcean](https://cloud.digitalocean.com/account/api/tokens) → **Generate New Token** (read + write).
2. Copy the token (shown once).

### 2. GitHub repository secrets

Repo: `geekyshubham/astranull` → **Settings → Secrets and variables → Actions → New repository secret**

| Secret | Value |
|--------|--------|
| `DIGITALOCEAN_ACCESS_TOKEN` | Your DigitalOcean API token |

Optional (if using `doctl` bootstrap instead of dashboard):

| Secret | Value |
|--------|--------|
| `DIGITALOCEAN_APP_ID` | App UUID after first create |

You do **not** need a GitHub PAT for this pipeline — Actions uses the built-in `GITHUB_TOKEN`, and App Platform pulls from your public repo.

### 3. Generate runtime secrets

```bash
openssl rand -hex 32   # → ASTRANULL_SECRET_ENCRYPTION_KEY
openssl rand -hex 24   # → ASTRANULL_PROBE_WORKER_SECRET
```

### 4. Create the App Platform app

**Option A — Dashboard (easiest)**

1. [App Platform](https://cloud.digitalocean.com/apps) → **Create App**.
2. Connect GitHub → select `geekyshubham/astranull`, branch `main`.
3. Choose **Dockerfile** path: `ops/digitalocean/Dockerfile`.
4. Add **Database** → PostgreSQL 16.
5. Under **Environment variables** for the web service, add:

   | Key | Value |
   |-----|--------|
   | `ASTRANULL_SECRET_ENCRYPTION_KEY` | (from openssl above) |
   | `ASTRANULL_PROBE_WORKER_SECRET` | (from openssl above) |

   Non-secret vars are already in [`app.yaml`](app.yaml); copy any missing ones from that file.

6. Link database → set `ASTRANULL_DATABASE_URL` = `${astranull-db.DATABASE_URL}`.
7. Name the app **`astranull`** (matches the GitHub Actions workflow).
8. Deploy once.

**Option B — CLI**

```bash
brew install doctl
doctl auth init -t "$DIGITALOCEAN_ACCESS_TOKEN"
doctl apps create --spec ops/digitalocean/app.yaml
```

Then add `ASTRANULL_SECRET_ENCRYPTION_KEY` and `ASTRANULL_PROBE_WORKER_SECRET` in the DO dashboard before the app will stay healthy.

### 5. Custom domain `astranull.site`

1. App Platform → **astranull** → **Settings → Domains**.
2. Add `astranull.site` (primary) and `www.astranull.site` (alias).
3. At your domain registrar, add the DNS records DigitalOcean shows (typically):
   - **A** / **ALIAS** for `@` → DO load balancer IP
   - **CNAME** for `www` → `astranull-xxxxx.ondigitalocean.app`
4. Wait for TLS (Let’s Encrypt) to turn green.

Set `ASTRANULL_PUBLIC_BASE_URL=https://astranull.site` (already in `app.yaml`).

## CI/CD (GitHub Actions)

Workflow: [`.github/workflows/deploy-digitalocean.yml`](../../.github/workflows/deploy-digitalocean.yml)

| Trigger | Behavior |
|---------|----------|
| Push to `main` | Lint + unit/integration tests + safety check → deploy live |
| Manual | Actions → **Deploy DigitalOcean** → **Run workflow** |

The deploy step uses [`digitalocean/app_action@v2`](https://github.com/digitalocean/app_action) with `app_name: astranull`. The app must exist on DO before the first automated deploy succeeds.

`deploy_on_push` is **false** in `app.yaml` so only GitHub Actions promotes releases (not every DO auto-hook).

## After deploy

1. Open **https://astranull.site**
2. **Sign up** or use bundled login at `/login` (hosted-staging OIDC fixture).
3. Demo tenant `ten_demo` is seeded on first boot (idempotent).

## What this minimal stack includes

- Control plane API + React portal
- Postgres persistence + migrations on boot
- Signed probe worker (in-container)
- Bundled OIDC for login until you wire enterprise IdP

## Not included (add later)

- External probe worker fleet
- Agent mTLS gateway
- WAF/cron workers on Kubernetes
- Enterprise IdP (`ASTRANULL_OIDC_ISSUER` / JWKS from your IdP)

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Deploy fails in Actions | Confirm `DIGITALOCEAN_ACCESS_TOKEN` secret and app name `astranull` |
| Crash on start | Set both encryption secrets in DO env |
| 503 `/ready` | Postgres not linked; check `ASTRANULL_DATABASE_URL` |
| Login redirect loop | `ASTRANULL_PUBLIC_BASE_URL` must be `https://astranull.site` |
| Old UI | Rebuild not needed — image ships committed `react-app.js` |

## Local parity

Same bootstrap as Railway: `scripts/railway-staging-start.mjs` (migrate → seed → probe worker → API).