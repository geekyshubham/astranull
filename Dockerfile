# AstraNull control plane (API + static UI). No secrets or database URLs baked in.
FROM node:22-alpine

LABEL org.opencontainers.image.title="AstraNull Control Plane"
LABEL org.opencontainers.image.description="No-access-first DDoS readiness validation platform — API and UI"
LABEL org.opencontainers.image.source="https://github.com/astranull/astranull"
LABEL org.opencontainers.image.vendor="AstraNull"

RUN addgroup -g 10001 -S astranull \
  && adduser -u 10001 -S astranull -G astranull

WORKDIR /app

COPY package.json ./
COPY src ./src
COPY apps/web ./apps/web
COPY docs/api.md ./docs/api.md
COPY db/schema.sql ./db/schema.sql

USER astranull

ENV NODE_ENV=production \
    PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Production startup fails closed until the Postgres persistence adapter is wired
# (see src/config.mjs). Set ASTRANULL_DATABASE_URL and ASTRANULL_SESSION_SECRET at runtime.
CMD ["node", "src/index.mjs"]