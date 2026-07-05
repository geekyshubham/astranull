# DigitalOcean App Platform: Postgres-backed control plane + React UI.
FROM node:22-alpine

LABEL org.opencontainers.image.title="AstraNull Control Plane (DigitalOcean)"
LABEL org.opencontainers.image.description="API and React portal for astranull.site"

RUN addgroup -g 10001 -S astranull \
  && adduser -u 10001 -S astranull -G astranull

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY src ./src
COPY scripts ./scripts
COPY apps/web ./apps/web
COPY docs/api.md ./docs/api.md
COPY db/schema.sql ./db/schema.sql
COPY db/migrations ./db/migrations
COPY ops/staging ./ops/staging
COPY workers ./workers

USER astranull

ENV NODE_ENV=production \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "scripts/railway-staging-start.mjs"]