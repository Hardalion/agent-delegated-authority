FROM node:22.19.0-bookworm-slim

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin adap
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@10.15.1 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages ./packages
COPY apps/hackathon-console ./apps/hackathon-console
COPY services/sandbox-apis ./services/sandbox-apis
COPY hackathon-starter.mjs hackathon-starter.ts ./
COPY examples/hackathon ./examples/hackathon

RUN pnpm install --frozen-lockfile \
  && pnpm --filter adap-policy build \
  && pnpm --filter adap-receipt build \
  && pnpm --filter adap build \
  && pnpm --filter adap-store-postgres build \
  && pnpm --filter adap-gateway build \
  && pnpm --filter adap-hackathon-console build \
  && mkdir -p /data \
  && chown -R adap:adap /app /data

USER adap
ENV NODE_ENV=production
ENV ADAP_DEPLOYMENT=hosted
ENV ADAP_BIND_HOST=127.0.0.1
ENV SANDBOX_DB=/data/hackathon-sandbox.sqlite
EXPOSE 4317

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4317/api/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "apps/hackathon-console/dist/main.js"]
