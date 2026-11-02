FROM node:22-alpine
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.15.1 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/policy-engine packages/policy-engine
COPY packages/audit-verify packages/audit-verify
COPY packages/aap packages/aap
COPY packages/adap-store-postgres packages/adap-store-postgres
COPY packages/adap-gateway packages/adap-gateway
COPY staging/bootstrap-vault.mjs staging/bootstrap-vault.mjs
COPY staging/downstream/server.mjs staging/downstream/server.mjs
RUN pnpm install --frozen-lockfile \
  && pnpm --filter adap-policy build \
  && pnpm --filter adap-receipt build \
  && pnpm --filter adap build \
  && pnpm --filter adap-store-postgres build \
  && pnpm --filter adap-gateway build
ENV NODE_ENV=production
EXPOSE 8443
CMD ["node", "packages/adap-gateway/dist/server.js"]
