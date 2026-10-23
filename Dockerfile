# syntax=docker/dockerfile:1
# Build and run Axis Intelligence as a self-contained Next.js server. Used by Coolify (Build Pack: Dockerfile).

# ── install dependencies ───────────────────────────────────────────────
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ── build the standalone server ────────────────────────────────────────
FROM node:22-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# ── run ────────────────────────────────────────────────────────────────
FROM node:22-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3200
ENV HOSTNAME=0.0.0.0

# the standalone server, static assets and the public folder
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
# pdfkit loads its font-metric (.afm) files from disk at runtime, so ship the whole package
COPY --from=build /app/node_modules/pdfkit ./node_modules/pdfkit

# leads are appended here; mount a volume on /app/data to keep them across deploys
RUN mkdir -p /app/data && chown -R node:node /app/data
VOLUME ["/app/data"]

USER node
EXPOSE 3200
CMD ["node", "server.js"]
