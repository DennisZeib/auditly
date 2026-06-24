# Auditly — slim image. Core scanner only (no Chromium) so it fits free-tier RAM.
# To enable deep browser checks, see README (uncomment the chromium block + set ENABLE_BROWSER=1).

FROM node:20-slim

WORKDIR /app

# Install only production deps; skip optional playwright-core to stay light.
COPY package.json ./
RUN npm install --omit=dev --omit=optional --no-audit --no-fund

COPY . .

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

CMD ["node", "server.js"]
