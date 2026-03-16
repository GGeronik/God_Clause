FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
COPY schemas/ ./schemas/
RUN npm run build

FROM node:20-slim
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./

RUN mkdir -p /app/contracts /app/audit

EXPOSE 3000

ENV PORT=3000
ENV CONTRACTS_DIR=/app/contracts
ENV AUDIT_DIR=/app/audit
ENV LOG_LEVEL=info

CMD ["node", "dist/cli/index.js", "serve", "--contracts", "/app/contracts", "--audit-dir", "/app/audit"]
