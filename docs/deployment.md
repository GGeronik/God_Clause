# Deployment Guide

God Clause can be deployed as an embedded library, a standalone server, or a Kubernetes sidecar.

## Embedded Library

The simplest deployment — import and use directly in your Node.js application:

```bash
npm install god-clause
```

```typescript
import { GodClause } from "god-clause";

const gov = new GodClause({
  auditSecretKey: process.env.AUDIT_HMAC_SECRET,
  stateStore: new MemoryStateStore(),
});

// Load contracts from files
import { readFileSync } from "fs";
const contract = readFileSync("./contracts/policy.yaml", "utf-8");
gov.loadContractYAML(contract);

// Use in your application
const decision = await gov.evaluate(context);
```

## Standalone Server

Run God Clause as an HTTP server that acts as a Policy Decision Point (PDP):

```bash
npx god-clause serve --port 3000 --contracts ./contracts/
```

Or via the API:

```typescript
import { createServer } from "god-clause/server";

const server = createServer({
  port: 3000,
  contractsDir: "./contracts",
  auditDir: "./audit",
  hmacSecret: process.env.AUDIT_HMAC_SECRET,
});

await server.start();
```

### Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/evaluate` | Evaluate context against policies |
| `POST` | `/v1/enforce` | Evaluate + return 403 on block |
| `GET` | `/v1/contracts` | List active contracts |
| `POST` | `/v1/contracts` | Load a new contract |
| `PUT` | `/v1/contracts/:name/activate/:version` | Activate version |
| `PUT` | `/v1/contracts/:name/deactivate/:version` | Deactivate version |
| `GET` | `/v1/audit` | Query audit log |
| `GET` | `/v1/audit/verify` | Verify hash chain |
| `POST` | `/v1/audit/seal` | Create Merkle checkpoint |
| `GET` | `/v1/health` | Liveness probe |
| `GET` | `/v1/ready` | Readiness probe |
| `GET` | `/v1/metrics` | Prometheus metrics |

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Server port |
| `CONTRACTS_DIR` | `./contracts` | Directory to load contracts from |
| `AUDIT_DIR` | `./audit` | Directory for JSONL audit files |
| `AUDIT_HMAC_SECRET` | — | HMAC-SHA256 signing key |
| `LOG_LEVEL` | `info` | Logging level (debug, info, warn, error) |
| `WATCH_CONTRACTS` | `true` | Hot-reload contracts on file change |
| `METRICS_ENABLED` | `true` | Enable Prometheus metrics |

## Docker

```dockerfile
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
RUN npm run build

FROM node:20-slim
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./
EXPOSE 3000
CMD ["node", "dist/cli/index.js", "serve"]
```

```bash
# Build
docker build -t god-clause .

# Run with contracts mounted
docker run -d \
  -p 3000:3000 \
  -v $(pwd)/contracts:/app/contracts \
  -e AUDIT_HMAC_SECRET=your-secret-key \
  god-clause
```

### Docker Compose

```yaml
version: "3.8"
services:
  god-clause:
    build: .
    ports:
      - "3000:3000"
    volumes:
      - ./contracts:/app/contracts
      - ./audit:/app/audit
    environment:
      - AUDIT_HMAC_SECRET=${AUDIT_HMAC_SECRET}
      - LOG_LEVEL=info
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/v1/health"]
      interval: 10s
      timeout: 5s
      retries: 3
```

## Kubernetes

### Helm Chart

```bash
helm install god-clause ./charts/god-clause \
  --set image.tag=latest \
  --set config.hmacSecret=your-secret \
  --set contracts.configMap=my-contracts
```

### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: god-clause
spec:
  replicas: 2
  selector:
    matchLabels:
      app: god-clause
  template:
    metadata:
      labels:
        app: god-clause
    spec:
      containers:
        - name: god-clause
          image: god-clause:latest
          ports:
            - containerPort: 3000
          env:
            - name: AUDIT_HMAC_SECRET
              valueFrom:
                secretKeyRef:
                  name: god-clause-secrets
                  key: hmac-secret
          volumeMounts:
            - name: contracts
              mountPath: /app/contracts
          livenessProbe:
            httpGet:
              path: /v1/health
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /v1/ready
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
            limits:
              memory: "256Mi"
              cpu: "500m"
      volumes:
        - name: contracts
          configMap:
            name: god-clause-contracts
---
apiVersion: v1
kind: Service
metadata:
  name: god-clause
spec:
  selector:
    app: god-clause
  ports:
    - port: 80
      targetPort: 3000
```

### Sidecar Pattern

Deploy God Clause as a sidecar container alongside your AI service:

```yaml
spec:
  containers:
    - name: ai-service
      image: my-ai-service:latest
      env:
        - name: GOD_CLAUSE_URL
          value: "http://localhost:3000"

    - name: god-clause
      image: god-clause:latest
      ports:
        - containerPort: 3000
      volumeMounts:
        - name: contracts
          mountPath: /app/contracts
```

Your AI service calls `http://localhost:3000/v1/evaluate` before every AI operation — zero network hops, pod-local enforcement.

## Production Checklist

- [ ] Set `AUDIT_HMAC_SECRET` to a strong random key (32+ bytes)
- [ ] Configure persistent audit storage (file sink with mounted volume, or S3/webhook sink)
- [ ] Enable Prometheus metrics scraping on `/v1/metrics`
- [ ] Set up liveness and readiness probes
- [ ] Store contracts in version control (ConfigMap sourced from Git)
- [ ] Create Merkle seal checkpoints on a schedule (e.g., hourly cron)
- [ ] Set up alerting on `godclause_blocks_total` metric
- [ ] Configure log aggregation (structured JSON → ELK/Splunk/Datadog)
- [ ] Test contract changes in staging before activating in production
- [ ] Document incident response for governance violations
