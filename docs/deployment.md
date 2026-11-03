# Deployment Guide

God Clause can be deployed as an embedded library, a standalone server, or a Kubernetes sidecar.

## Embedded Library

The simplest deployment — import and use directly in your Node.js application:

```bash
npm install god-clause
```

```typescript
import { GodClause, MemoryStateStore } from "god-clause";

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
import { createServer } from "god-clause";

const server = createServer({
  port: 3000,
  contractsDir: "./contracts",
  auditDir: "./audit",
  hmacSecret: process.env.AUDIT_HMAC_SECRET,
  apiToken: process.env.API_TOKEN,
});

await server.start();
```

When `API_TOKEN` is set, every endpoint except the two probes requires `Authorization: Bearer <token>` and answers 401 otherwise; without it the server logs a warning at start and accepts unauthenticated requests. Bodies larger than `MAX_BODY_BYTES` get 413, malformed JSON or a context without `action`/`caller` gets 400.

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
| `POST` | `/v1/evaluate/batch` | Evaluate several contexts |
| `POST` | `/v1/mcp/authorize` | Authorize an MCP tool call |
| `GET` | `/v1/events` | Server-sent decision events |
| `GET` | `/v1/proof-bundle` | Export a proof bundle |
| `POST` | `/v1/proof-bundle/verify` | Verify a proof bundle |
| `GET` | `/v1/health` | Liveness probe (no token needed) |
| `GET` | `/v1/ready` | Readiness probe (no token needed; 503 until a contract is loaded) |
| `GET` | `/v1/metrics` | Prometheus metrics |

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Server port |
| `CONTRACTS_DIR` | `./contracts` | Directory to load contracts from |
| `AUDIT_DIR` | — | Directory for JSONL audit files; unset keeps the audit log in memory only (warned at start) |
| `AUDIT_HMAC_SECRET` | — | HMAC-SHA256 signing key; blank means unsigned (warned at start) |
| `API_TOKEN` | — | Bearer token clients must send; blank means unauthenticated (warned at start) |
| `MAX_BODY_BYTES` | `1048576` | Largest accepted request body |
| `LOG_LEVEL` | `info` | Logging level (debug, info, warn, error) |

The same settings are available as `serve` flags (`--port`, `--contracts`, `--audit-dir`, `--hmac-secret`, `--api-token`, `--log-level`); a flag overrides its environment variable.

## Docker

The repository's `Dockerfile` builds the image; it reads contracts from `/app/contracts` and writes audit files to `/app/audit`, both configurable through the environment variables above.

```bash
# Build
docker build -t god-clause .

# Run with contracts mounted
docker run -d \
  -p 3000:3000 \
  -v $(pwd)/contracts:/app/contracts \
  -v $(pwd)/audit:/app/audit \
  -e AUDIT_HMAC_SECRET=your-secret-key \
  -e API_TOKEN=your-api-token \
  god-clause
```

`docker-compose.yml` does the same and passes `AUDIT_HMAC_SECRET`, `API_TOKEN` and `LOG_LEVEL` through from your shell.

## Kubernetes

### Helm Chart

```bash
helm install god-clause ./charts/god-clause \
  --set image.tag=latest \
  --set server.existingSecret=god-clause-secrets \
  --set contracts.configMapName=my-contracts
```

`contracts.configMapName` is required: the server answers 503 until a contract is loaded, so a pod without one never becomes ready. `server.existingSecret` names a Secret with keys `hmac-secret` and `api-token` (the key names are `server.existingSecretKey` and `server.apiTokenSecretKey`); if the `api-token` key is missing the pod still starts, unauthenticated, and logs a warning. For a quick test `--set server.hmacSecret=... --set server.apiToken=...` puts the values in the chart instead. The ConfigMap is mounted at `/app/contracts` and audit files go to `audit.dir` (`/data/audit`), backed by a PersistentVolumeClaim when `audit.persistence.enabled` is true — which limits the chart to one replica, since several servers appending to one `audit.jsonl` would fork the hash chain.

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
            - name: API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: god-clause-secrets
                  key: api-token
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
- [ ] Set `API_TOKEN` and keep the server off the public network; only the two probes are unauthenticated
- [ ] Configure persistent audit storage (file sink with mounted volume, or S3/webhook sink)
- [ ] Enable Prometheus metrics scraping on `/v1/metrics`
- [ ] Set up liveness and readiness probes
- [ ] Store contracts in version control (ConfigMap sourced from Git)
- [ ] Create Merkle seal checkpoints on a schedule (e.g., hourly cron)
- [ ] Set up alerting on `godclause_blocks_total` metric
- [ ] Configure log aggregation (structured JSON → ELK/Splunk/Datadog)
- [ ] Test contract changes in staging before activating in production
- [ ] Document incident response for governance violations
