# Contributing to God Clause

We welcome contributions of all kinds — bug fixes, new features, documentation, and trust contract examples.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/god-clause.git
cd god-clause

# Install dependencies
npm install

# Run tests
npm test

# Type check
npx tsc --noEmit

# Build
npm run build
```

## Project Structure

```
src/
  types.ts              # All TypeScript type definitions
  governance.ts         # GodClause orchestrator class
  index.ts              # Public API barrel exports
  contracts/
    schema.ts           # JSON Schema validation (AJV)
    parser.ts           # YAML/JSON parsing + summarization
    registry.ts         # Multi-version contract registry
  engine/
    evaluator.ts        # Rule & condition evaluation logic
    policy-engine.ts    # Policy engine with hooks
    state-store.ts      # StateStore interface + MemoryStateStore
  audit/
    audit-log.ts        # Hash-chained audit log + sinks
    seal.ts             # Merkle tree sealing
    file-sink.ts        # JSONL file sink with rotation
    trace.ts            # TraceBuilder for span correlation
  tenancy/
    tenant.ts           # TenantScope for multi-tenant isolation
  middleware/
    http.ts             # Express/Fastify HTTP middleware
    ai-sdk.ts           # LangChain, Vercel AI SDK adapters
tests/                  # Vitest test suites
examples/               # Example trust contracts
```

## Making Changes

1. **Fork** the repository and create a feature branch
2. **Write tests** for any new functionality
3. **Run the full test suite** before submitting: `npm test`
4. **Type check**: `npx tsc --noEmit` must pass with zero errors
5. **Keep commits focused** — one logical change per commit
6. **Open a PR** with a clear description of what and why

## Code Style

- TypeScript strict mode
- No `any` types unless absolutely necessary (and commented why)
- Prefer interfaces over type aliases for object shapes
- Use `readonly` for arrays/properties that shouldn't be mutated
- Keep dependencies minimal — don't add a package for something Node.js can do natively

## Testing

- We use [Vitest](https://vitest.dev/) for testing
- Tests live in `tests/` with `.test.ts` extension
- Aim for both happy path and edge case coverage
- Test file naming matches the feature: `audit.test.ts`, `engine.test.ts`, etc.

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run a specific test file
npx vitest run tests/audit.test.ts
```

## Adding a New Feature

1. Define types in `src/types.ts`
2. Implement the feature in the appropriate module
3. Export from `src/index.ts`
4. Add tests in `tests/`
5. Update the schema in `src/contracts/schema.ts` if contract format changes
6. Add an example contract in `examples/` if applicable

## Trust Contract Examples

When adding example contracts:
- Use realistic, domain-specific scenarios
- Include a mix of severity levels (block, warn, log, modify)
- Add tags to every rule
- Use composite conditions where they add clarity
- Keep them under 100 lines

## Reporting Issues

- Use GitHub Issues for bugs and feature requests
- Include reproduction steps for bugs
- For security vulnerabilities, email security@god-clause.dev instead of opening a public issue
