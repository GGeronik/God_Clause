import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, unlinkSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { GodClause, ContractWatcher } from "../src";

function contract(name: string, version: string): string {
  return `
schema_version: "1.0"
metadata:
  name: ${name}
  version: "${version}"
  author: Test
  description: Test
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: ${name}-001
    description: Prompt must exist
    action: generate
    conditions:
      - field: input.prompt
        operator: exists
        value: true
    on_violation: block
`;
}

const ctx = {
  action: "generate" as const,
  input: { prompt: "x" },
  caller: { user_id: "u", session_id: "s", roles: [] },
};

describe("Loading the same contract twice", () => {
  it("replaces the earlier copy instead of adding a duplicate", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(contract("A", "1.0.0"));
    gov.loadContractYAML(contract("A", "1.0.0"));

    expect(gov.engine.getContracts()).toHaveLength(1);
    expect((await gov.evaluate(ctx)).evaluations).toHaveLength(1);
  });

  it("replaceContracts swaps the whole set and validates first", () => {
    const gov = new GodClause();
    gov.loadContractYAML(contract("A", "1.0.0"));
    const b = JSON.parse(JSON.stringify(gov.getContracts()[0]));
    b.metadata.name = "B";

    gov.replaceContracts([b]);
    expect(gov.getContracts().map((c) => c.metadata.name)).toEqual(["B"]);

    expect(() => gov.replaceContracts([{ ...b, rules: "nope" }])).toThrow();
    expect(gov.getContracts().map((c) => c.metadata.name)).toEqual(["B"]);
  });

  it("loadContractVersion with activate:false leaves a live version active", () => {
    const gov = new GodClause();
    gov.loadContractYAML(contract("A", "1.0.0"));

    gov.loadContractVersion(contract("A", "1.0.0"), { activate: false });

    expect(gov.getContracts()).toHaveLength(1);
    expect(gov.engine.getContracts()).toHaveLength(1);
  });

  it("a reload landing mid-evaluation does not change what the decision is attributed to", async () => {
    let release!: () => void;
    const store = { recordAndCount: () => new Promise<number>((r) => (release = () => r(1))) };
    const gov = new GodClause({ stateStore: store as any });
    gov.loadContractYAML(
      contract("Old", "1.0.0").replace(
        "operator: exists\n        value: true",
        "operator: rate_limit\n        value: { max: 5, window: PT1H }",
      ),
    );

    const pending = gov.evaluate(ctx);
    const replacement = JSON.parse(JSON.stringify(gov.getContracts()[0]));
    replacement.metadata.name = "New";
    gov.replaceContracts([replacement]);
    release();
    const decision = await pending;

    expect(decision.governance_context?.contract_id).toBe("Old@1.0.0");
    expect(gov.getAuditEntries()[0].contract_name).toBe("Old");
    expect(gov.getContracts().map((c) => c.metadata.name)).toEqual(["New"]);
  });
});

describe("ContractWatcher reload semantics", () => {
  let dir: string;
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("reloading the same file twice does not duplicate rules", async () => {
    dir = mkdtempSync(join(tmpdir(), "gc-watch-"));
    writeFileSync(join(dir, "a.yaml"), contract("A", "1.0.0"));
    const gov = new GodClause();
    const watcher = new ContractWatcher(gov, { dir });

    watcher.reloadAll();
    watcher.reloadAll();

    expect(gov.engine.getContracts()).toHaveLength(1);
    expect((await gov.evaluate(ctx)).evaluations).toHaveLength(1);
  });

  it("a file that changes version retires the version it provided before", () => {
    dir = mkdtempSync(join(tmpdir(), "gc-watch-"));
    const file = join(dir, "a.yaml");
    writeFileSync(file, contract("A", "1.0.0"));
    const gov = new GodClause();
    const watcher = new ContractWatcher(gov, { dir });
    watcher.reloadAll();

    writeFileSync(file, contract("A", "2.0.0"));
    watcher.reloadAll();

    expect(gov.getContracts().map((c) => c.metadata.version)).toEqual(["2.0.0"]);
    expect(gov.engine.getContracts()).toHaveLength(1);
    expect(gov.getContractVersions("A")[0].versions).toEqual(["1.0.0", "2.0.0"]);
  });

  it("a renamed file keeps its contract active whichever event lands first", () => {
    dir = mkdtempSync(join(tmpdir(), "gc-watch-"));
    writeFileSync(join(dir, "a.yaml"), contract("A", "1.0.0"));
    const gov = new GodClause();
    const watcher = new ContractWatcher(gov, { dir });
    watcher.reloadAll();

    writeFileSync(join(dir, "b.yaml"), contract("A", "1.0.0"));
    unlinkSync(join(dir, "a.yaml"));
    watcher.reloadAll();

    expect(gov.getContracts().map((c) => c.metadata.name)).toEqual(["A"]);
    expect(gov.engine.getContracts()).toHaveLength(1);
  });

  it("when two files provide the same contract and one goes away, the other's content is enforced", () => {
    dir = mkdtempSync(join(tmpdir(), "gc-watch-"));
    writeFileSync(join(dir, "a.yaml"), contract("A", "1.0.0"));
    writeFileSync(join(dir, "b.yaml"), contract("A", "1.0.0").replace("on_violation: block", "on_violation: warn"));
    const gov = new GodClause();
    const watcher = new ContractWatcher(gov, { dir });
    watcher.reloadFile("a.yaml");
    watcher.reloadFile("b.yaml");
    expect(gov.engine.getContracts()[0].rules[0].on_violation).toBe("warn");

    unlinkSync(join(dir, "b.yaml"));
    watcher.reloadFile("b.yaml");

    expect(gov.getContracts()).toHaveLength(1);
    expect(gov.engine.getContracts()[0].rules[0].on_violation).toBe("block");
  });

  it("reloadAll on a vanished directory retires everything", () => {
    dir = mkdtempSync(join(tmpdir(), "gc-watch-"));
    writeFileSync(join(dir, "a.yaml"), contract("A", "1.0.0"));
    const gov = new GodClause();
    const watcher = new ContractWatcher(gov, { dir });
    watcher.reloadAll();
    expect(gov.getContracts()).toHaveLength(1);

    rmSync(dir, { recursive: true, force: true });
    watcher.reloadAll();

    expect(gov.getContracts()).toHaveLength(0);
  });

  it("start() twice leaves nothing running after stop()", async () => {
    dir = mkdtempSync(join(tmpdir(), "gc-watch-"));
    const gov = new GodClause();
    const watcher = new ContractWatcher(gov, { dir });
    watcher.start();
    watcher.start();
    watcher.stop();

    writeFileSync(join(dir, "a.yaml"), contract("A", "1.0.0"));
    await new Promise((r) => setTimeout(r, 350));

    expect(gov.getContracts()).toHaveLength(0);
  });

  it("a deleted file retires its contract", () => {
    dir = mkdtempSync(join(tmpdir(), "gc-watch-"));
    writeFileSync(join(dir, "a.yaml"), contract("A", "1.0.0"));
    writeFileSync(join(dir, "b.yaml"), contract("B", "1.0.0"));
    const gov = new GodClause();
    const watcher = new ContractWatcher(gov, { dir });
    watcher.reloadAll();
    expect(gov.getContracts()).toHaveLength(2);

    unlinkSync(join(dir, "a.yaml"));
    watcher.reloadAll();

    expect(gov.getContracts().map((c) => c.metadata.name)).toEqual(["B"]);
  });

  it("a file that turns invalid keeps the last good contract and reports the error", () => {
    dir = mkdtempSync(join(tmpdir(), "gc-watch-"));
    const file = join(dir, "a.yaml");
    writeFileSync(file, contract("A", "1.0.0"));
    const gov = new GodClause();
    const watcher = new ContractWatcher(gov, { dir });
    const errors: string[] = [];
    watcher.onError = (err, f) => errors.push(`${f}: ${err.message}`);
    watcher.reloadAll();

    writeFileSync(file, "rules: [");
    watcher.reloadAll();

    expect(gov.getContracts().map((c) => c.metadata.version)).toEqual(["1.0.0"]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/^a\.yaml: /);
  });
});
