/// <reference lib="ES2022" />

import { performance } from "perf_hooks";
import {
  WasmSandboxOptions,
  WasmResourceUsage,
  ObligationResult,
  PolicyContext,
  ViolatedCondition,
} from "../types";
import { ConditionResult } from "../engine/evaluator";

/* eslint-disable @typescript-eslint/no-explicit-any */
// WebAssembly is a global in Node.js but TypeScript's ES2022 lib doesn't
// include its type definitions. We declare the subset we need here.
declare const WebAssembly: {
  Module: { new (bytes: Uint8Array): any };
  Instance: { new (module: any, imports?: any): { exports: Record<string, any> } };
  Memory: { new (descriptor: { initial: number; maximum?: number }): WebAssemblyMemory };
};

interface WebAssemblyMemory {
  buffer: ArrayBuffer;
  grow(pages: number): number;
}

// ─── Internal Types ──────────────────────────────────────────────────

interface LoadedModule {
  id: string;
  instance: { exports: Record<string, any> };
  memory: WebAssemblyMemory;
  usage: WasmResourceUsage;
  context?: PolicyContext;
  violations: ViolatedCondition[];
}

// ─── WASM Binary Helpers ─────────────────────────────────────────────

/** WASM magic number and version header */
const WASM_HEADER = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

/**
 * Encode an unsigned integer as a LEB128 byte sequence.
 */
function leb128(value: number): number[] {
  const result: number[] = [];
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value !== 0) byte |= 0x80;
    result.push(byte);
  } while (value !== 0);
  return result;
}

/**
 * Build a WASM section: section id byte, then LEB128 length, then content.
 */
function section(id: number, content: number[]): number[] {
  return [id, ...leb128(content.length), ...content];
}

/**
 * Create a minimal valid WASM module that exports an `evaluate` function returning 0 (pass)
 * and an `execute_obligation` function returning 1 (success).
 * Also imports a linear memory from env.memory.
 */
export function createMinimalWasmModule(): Uint8Array {
  // Type section: two function types
  //   type 0: (i32) -> i32   (for evaluate)
  //   type 1: () -> i32      (for execute_obligation)
  const typeSection = section(0x01, [
    2,                          // 2 types
    0x60, 1, 0x7f, 1, 0x7f,    // type 0: (i32) -> (i32)
    0x60, 0, 1, 0x7f,           // type 1: () -> (i32)
  ]);

  // Import section: import memory from env
  const memImportName = [0x06, ...strBytes("memory")]; // "memory"
  const envName = [0x03, ...strBytes("env")];          // "env"
  const importSection = section(0x02, [
    1,                          // 1 import
    ...envName,
    ...memImportName,
    0x02, 0x00, 0x01,           // memory, limits: min=0, max not specified (flags=0, initial=1)
  ]);

  // Function section: 2 functions
  const funcSection = section(0x03, [
    2,     // 2 functions
    0x00,  // function 0 uses type 0
    0x01,  // function 1 uses type 1
  ]);

  // Export section: export both functions
  const evalExport = [...strBytes("evaluate"), 0x00, 0x00]; // func index 0
  const obligExport = [...strBytes("execute_obligation"), 0x00, 0x01]; // func index 1
  const exportSection = section(0x07, [
    2,
    0x08, ...evalExport,
    0x12, ...obligExport,
  ]);

  // Code section: 2 function bodies
  // Function 0 (evaluate): return 0 (i32.const 0; end)
  const body0 = [0x00, 0x41, 0x00, 0x0b]; // no locals, i32.const 0, end
  // Function 1 (execute_obligation): return 1 (i32.const 1; end)
  const body1 = [0x00, 0x41, 0x01, 0x0b]; // no locals, i32.const 1, end
  const codeSection = section(0x0a, [
    2,
    ...leb128(body0.length), ...body0,
    ...leb128(body1.length), ...body1,
  ]);

  const bytes = [
    ...WASM_HEADER,
    ...typeSection,
    ...importSection,
    ...funcSection,
    ...exportSection,
    ...codeSection,
  ];

  return new Uint8Array(bytes);
}

/**
 * Create a WASM module that exports an `evaluate` function returning 1 (fail)
 * and `execute_obligation` returning 0 (failure).
 */
export function createFailingWasmModule(): Uint8Array {
  const typeSection = section(0x01, [
    2,
    0x60, 1, 0x7f, 1, 0x7f,    // type 0: (i32) -> (i32)
    0x60, 0, 1, 0x7f,           // type 1: () -> (i32)
  ]);

  const envName = [0x03, ...strBytes("env")];
  const memImportName = [0x06, ...strBytes("memory")];
  const importSection = section(0x02, [
    1,
    ...envName,
    ...memImportName,
    0x02, 0x00, 0x01,
  ]);

  const funcSection = section(0x03, [
    2,
    0x00,
    0x01,
  ]);

  const evalExport = [...strBytes("evaluate"), 0x00, 0x00];
  const obligExport = [...strBytes("execute_obligation"), 0x00, 0x01];
  const exportSection = section(0x07, [
    2,
    0x08, ...evalExport,
    0x12, ...obligExport,
  ]);

  // Function 0: return 1 (fail)
  const body0 = [0x00, 0x41, 0x01, 0x0b];
  // Function 1: return 0 (obligation failure)
  const body1 = [0x00, 0x41, 0x00, 0x0b];
  const codeSection = section(0x0a, [
    2,
    ...leb128(body0.length), ...body0,
    ...leb128(body1.length), ...body1,
  ]);

  return new Uint8Array([
    ...WASM_HEADER,
    ...typeSection,
    ...importSection,
    ...funcSection,
    ...exportSection,
    ...codeSection,
  ]);
}

/**
 * Create a WASM module that tries to grow memory beyond limits.
 * Exports a `grow_memory` function that attempts to grow by `pages` pages.
 */
export function createMemoryHogModule(pages: number): Uint8Array {
  const typeSection = section(0x01, [
    2,
    0x60, 1, 0x7f, 1, 0x7f,    // type 0: (i32) -> (i32) for evaluate
    0x60, 0, 1, 0x7f,           // type 1: () -> (i32) for grow_memory
  ]);

  const envName = [0x03, ...strBytes("env")];
  const memImportName = [0x06, ...strBytes("memory")];
  const importSection = section(0x02, [
    1,
    ...envName,
    ...memImportName,
    0x02, 0x00, 0x01,
  ]);

  const funcSection = section(0x03, [
    2,
    0x00,
    0x01,
  ]);

  const evalExport = [...strBytes("evaluate"), 0x00, 0x00];
  const growExport = [...strBytes("grow_memory"), 0x00, 0x01];
  const exportSection = section(0x07, [
    2,
    0x08, ...evalExport,
    0x0b, ...growExport,
  ]);

  // evaluate: return 0
  const body0 = [0x00, 0x41, 0x00, 0x0b];
  // grow_memory: memory.grow(pages), return result (-1 on failure)
  const pagesLeb = leb128(pages);
  const body1Instructions = [
    0x00,           // no locals
    0x41, ...pagesLeb, // i32.const pages
    0x40, 0x00,     // memory.grow 0
    0x0b,           // end
  ];
  const codeSection = section(0x0a, [
    2,
    ...leb128(body0.length), ...body0,
    ...leb128(body1Instructions.length), ...body1Instructions,
  ]);

  return new Uint8Array([
    ...WASM_HEADER,
    ...typeSection,
    ...importSection,
    ...funcSection,
    ...exportSection,
    ...codeSection,
  ]);
}

/** Convert a string to UTF-8 bytes (ASCII subset). */
function strBytes(s: string): number[] {
  return Array.from(s).map((c) => c.charCodeAt(0));
}

// ─── WasmPolicySandbox ──────────────────────────────────────────────

export class WasmPolicySandbox {
  private modules = new Map<string, LoadedModule>();
  private opts: Required<WasmSandboxOptions>;
  private nextId = 0;

  constructor(opts?: WasmSandboxOptions) {
    this.opts = {
      maxMemoryPages: opts?.maxMemoryPages ?? 256,
      executionTimeoutMs: opts?.executionTimeoutMs ?? 5000,
      maxModules: opts?.maxModules ?? 32,
    };
  }

  /**
   * Load a WASM module into the sandbox. Returns a module ID.
   * The module must export an `evaluate(ctxPtr: i32) -> i32` function.
   */
  loadModule(wasmBytes: Uint8Array): string {
    if (this.modules.size >= this.opts.maxModules) {
      throw new Error(
        `Maximum module limit reached (${this.opts.maxModules}). Unload a module first.`,
      );
    }

    const id = `wasm_module_${this.nextId++}`;

    // Create sandboxed memory with limits
    const memory = new WebAssembly.Memory({
      initial: 1,
      maximum: this.opts.maxMemoryPages,
    });

    // Build import object with safe host functions
    const mod: Partial<LoadedModule> = {
      id,
      memory,
      violations: [],
      usage: { memoryBytes: 0, executionCount: 0, lastExecutionMs: 0 },
    };

    const importObject: Record<string, Record<string, any>> = {
      env: {
        memory,
        log: (_ptr: number, _len: number) => {
          // Safe no-op log function — could be wired to a logger
        },
        get_field: (_ptr: number, _len: number): number => {
          // Returns 0 — in a full implementation would read from frozen context
          return 0;
        },
        report_violation: (
          _fieldPtr: number,
          _fieldLen: number,
          _msgPtr: number,
          _msgLen: number,
        ) => {
          // Collect a violation during evaluation
          const loaded = this.modules.get(id);
          if (loaded) {
            loaded.violations.push({
              field: "wasm_reported",
              operator: "equals",
              expected: "pass",
              actual: "fail",
            });
          }
        },
      },
    };

    let compiled: any;
    try {
      compiled = new WebAssembly.Module(wasmBytes);
    } catch (err) {
      throw new Error(
        `Failed to compile WASM module: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    let instance: { exports: Record<string, any> };
    try {
      instance = new WebAssembly.Instance(compiled, importObject);
    } catch (err) {
      throw new Error(
        `Failed to instantiate WASM module: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    const loaded: LoadedModule = {
      id,
      instance,
      memory,
      usage: {
        memoryBytes: memory.buffer.byteLength,
        executionCount: 0,
        lastExecutionMs: 0,
      },
      violations: [],
    };

    this.modules.set(id, loaded);
    return id;
  }

  /**
   * Evaluate a condition using a loaded WASM module.
   * The WASM module's `evaluate` export should return 0 for pass, non-zero for fail.
   */
  async evaluate(
    moduleId: string,
    context: PolicyContext,
  ): Promise<ConditionResult> {
    const mod = this.getModule(moduleId);

    // Freeze the context to prevent mutation during evaluation
    const frozenContext = Object.freeze({ ...context });
    mod.context = frozenContext;
    mod.violations = [];

    const evaluateFn = mod.instance.exports.evaluate as
      | ((ctxPtr: number) => number)
      | undefined;
    if (typeof evaluateFn !== "function") {
      throw new Error(
        `Module ${moduleId} does not export an 'evaluate' function.`,
      );
    }

    const start = performance.now();

    // Execute with timeout via Promise.race
    const result = await Promise.race([
      new Promise<number>((resolve) => {
        resolve(evaluateFn(0));
      }),
      new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error("WASM execution timed out")),
          this.opts.executionTimeoutMs,
        ),
      ),
    ]);

    const elapsed = performance.now() - start;

    // Update usage stats
    mod.usage.executionCount++;
    mod.usage.lastExecutionMs = elapsed;
    mod.usage.memoryBytes = mod.memory.buffer.byteLength;

    // Clear context reference
    mod.context = undefined;

    const passed = result === 0;

    if (!passed && mod.violations.length === 0) {
      // The WASM module signaled failure but didn't report specific violations
      mod.violations.push({
        field: "wasm_evaluate",
        operator: "equals",
        expected: 0,
        actual: result,
      });
    }

    const violations = passed ? [] : [...mod.violations];
    mod.violations = [];

    return { passed, violations };
  }

  /**
   * Execute an obligation handler in the WASM sandbox.
   */
  async executeObligation(
    moduleId: string,
    params: Record<string, unknown>,
  ): Promise<ObligationResult> {
    const mod = this.getModule(moduleId);

    const executeFn = mod.instance.exports.execute_obligation as
      | (() => number)
      | undefined;
    if (typeof executeFn !== "function") {
      return {
        success: false,
        error: `Module ${moduleId} does not export an 'execute_obligation' function.`,
      };
    }

    const start = performance.now();

    try {
      const result = await Promise.race([
        new Promise<number>((resolve) => {
          resolve(executeFn());
        }),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error("WASM obligation execution timed out")),
            this.opts.executionTimeoutMs,
          ),
        ),
      ]);

      const elapsed = performance.now() - start;
      mod.usage.executionCount++;
      mod.usage.lastExecutionMs = elapsed;
      mod.usage.memoryBytes = mod.memory.buffer.byteLength;

      const success = result !== 0;
      return {
        success,
        modifications: success ? {} : undefined,
        error: success ? undefined : "Obligation handler returned failure code",
      };
    } catch (err) {
      return {
        success: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Unload a module from the sandbox, freeing resources.
   */
  unloadModule(moduleId: string): void {
    if (!this.modules.has(moduleId)) {
      throw new Error(`Module ${moduleId} not found.`);
    }
    this.modules.delete(moduleId);
  }

  /**
   * Get resource usage statistics for a loaded module.
   */
  getResourceUsage(moduleId: string): WasmResourceUsage {
    const mod = this.getModule(moduleId);
    // Refresh memory measurement
    mod.usage.memoryBytes = mod.memory.buffer.byteLength;
    return { ...mod.usage };
  }

  /**
   * Get the number of currently loaded modules.
   */
  getModuleCount(): number {
    return this.modules.size;
  }

  // ─── Private Helpers ──────────────────────────────────────────────

  private getModule(moduleId: string): LoadedModule {
    const mod = this.modules.get(moduleId);
    if (!mod) {
      throw new Error(`Module ${moduleId} not found.`);
    }
    return mod;
  }
}
