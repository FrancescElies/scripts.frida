/// Frida Toolkit

/// <reference types="frida-gum" />

// ============================================================================
// TYPES
// ============================================================================

type MemoryReadType =
  "string" | "cstring" | "int" | "uint" | "long" | "ulong" | "bytes" | "hex";
type MemoryWriteType = "string" | "cstring" | "int" | "uint" | "long" | "bytes";

interface HookCallbacks {
  onEnter?: (this: InvocationContext, args: InvocationArguments) => void;
  onLeave?: (this: InvocationContext, retval: InvocationReturnValue) => void;
  logArgs?: boolean;
  logReturn?: boolean;
}

interface ModuleInfo {
  name: string;
  base: string;
  size: number;
  path: string;
  end: string;
}

interface ProcessInfo {
  pid: number;
  arch: string;
  pageSize: number;
  platform: string;
}

interface AllocationInfo {
  size: number;
  timestamp: number;
  type: string;
}

interface PerfStats {
  calls: number;
  times: number[];
  totalTime: number;
}

interface TraceEntry {
  time: number;
  args: string[];
  backtrace: string[];
}

interface Modification {
  type: string;
  value: any;
}

interface ApiCall {
  id: number;
  name: string;
  time: number;
  args: string[];
}

interface Detection {
  pattern: string;
  data: string;
  time: number;
}

// ============================================================================
// UTILITIES MODULE
// ============================================================================

const U = {
  /** Find a function by export name. */
  findFunc(fnName: string): NativePointer | null {
    return Module.findGlobalExportByName(fnName);
  },

  /** Read memory as different types. */
  readMem(
    addr: NativePointer | string,
    type: MemoryReadType = "string",
    size = 256,
  ): any {
    try {
      const pointer = typeof addr === "string" ? ptr(addr) : addr;

      switch (type) {
        case "string":
          return pointer.readUtf8String();
        case "cstring":
          return pointer.readCString();
        case "int":
          return pointer.readS32();
        case "uint":
          return pointer.readU32();
        case "long":
          return pointer.readS64();
        case "ulong":
          return pointer.readU64();
        case "bytes":
          return pointer.readByteArray(size);
        case "hex":
        default:
          return hexdump(pointer, { length: size });
      }
    } catch (e: any) {
      console.log(`[!] Error reading memory: ${e.message}`);
      return null;
    }
  },

  /** Write memory. */
  writeMem(
    addr: NativePointer | string,
    value: any,
    type: MemoryWriteType = "int",
  ): void {
    try {
      const pointer = typeof addr === "string" ? ptr(addr) : addr;

      switch (type) {
        case "string":
        case "cstring":
          pointer.writeUtf8String(value);
          break;
        case "int":
          pointer.writeS32(value);
          break;
        case "uint":
          pointer.writeU32(value);
          break;
        case "long":
          pointer.writeS64(value);
          break;
        case "bytes":
          pointer.writeByteArray(value);
          break;
        default:
          console.log("[!] Unknown type:", type);
          return;
      }

      console.log(`[+] Wrote ${type} at ${pointer}`);
    } catch (e: any) {
      console.log(`[!] Error writing memory: ${e.message}`);
    }
  },

  /** Allocate memory and write data. */
  allocate(
    value: any,
    type: "string" | "cstring" | "int" | "bytes" = "string",
  ): NativePointer | null {
    try {
      if (type === "string" || type === "cstring") {
        return Memory.allocUtf8String(value);
      }

      if (type === "int") {
        const buf = Memory.alloc(4);
        buf.writeS32(value);
        return buf;
      }

      if (type === "bytes") {
        const buf = Memory.alloc(value.length);
        buf.writeByteArray(value);
        return buf;
      }

      return null;
    } catch (e: any) {
      console.log(`[!] Allocation error: ${e.message}`);
      return null;
    }
  },

  /** Dump memory as hex. */
  hexDump(addr: NativePointer | string, size = 256): void {
    const pointer = typeof addr === "string" ? ptr(addr) : addr;
    console.log(hexdump(pointer, { length: size }));
  },

  /** Search loaded modules using a Frida Memory.scan pattern. */
  findString(search: string): NativePointer[] {
    const results: NativePointer[] = [];

    Process.enumerateModules().forEach((mod) => {
      try {
        Memory.scan(mod.base, mod.size, search, {
          onMatch(address) {
            results.push(address);
            return "continue" as any;
          },
          onComplete() {},
        });
      } catch (_) {
        // Skip unreadable regions.
      }
    });

    return results;
  },

  /** Search loaded modules for a hex pattern. */
  findPattern(pattern: string): NativePointer[] {
    const results: NativePointer[] = [];

    Process.enumerateModules().forEach((mod) => {
      try {
        Memory.scan(mod.base, mod.size, pattern, {
          onMatch(address) {
            results.push(address);
            return "continue" as any;
          },
          onComplete() {},
        });
      } catch (_) {
        // Skip unreadable regions.
      }
    });

    return results;
  },

  /** Get module information. */
  moduleInfo(name: string): ModuleInfo | null {
    try {
      const mod = Process.getModuleByName(name);
      return {
        name: mod.name,
        base: mod.base.toString(),
        size: mod.size,
        path: mod.path,
        end: mod.base.add(mod.size).toString(),
      };
    } catch (e: any) {
      console.log(`[!] Module not found: ${name}`);
      return null;
    }
  },

  /** List all loaded modules. */
  listModules(): Array<{
    name: string;
    base: string;
    size: number;
    path: string;
  }> {
    return Process.enumerateModules().map((m) => ({
      name: m.name,
      base: m.base.toString(),
      size: m.size,
      path: m.path,
    }));
  },

  /** List exported functions from a module. */
  listFunctions(moduleName = "libc.so"): string[] {
    try {
      const mod = Process.getModuleByName(moduleName);
      return mod
        .enumerateExports()
        .filter((e) => e.type === "function")
        .map((e) => e.name);
    } catch (e: any) {
      console.log(`[!] Error listing functions: ${e.message}`);
      return [];
    }
  },

  /** Call a native function directly. */
  callNative(
    fnName: string,
    returnType: NativeFunctionReturnType = "int",
    argTypes: NativeFunctionArgumentType[] = [],
    args: any[] = [],
  ): any {
    try {
      const addr = this.findFunc(fnName);
      if (!addr) return null;

      const fn = new NativeFunction(addr, returnType, argTypes);

      // @ts-ignore
      const result = fn(...args);
      console.log(`[+] ${fnName}() returned: ${result}`);
      return result;
    } catch (e: any) {
      console.log(`[!] Error calling native function: ${e.message}`);
      return null;
    }
  },

  /** Get process information. */
  processInfo(): ProcessInfo {
    return {
      pid: Process.id,
      arch: Process.arch,
      pageSize: Process.pageSize,
      platform: Process.platform,
    };
  },

  /** Convenience alias matching the original utility template example. */
  hook(fnName: string, callbacks: HookCallbacks = {}): NativePointer | null {
    return H.hook(fnName, callbacks);
  },
};

// ============================================================================
// HOOKING MODULE
// ============================================================================

const H = {
  hooks: new Map<string, InvocationListener>(),
  mallocAllocations: new Map<string, { size: number; timestamp: number }>(),

  /** Generic hook function. */
  hook(fnName: string, callbacks: HookCallbacks = {}): NativePointer | null {
    try {
      const addr = U.findFunc(fnName);
      if (!addr) return null;

      if (this.hooks.has(fnName)) {
        console.log(`[!] Already hooked: ${fnName}`);
        return addr;
      }

      const logArgs = callbacks.logArgs !== false;
      const logReturn = callbacks.logReturn !== false;

      const listener = Interceptor.attach(addr, {
        onEnter(args) {
          if (logArgs) {
            const argStr = Array.from(
              { length: 6 },
              (_, i) => args[i]?.toString() ?? "null",
            ).join(", ");
            console.log(`[>] ${fnName}(${argStr})`);
          }

          callbacks.onEnter?.call(this, args);
        },
        onLeave(retval) {
          if (logReturn) {
            console.log(`[<] ${fnName} => ${retval}`);
          }

          callbacks.onLeave?.call(this, retval);
        },
      });

      this.hooks.set(fnName, listener);
      console.log(`[+] Hooked: ${fnName}`);
      return addr;
    } catch (e: any) {
      console.log(`[!] Hook error: ${e.message}`);
      return null;
    }
  },

  /** Hook malloc and expose mallocTracker. */
  hookMalloc(verbose = true): void {
    this.mallocAllocations.clear();

    this.hook("malloc", {
      logArgs: verbose,
      logReturn: verbose,
      onEnter(args) {
        (this as any).size = args[0].toInt32();
      },
      onLeave(retval) {
        const size = (this as any).size;
        if (size) {
          H.mallocAllocations.set(retval.toString(), {
            size,
            timestamp: Date.now(),
          });
        }
      },
    });

    (globalThis as any).mallocTracker = {
      count: () => H.mallocAllocations.size,
      total: () =>
        Array.from(H.mallocAllocations.values()).reduce(
          (sum, a) => sum + a.size,
          0,
        ),
      list: () =>
        Array.from(H.mallocAllocations.entries()).map(([addr, info]) => ({
          address: addr,
          size: info.size,
          age: Date.now() - info.timestamp,
        })),
    };

    console.log("[+] malloc tracker available as: mallocTracker");
  },

  /** Hook free. */
  hookFree(verbose = true): void {
    this.hook("free", {
      logArgs: verbose,
      logReturn: false,
      onEnter(args) {
        const address = args[0].toString();
        H.mallocAllocations.delete(address);
        if (verbose) console.log(`  freeing: ${args[0]}`);
      },
    });
  },

  /** Hook read/write. */
  hookIO(): void {
    this.hook("read", {
      logArgs: false,
      logReturn: false,
      onEnter(args) {
        console.log(`[READ] fd=${args[0]}, size=${args[2]}`);
      },
    });

    this.hook("write", {
      logArgs: false,
      logReturn: false,
      onEnter(args) {
        console.log(`[WRITE] fd=${args[0]}, size=${args[2]}`);
      },
    });

    console.log("[+] IO hooks installed");
  },

  /** Hook common string operations. */
  hookStringOps(): void {
    ["strlen", "strcpy", "strcat", "strcmp"].forEach((fn) =>
      this.hook(fn, { logReturn: false }),
    );
    console.log("[+] String operation hooks installed");
  },

  /** Hook multiple functions. */
  hookMultiple(names: string[], callbacks: HookCallbacks = {}): void {
    names.forEach((name) => this.hook(name, callbacks));
  },

  /** Unhook one function without touching unrelated listeners. */
  unhook(fnName: string): void {
    const listener = this.hooks.get(fnName);
    if (!listener) return;

    listener.detach();
    this.hooks.delete(fnName);
    console.log(`[+] Unhooked: ${fnName}`);
  },

  /** Unhook all hooks managed by H. */
  unhookAll(): void {
    this.hooks.forEach((listener) => listener.detach());
    this.hooks.clear();
    console.log("[+] H hooks removed");
  },

  /** List active hooks. */
  listHooks(): string[] {
    return Array.from(this.hooks.keys());
  },

  /** Compatibility alias; replacement logic is centralized in C. */
  replaceReturn(
    fnName: string,
    returnValue: any,
    returnType: NativeCallbackReturnType = "int",
  ): void {
    C.forceReturn(fnName, returnValue, returnType);
  },
};

// ============================================================================
// ANALYSIS MODULE
// ============================================================================

const A = {
  allocations: new Map<string, AllocationInfo>(),
  frees: new Map<string, number>(),
  memoryStats: {
    totalAllocated: 0,
    totalFreed: 0,
  },
  memoryListeners: [] as InvocationListener[],
  suspectAfterMs: 5000,

  performance: new Map<string, PerfStats>(),
  profilerListeners: new Map<string, InvocationListener>(),

  resetMemoryTracking(): void {
    this.allocations.clear();
    this.frees.clear();
    this.memoryStats.totalAllocated = 0;
    this.memoryStats.totalFreed = 0;
  },

  /** Start continuous malloc/free tracking. */
  startMemoryTracking(suspectAfterMs = 5000): void {
    if (this.memoryListeners.length > 0) {
      console.log("[!] Memory tracking already active");
      return;
    }

    const mallocAddr = U.findFunc("malloc");
    const freeAddr = U.findFunc("free");

    if (!mallocAddr || !freeAddr) {
      console.log("[!] malloc/free not found");
      return;
    }

    this.resetMemoryTracking();
    this.suspectAfterMs = suspectAfterMs;

    const mallocListener = Interceptor.attach(mallocAddr, {
      onEnter(args) {
        (this as any).size = args[0].toInt32();
      },
      onLeave(retval) {
        const size = (this as any).size;
        const addr = retval.toString();

        A.allocations.set(addr, {
          size,
          timestamp: Date.now(),
          type: "malloc",
        });
        A.memoryStats.totalAllocated += size;
      },
    });

    const freeListener = Interceptor.attach(freeAddr, {
      onEnter(args) {
        const addr = args[0].toString();
        const alloc = A.allocations.get(addr);

        if (alloc) {
          A.memoryStats.totalFreed += alloc.size;
          A.allocations.delete(addr);
        }

        A.frees.set(addr, Date.now());
      },
    });

    this.memoryListeners.push(mallocListener, freeListener);
    console.log(
      `[+] Memory tracking started (suspect after ${suspectAfterMs} ms)`,
    );
  },

  /** Print the current memory/leak report. */
  memoryReport(): void {
    const leaks = Array.from(A.allocations.values()) as AllocationInfo[];
    const now = Date.now();
    const suspectedLeaks = leaks.filter(
      (l) => now - l.timestamp > A.suspectAfterMs,
    );

    console.log("\n=== MEMORY LEAK REPORT ===");
    console.log(
      `Total Allocated        : ${(this.memoryStats.totalAllocated / 1024 / 1024).toFixed(2)} MB`,
    );
    console.log(
      `Total Freed            : ${(this.memoryStats.totalFreed / 1024 / 1024).toFixed(2)} MB`,
    );
    console.log(
      `Current Usage          : ${((this.memoryStats.totalAllocated - this.memoryStats.totalFreed) / 1024 / 1024).toFixed(2)} MB`,
    );
    console.log(`Unreleased Blocks      : ${leaks.length}`);
    console.log(`Suspected Leaks        : ${suspectedLeaks.length}`);

    const bySize: Record<number, number> = {};
    suspectedLeaks.forEach((leak) => {
      bySize[leak.size] = (bySize[leak.size] || 0) + 1;
    });

    if (suspectedLeaks.length > 0) {
      console.log("\nLeak patterns:");
      Object.entries(bySize)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .forEach(([size, count]) => {
          const total = Number(size) * count;
          console.log(
            `  ${count}x ${size} bytes (${(total / 1024).toFixed(2)} KB)`,
          );
        });
    }
  },

  /** Stop only the memory listeners owned by A. */
  stopMemoryTracking(): void {
    this.memoryListeners.forEach((listener) => listener.detach());
    this.memoryListeners = [];
    console.log("[+] Memory tracking stopped");
  },

  /** Analyze allocations for a fixed duration, then print a report. */
  analyzeMemory(duration = 10): void {
    this.startMemoryTracking(duration * 1000 + 1);
    if (this.memoryListeners.length === 0) return;

    console.log(`[*] Analyzing memory for ${duration} seconds...`);
    const startTime = Date.now();

    const interval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const current =
        this.memoryStats.totalAllocated - this.memoryStats.totalFreed;
      const progress = Math.min(
        100,
        Math.round((elapsed / (duration * 1000)) * 100),
      );
      console.log(
        `[${progress}%] Allocs: ${this.allocations.size}, Current: ${(current / 1024 / 1024).toFixed(2)}MB`,
      );
    }, 1000);

    setTimeout(() => {
      clearInterval(interval);
      this.memoryReport();
      this.stopMemoryTracking();
    }, duration * 1000);
  },

  /** Begin profiling a function until explicitly stopped. */
  profile(functionName: string): void {
    if (this.profilerListeners.has(functionName)) {
      console.log(`[!] Already profiling: ${functionName}`);
      return;
    }

    const addr = U.findFunc(functionName);
    if (!addr) return;

    if (!this.performance.has(functionName)) {
      this.performance.set(functionName, { calls: 0, times: [], totalTime: 0 });
    }

    const listener = Interceptor.attach(addr, {
      onEnter() {
        (this as any).startTime = Date.now();
      },
      onLeave() {
        const duration = Date.now() - (this as any).startTime;
        const stats = A.performance.get(functionName)!;
        stats.calls++;
        stats.times.push(duration);
        stats.totalTime += duration;
      },
    });

    this.profilerListeners.set(functionName, listener);
    console.log(`[+] Profiling ${functionName}`);
  },

  /** Profile until sampleCount calls are collected, then auto-report and detach. */
  profileFunction(fnName: string, sampleCount = 100): void {
    if (this.profilerListeners.has(fnName)) {
      console.log(`[!] Already profiling: ${fnName}`);
      return;
    }

    const addr = U.findFunc(fnName);
    if (!addr) return;

    this.performance.set(fnName, { calls: 0, times: [], totalTime: 0 });

    const listener = Interceptor.attach(addr, {
      onEnter() {
        (this as any).startTime = Date.now();
      },
      onLeave() {
        const duration = Date.now() - (this as any).startTime;
        const stats = A.performance.get(fnName)!;
        stats.calls++;
        stats.times.push(duration);
        stats.totalTime += duration;

        if (stats.calls >= sampleCount) {
          listener.detach();
          A.profilerListeners.delete(fnName);
          A.reportPerformance(fnName);
        }
      },
    });

    this.profilerListeners.set(fnName, listener);
    console.log(
      `[*] Profiling ${fnName}... (collecting ${sampleCount} samples)`,
    );
  },

  profileMultiple(functionNames: string[]): void {
    functionNames.forEach((fn) => this.profile(fn));
  },

  stopProfiling(functionName: string | null = null): void {
    if (functionName) {
      const listener = this.profilerListeners.get(functionName);
      listener?.detach();
      this.profilerListeners.delete(functionName);
      return;
    }

    this.profilerListeners.forEach((listener) => listener.detach());
    this.profilerListeners.clear();
  },

  reportPerformance(functionName: string | null = null): void {
    console.log("\n=== PERFORMANCE REPORT ===\n");

    const names = functionName
      ? [functionName]
      : Array.from(this.performance.keys());

    names.forEach((fn) => {
      const stats = this.performance.get(fn);
      if (!stats || stats.calls === 0) return;

      const times = [...stats.times].sort((a, b) => a - b);
      const avg = stats.totalTime / stats.calls;
      const median = times[Math.floor(times.length / 2)];
      const min = times[0];
      const max = times[times.length - 1];

      console.log(`${fn}:`);
      console.log(`  Calls      : ${stats.calls}`);
      console.log(`  Total Time : ${stats.totalTime} ms`);
      console.log(`  Average    : ${avg.toFixed(2)} ms`);
      console.log(`  Median     : ${median} ms`);
      console.log(`  Min / Max  : ${min} ms / ${max} ms`);
      console.log();
    });
  },

  slowest(count = 5): void {
    const sorted = Array.from(this.performance.entries()).sort((a, b) => {
      const avgA = a[1].calls ? a[1].totalTime / a[1].calls : 0;
      const avgB = b[1].calls ? b[1].totalTime / b[1].calls : 0;
      return avgB - avgA;
    });

    console.log(`\n=== TOP ${count} SLOWEST FUNCTIONS ===\n`);
    sorted.slice(0, count).forEach(([fn, stats]) => {
      const avg = stats.calls ? stats.totalTime / stats.calls : 0;
      console.log(`${fn}: ${avg.toFixed(2)} ms avg (${stats.calls} calls)`);
    });
  },
};

// ============================================================================
// DEBUGGING MODULE
// ============================================================================

const D = {
  traces: {} as Record<string, TraceEntry[]>,
  traceListeners: new Map<string, InvocationListener>(),

  /** Trace calls, capture arguments/backtraces, and optionally stop after N calls. */
  traceFunction(fnName: string, maxCalls = 10, depth = 6): void {
    if (this.traceListeners.has(fnName)) {
      console.log(`[!] Already tracing: ${fnName}`);
      return;
    }

    const addr = U.findFunc(fnName);
    if (!addr) return;

    let count = 0;
    this.traces[fnName] = this.traces[fnName] || [];

    const listener = Interceptor.attach(addr, {
      onEnter(args) {
        if (maxCalls > 0 && count >= maxCalls) {
          listener.detach();
          D.traceListeners.delete(fnName);
          console.log(`[*] Max traces (${maxCalls}) reached, stopping`);
          return;
        }

        count++;
        const argList: string[] = [];

        console.log(`\n[TRACE #${count}] ${fnName}`);
        console.log(`  Address: ${addr}`);
        console.log("  Args:");

        for (let i = 0; i < 4; i++) {
          try {
            const arg = args[i];
            argList.push(arg.toString());
            console.log(`    [${i}]: ${arg}`);

            try {
              const str = arg.readCString();
              if (str && str.length > 0 && str.length < 200) {
                console.log(`         → "${str}"`);
              }
            } catch (_) {}
          } catch (_) {
            break;
          }
        }

        const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
        const symbols = bt
          .slice(0, depth)
          .map((a) => DebugSymbol.fromAddress(a).toString());

        D.traces[fnName].push({
          time: Date.now(),
          args: argList,
          backtrace: symbols,
        });

        console.log("  Backtrace:");
        symbols.forEach((symbol, i) => console.log(`    [${i}] ${symbol}`));
      },
    });

    this.traceListeners.set(fnName, listener);
    console.log(
      `[+] Tracing ${fnName}${maxCalls > 0 ? ` (max ${maxCalls} calls)` : ""}`,
    );
  },

  /** Alias matching the example script's FunctionTracer.trace(). */
  trace(functionName: string, depth = 5): void {
    this.traceFunction(functionName, 0, depth);
  },

  stopTrace(functionName: string | null = null): void {
    if (functionName) {
      const listener = this.traceListeners.get(functionName);
      listener?.detach();
      this.traceListeners.delete(functionName);
      return;
    }

    this.traceListeners.forEach((listener) => listener.detach());
    this.traceListeners.clear();
  },

  traceSummary(): void {
    console.log("\n=== TRACE SUMMARY ===");
    (Object.entries(D.traces) as Array<[string, TraceEntry[]]>).forEach(
      ([fn, calls]) => {
        console.log(`${fn}: ${calls.length} calls`);
      },
    );
  },

  clearTraces(functionName: string | null = null): void {
    if (functionName) delete this.traces[functionName];
    else this.traces = {};
  },

  /** Get thread information. */
  getThreads(): Array<{ id: number; state: string; pc?: string; sp?: string }> {
    return Process.enumerateThreads().map((t) => ({
      id: t.id,
      state: t.state,
      pc: t.context.pc?.toString(),
      sp: t.context.sp?.toString(),
    }));
  },

  /** Show symbol at address. */
  symbolAt(addr: NativePointer | string): DebugSymbol {
    const pointer = typeof addr === "string" ? ptr(addr) : addr;
    const sym = DebugSymbol.fromAddress(pointer);
    console.log(sym.toString());
    return sym;
  },
};

// ============================================================================
// INTERCEPTION / BEHAVIOR MODULE
// ============================================================================

const C = {
  modifications: new Map<string, Modification>(),
  listeners: new Map<string, InvocationListener>(),
  replacements: new Map<string, NativePointer>(),

  /** Intercept a function and modify its arguments. */
  intercept(
    fnName: string,
    modifier: (this: InvocationContext, args: InvocationArguments) => void,
  ): void {
    const addr = U.findFunc(fnName);
    if (!addr) return;

    const key = `intercept:${fnName}`;
    if (this.listeners.has(key)) {
      console.log(`[!] Already intercepted: ${fnName}`);
      return;
    }

    const listener = Interceptor.attach(addr, {
      onEnter(args) {
        console.log(`[INTERCEPT] ${fnName}`);
        try {
          modifier.call(this, args);
        } catch (e: any) {
          console.log(`[!] Modifier error: ${e.message}`);
        }
      },
    });

    this.listeners.set(key, listener);
    console.log(`[+] Intercepted ${fnName}`);
  },

  /** Force a function to return a specific value. */
  forceReturn(
    functionName: string,
    returnValue: any,
    returnType: NativeCallbackReturnType = "int",
  ): void {
    const addr = U.findFunc(functionName);
    if (!addr) return;

    try {
      Interceptor.replace(
        addr,
        new NativeCallback(
          function () {
            console.log(`[MODIFIED] ${functionName} returning ${returnValue}`);
            return returnValue;
          },
          returnType,
          [],
        ),
      );

      this.replacements.set(functionName, addr);
      this.modifications.set(functionName, {
        type: "return",
        value: returnValue,
      });
      console.log(`[+] ${functionName} will always return ${returnValue}`);
    } catch (e: any) {
      console.log(`[!] Replace error: ${e.message}`);
    }
  },

  /** Compatibility name from the utility template. */
  mock(
    fnName: string,
    returnValue: any,
    returnType: NativeCallbackReturnType = "int",
  ): void {
    this.forceReturn(fnName, returnValue, returnType);
  },

  /** Skip execution by replacing the function with a fixed int return. */
  skip(functionName: string, returnValue: any = 0): void {
    this.forceReturn(functionName, returnValue, "int");
    this.modifications.set(functionName, { type: "skip", value: returnValue });
  },

  /** Modify one argument before the original function executes. */
  modifyArg(
    functionName: string,
    argIndex: number,
    newValue: NativePointerValue,
  ): void {
    const addr = U.findFunc(functionName);
    if (!addr) return;

    const key = `arg:${functionName}:${argIndex}`;
    if (this.listeners.has(key)) {
      console.log(
        `[!] Argument modifier already active: ${functionName}[${argIndex}]`,
      );
      return;
    }

    const listener = Interceptor.attach(addr, {
      onEnter(args) {
        console.log(
          `[MODIFY] ${functionName} arg[${argIndex}]: ${args[argIndex]} → ${newValue}`,
        );
        args[argIndex] = newValue as any;
      },
    });

    this.listeners.set(key, listener);
    this.modifications.set(key, { type: "argument", value: newValue });
    console.log(`[+] Will modify arg ${argIndex} of ${functionName}`);
  },

  /** Log function arguments. */
  logArgs(fnName: string, argTypes: string[] = []): void {
    const addr = U.findFunc(fnName);
    if (!addr) return;

    const key = `log:${fnName}`;
    if (this.listeners.has(key)) {
      console.log(`[!] Already logging arguments for: ${fnName}`);
      return;
    }

    const listener = Interceptor.attach(addr, {
      onEnter(args) {
        console.log(`[${fnName}]:`);
        for (let i = 0; i < Math.max(argTypes.length, 4); i++) {
          const type = argTypes[i] || "unknown";
          console.log(`  arg${i} (${type}): ${args[i]}`);
        }
      },
    });

    this.listeners.set(key, listener);
    console.log(`[+] Logging ${fnName} arguments`);
  },

  listModifications(): void {
    console.log("\n=== ACTIVE MODIFICATIONS ===");
    this.modifications.forEach((mod, fn) => {
      console.log(`${fn}: ${JSON.stringify(mod)}`);
    });
  },

  /** Revert a replacement or detach listeners associated with a function. */
  revert(functionName: string): void {
    const replacement = this.replacements.get(functionName);
    if (replacement) {
      Interceptor.revert(replacement);
      this.replacements.delete(functionName);
      this.modifications.delete(functionName);
    }

    Array.from(this.listeners.entries()).forEach(([key, listener]) => {
      if (key.includes(`:${functionName}`)) {
        listener.detach();
        this.listeners.delete(key);
        this.modifications.delete(key);
      }
    });

    console.log(`[+] Reverted C modifications for ${functionName}`);
  },

  revertAll(): void {
    this.replacements.forEach((address) => Interceptor.revert(address));
    this.replacements.clear();

    this.listeners.forEach((listener) => listener.detach());
    this.listeners.clear();
    this.modifications.clear();

    console.log("[+] All C modifications reverted");
  },
};

// ============================================================================
// NETWORK / DATA-MONITORING MODULE
// ============================================================================

const N = {
  calls: [] as ApiCall[],
  callCount: 0,
  apiListeners: new Map<string, InvocationListener>(),

  suspiciousPatterns: [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credit_card",
    "ssn",
    "private_key",
    "authorization",
  ],
  detectedData: [] as Detection[],
  dataListeners: new Map<string, InvocationListener>(),

  /** Hook common network/API functions and retain a call history. */
  hookAPI(
    functionNames: string[] = [
      "curl_easy_perform",
      "socket",
      "connect",
      "send",
      "recv",
      "sendto",
      "recvfrom",
    ],
  ): void {
    functionNames.forEach((fnName) => {
      if (this.apiListeners.has(fnName)) return;

      const addr = U.findFunc(fnName);
      if (!addr) return;

      const listener = Interceptor.attach(addr, {
        onEnter(args) {
          N.callCount++;
          console.log(`[${N.callCount}] ${fnName} called`);

          const argList: string[] = [];
          for (let i = 0; i < 4; i++) {
            try {
              argList.push(args[i].toString());
            } catch (_) {
              break;
            }
          }

          N.calls.push({
            id: N.callCount,
            name: fnName,
            time: Date.now(),
            args: argList,
          });
        },
        onLeave(retval) {
          console.log(`  → returned: ${retval}`);
        },
      });

      this.apiListeners.set(fnName, listener);
    });

    console.log("[+] API hooks installed");
  },

  recentCalls(count = 10): void {
    console.log("\n=== RECENT API CALLS ===");
    this.calls.slice(-count).forEach((call) => {
      console.log(`[${call.id}] ${call.name}`);
      console.log(`  Time: ${new Date(call.time).toISOString()}`);
      console.log(`  Args: ${call.args.join(", ")}`);
    });
  },

  apiStats(): void {
    const byFunction: Record<string, number> = {};
    this.calls.forEach((call) => {
      byFunction[call.name] = (byFunction[call.name] || 0) + 1;
    });

    console.log("\n=== API STATISTICS ===");
    console.log(`Total Calls: ${this.callCount}`);
    console.log("\nBy function:");

    Object.entries(byFunction)
      .sort((a, b) => b[1] - a[1])
      .forEach(([fn, count]) => console.log(`  ${fn}: ${count}`));
  },

  stopAPI(): void {
    this.apiListeners.forEach((listener) => listener.detach());
    this.apiListeners.clear();
    console.log("[+] API hooks removed");
  },

  /** Monitor write/send/sendto buffers for configured sensitive keywords. */
  monitorSensitiveData(
    // @ts-ignore
    patterns: string[] = this.suspiciousPatterns,
    maxBufferSize = 4096,
  ): void {
    const targets = ["write", "send", "sendto"];

    targets.forEach((fnName) => {
      if (this.dataListeners.has(fnName)) return;

      const addr = U.findFunc(fnName);
      if (!addr) return;

      const listener = Interceptor.attach(addr, {
        onEnter(args: InvocationArguments) {
          try {
            const bufPtr = args[1];
            const size = args[2].toInt32();
            if (size <= 0 || size > maxBufferSize) return;

            const data = bufPtr.readUtf8String(size);
            if (!data) return;

            const lower = data.toLowerCase();
            patterns.forEach((pattern) => {
              if (!lower.includes(pattern.toLowerCase())) return;

              console.log(`[ALERT] Suspicious data detected: ${pattern}`);
              console.log(`  Data: ${data.substring(0, 120)}`);

              N.detectedData.push({
                pattern,
                data: data.substring(0, 300),
                time: Date.now(),
              });
            });
          } catch (_) {
            // Binary data or invalid pointer: ignore.
          }
        },
      });

      this.dataListeners.set(fnName, listener);
    });

    console.log("[+] Sensitive-data monitor active");
  },

  sensitiveReport(): void {
    console.log("\n=== SENSITIVE-DATA REPORT ===");
    console.log(`Detections: ${this.detectedData.length}`);

    this.detectedData.forEach((detection, i) => {
      console.log(`\n[${i + 1}] ${detection.pattern}`);
      console.log(`  ${detection.data}`);
    });
  },

  stopSensitiveDataMonitor(): void {
    this.dataListeners.forEach((listener) => listener.detach());
    this.dataListeners.clear();
    console.log("[+] Sensitive-data monitor stopped");
  },
};

// ============================================================================
// LEGACY EXAMPLE-SCRIPT COMPATIBILITY WRAPPERS
// ============================================================================

const MemoryLeakDetector = {
  get allocations() {
    return A.allocations;
  },
  get frees() {
    return A.frees;
  },
  start: (suspectAfterMs = 5000) => A.startMemoryTracking(suspectAfterMs),
  report: () => A.memoryReport(),
  stop: () => A.stopMemoryTracking(),
};

const APIInterceptor = {
  get calls() {
    return N.calls;
  },
  get callCount() {
    return N.callCount;
  },
  hookAPI: () => N.hookAPI(),
  recentCalls: (count = 10) => N.recentCalls(count),
  stats: () => N.apiStats(),
};

const FunctionTracer = {
  get traces() {
    return D.traces;
  },
  trace: (functionName: string, depth = 5) => D.trace(functionName, depth),
  summary: () => D.traceSummary(),
};

const BehaviorModifier = {
  get modifications() {
    return C.modifications;
  },
  forceReturn: (
    functionName: string,
    returnValue: any,
    returnType: NativeCallbackReturnType = "int",
  ) => C.forceReturn(functionName, returnValue, returnType),
  modifyArg: (
    functionName: string,
    argIndex: number,
    newValue: NativePointerValue,
  ) => C.modifyArg(functionName, argIndex, newValue),
  skip: (functionName: string, returnValue: any = 0) =>
    C.skip(functionName, returnValue),
  listModifications: () => C.listModifications(),
};

const PerformanceProfiler = {
  get functions() {
    return A.performance;
  },
  profile: (functionName: string) => A.profile(functionName),
  profileMultiple: (functionNames: string[]) =>
    A.profileMultiple(functionNames),
  report: (functionName: string | null = null) =>
    A.reportPerformance(functionName),
  slowest: (count = 5) => A.slowest(count),
};

const ExfiltrationDetector = {
  get suspiciousPatterns() {
    return N.suspiciousPatterns;
  },
  get detectedData() {
    return N.detectedData;
  },
  monitor: () => N.monitorSensitiveData(),
  report: () => N.sensitiveReport(),
};

// ============================================================================
// HELP
// ============================================================================

function toolkitHelp(): void {
  console.log(`
╔═══════════════════════════════════════════════════════╗
║                  FRIDA TOOLKIT                        ║
╚═══════════════════════════════════════════════════════╝

MODULES:
  U  – Utilities      memory, modules, native calls
  H  – Hooking        generic hooks, malloc/free, I/O
  A  – Analysis       leak tracking, memory analysis, profiling
  D  – Debugging      tracing, trace history, threads, symbols
  C  – Interception   modify args, force returns, mock/skip
  N  – Network/Data   API call history, sensitive-data monitoring

QUICK EXAMPLES:
  U.findFunc("strlen")
  U.hexDump("0x7f...")
  H.hook("malloc")
  H.hookMalloc()
  A.analyzeMemory(8)
  A.startMemoryTracking()
  A.memoryReport()
  A.profileMultiple(["malloc", "free"])
  A.reportPerformance()
  D.traceFunction("open", 5)
  D.traceSummary()
  C.forceReturn("check_license", 1)
  C.modifyArg("open", 0, ptr("0x..."))
  N.hookAPI()
  N.recentCalls()
  N.monitorSensitiveData()
  N.sensitiveReport()

Type help() anytime.
`);
}

// ============================================================================
// INIT
// ============================================================================

Object.assign(globalThis as any, {
  U,
  H,
  A,
  D,
  C,
  N,
  toolkitHelp,
  MemoryLeakDetector,
  APIInterceptor,
  FunctionTracer,
  BehaviorModifier,
  PerformanceProfiler,
  ExfiltrationDetector,
});

console.log(`
╔═══════════════════════════════════════════════════════╗
║     Frida toolkit loaded – toolkitHelp() for usage    ║
╚═══════════════════════════════════════════════════════╝
`);
