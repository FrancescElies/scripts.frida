/**
 *
 * Utility library for Frida REPL
 *
 * Usage:
 *   frida-compile frida_utils_template.ts -o frida_utils_template.js
 *   frida -U com.example.app -l frida_utils_template.js
 *
 * Then in REPL:
 *   U.hook("malloc")
 *   H.hookMalloc()
 *   A.analyzeMemory(10)
 *   D.traceFunction("strlen")
 *   C.intercept("read", (args) => { ... })
 *   help()
 */

// ============================================================================
// TYPES
// ============================================================================

type MemoryReadType = "string" | "cstring" | "int" | "uint" | "long" | "ulong" | "bytes" | "hex";
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

// ============================================================================
// UTILITIES MODULE
// ============================================================================

const U = {
  /**
   * Find a function by name
   */
  findFunc(fnName: string, module: string | null = null): NativePointer | null {
    try {
      const addr = Module.findExportByName(module, fnName);
      return addr;
    } catch (e: any) {
      console.log(`[!] Function not found: ${fnName}`);
      return null;
    }
  },

  /**
   * Read memory as different types
   */
  readMem(addr: NativePointer | string, type: MemoryReadType = "string", size = 256): any {
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
          return hexdump(pointer, { length: size });
        default:
          return hexdump(pointer, { length: size });
      }
    } catch (e: any) {
      console.log(`[!] Error reading memory: ${e.message}`);
      return null;
    }
  },

  /**
   * Write memory
   */
  writeMem(addr: NativePointer | string, value: any, type: MemoryWriteType = "int"): void {
    try {
      const pointer = typeof addr === "string" ? ptr(addr) : addr;

      switch (type) {
        case "string":
          pointer.writeUtf8String(value);
          break;
        case "cstring":
          pointer.writeUtf8String(value); // Frida uses writeUtf8String for both
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

  /**
   * Allocate memory and write data
   */
  allocate(value: any, type: "string" | "cstring" | "int" | "bytes" = "string"): NativePointer | null {
    try {
      if (type === "string" || type === "cstring") {
        return Memory.allocUtf8String(value);
      } else if (type === "int") {
        const buf = Memory.alloc(4);
        buf.writeS32(value);
        return buf;
      } else if (type === "bytes") {
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

  /**
   * Dump memory as hexdump
   */
  hexDump(addr: NativePointer | string, size = 256): void {
    const pointer = typeof addr === "string" ? ptr(addr) : addr;
    console.log(hexdump(pointer, { length: size }));
  },

  /**
   * Search for string in memory (simplified - scans main modules)
   */
  findString(search: string): NativePointer[] {
    const results: NativePointer[] = [];
    const pattern = search;

    Process.enumerateModules().forEach((mod) => {
      try {
        Memory.scan(mod.base, mod.size, pattern, {
          onMatch(address, size) {
            results.push(address);
            return "continue" as any;
          },
          onComplete() {},
        });
      } catch (e) {
        // skip unreadable regions
      }
    });

    return results;
  },

  /**
   * Search for hex pattern
   */
  findPattern(pattern: string): NativePointer[] {
    const results: NativePointer[] = [];

    Process.enumerateModules().forEach((mod) => {
      try {
        Memory.scan(mod.base, mod.size, pattern, {
          onMatch(address, size) {
            results.push(address);
            return "continue" as any;
          },
          onComplete() {},
        });
      } catch (e) {
        // skip
      }
    });

    return results;
  },

  /**
   * Get module information
   */
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

  /**
   * List all loaded modules
   */
  listModules(): Array<{ name: string; base: string; size: number; path: string }> {
    return Process.enumerateModules().map((m) => ({
      name: m.name,
      base: m.base.toString(),
      size: m.size,
      path: m.path,
    }));
  },

  /**
   * List exported functions from a module
   */
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

  /**
   * Call a native function directly
   */
  callNative(
    fnName: string,
    returnType: NativeFunctionReturnType = "int",
    argTypes: NativeFunctionArgumentType[] = [],
    args: any[] = []
  ): any {
    try {
      const addr = this.findFunc(fnName);
      if (!addr) return null;

      const fn = new NativeFunction(addr, returnType, argTypes);
      const result = fn(...args);
      console.log(`[+] ${fnName}() returned: ${result}`);
      return result;
    } catch (e: any) {
      console.log(`[!] Error calling native function: ${e.message}`);
      return null;
    }
  },

  /**
   * Get process information
   */
  processInfo(): ProcessInfo {
    return {
      pid: Process.id,
      arch: Process.arch,
      pageSize: Process.pageSize,
      platform: Process.platform,
    };
  },
};

// ============================================================================
// HOOKING MODULE
// ============================================================================

const H = {
  hooks: new Map<string, NativePointer>(),

  /**
   * Generic hook function
   */
  hook(fnName: string, callbacks: HookCallbacks = {}): NativePointer | null {
    try {
      const addr = U.findFunc(fnName);
      if (!addr) return null;

      const logArgs = callbacks.logArgs !== false;
      const logReturn = callbacks.logReturn !== false;

      Interceptor.attach(addr, {
        onEnter(args) {
          if (logArgs) {
            const argStr = Array.from({ length: 6 }, (_, i) => args[i]?.toString() ?? "null").join(", ");
            console.log(`[>] ${fnName}(${argStr})`);
          }
          if (callbacks.onEnter) {
            callbacks.onEnter.call(this, args);
          }
        },
        onLeave(retval) {
          if (logReturn) {
            console.log(`[<] ${fnName} => ${retval}`);
          }
          if (callbacks.onLeave) {
            callbacks.onLeave.call(this, retval);
          }
        },
      });

      this.hooks.set(fnName, addr);
      console.log(`[+] Hooked: ${fnName}`);
      return addr;
    } catch (e: any) {
      console.log(`[!] Hook error: ${e.message}`);
      return null;
    }
  },

  /**
   * Hook malloc - track allocations
   */
  hookMalloc(verbose = true): void {
    const allocations = new Map<string, { size: number; timestamp: number }>();

    this.hook("malloc", {
      logArgs: verbose,
      logReturn: verbose,
      onEnter(args) {
        (this as any).size = args[0].toInt32();
      },
      onLeave(retval) {
        const size = (this as any).size;
        if (size) {
          allocations.set(retval.toString(), {
            size,
            timestamp: Date.now(),
          });
        }
      },
    });

    (globalThis as any).mallocTracker = {
      count: () => allocations.size,
      total: () => Array.from(allocations.values()).reduce((sum, a) => sum + a.size, 0),
      list: () =>
        Array.from(allocations.entries()).map(([addr, info]) => ({
          address: addr,
          size: info.size,
          age: Date.now() - info.timestamp,
        })),
    };

    console.log("[+] malloc tracker available as: mallocTracker");
  },

  /**
   * Hook free
   */
  hookFree(verbose = true): void {
    this.hook("free", {
      logArgs: verbose,
      logReturn: false,
      onEnter(args) {
        if (verbose) {
          console.log(`  freeing: ${args[0]}`);
        }
      },
    });
  },

  /**
   * Hook read/write
   */
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

  /**
   * Hook common string operations
   */
  hookStringOps(): void {
    ["strlen", "strcpy", "strcat", "strcmp"].forEach((fn) => {
      try {
        this.hook(fn, { logReturn: false });
      } catch (e) {
        // skip
      }
    });
    console.log("[+] String operation hooks installed");
  },

  /**
   * Hook multiple functions
   */
  hookMultiple(names: string[], callbacks: HookCallbacks = {}): void {
    names.forEach((name) => {
      try {
        this.hook(name, callbacks);
      } catch (e: any) {
        console.log(`[!] Failed to hook ${name}: ${e.message}`);
      }
    });
  },

  /**
   * Unhook a function
   */
  unhook(fnName: string): void {
    const addr = this.hooks.get(fnName);
    if (addr) {
      Interceptor.detachAll(); // Note: Frida doesn't support per-listener detach easily
      this.hooks.delete(fnName);
      console.log(`[+] Unhooked: ${fnName} (note: detachAll used)`);
    }
  },

  /**
   * Unhook all
   */
  unhookAll(): void {
    Interceptor.detachAll();
    this.hooks.clear();
    console.log("[+] All hooks removed");
  },

  /**
   * List active hooks
   */
  listHooks(): string[] {
    return Array.from(this.hooks.keys());
  },

  /**
   * Replace function return value
   */
  replaceReturn(fnName: string, returnValue: any, returnType: NativeCallbackReturnType = "int"): void {
    try {
      const addr = U.findFunc(fnName);
      if (!addr) return;

      Interceptor.replace(
        addr,
        new NativeCallback(
          function () {
            console.log(`[*] ${fnName} replaced, returning: ${returnValue}`);
            return returnValue;
          },
          returnType,
          []
        )
      );
      console.log(`[+] Replaced ${fnName} to return ${returnValue}`);
    } catch (e: any) {
      console.log(`[!] Replace error: ${e.message}`);
    }
  },
};

// ============================================================================
// ANALYSIS MODULE
// ============================================================================

const A = {
  /**
   * Analyze memory allocations for a duration
   */
  analyzeMemory(duration = 10): void {
    const allocations = new Map<string, { size: number; time: number }>();
    const stats = { allocs: 0, frees: 0, totalAllocated: 0, totalFreed: 0 };

    const mallocAddr = U.findFunc("malloc");
    const freeAddr = U.findFunc("free");

    if (!mallocAddr || !freeAddr) {
      console.log("[!] malloc/free not found");
      return;
    }

    const mallocListener = Interceptor.attach(mallocAddr, {
      onEnter(args) {
        (this as any).size = args[0].toInt32();
      },
      onLeave(retval) {
        const size = (this as any).size;
        const addr = retval.toString();
        allocations.set(addr, { size, time: Date.now() });
        stats.allocs++;
        stats.totalAllocated += size;
      },
    });

    const freeListener = Interceptor.attach(freeAddr, {
      onEnter(args) {
        const addr = args[0].toString();
        if (allocations.has(addr)) {
          stats.totalFreed += allocations.get(addr)!.size;
          allocations.delete(addr);
        }
        stats.frees++;
      },
    });

    console.log(`[*] Analyzing memory for ${duration} seconds...`);

    const startTime = Date.now();
    const interval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const current = stats.totalAllocated - stats.totalFreed;
      const progress = Math.min(100, Math.round((elapsed / (duration * 1000)) * 100));
      // Note: process.stdout may not exist in all Frida environments
      console.log(`[${progress}%] Allocs: ${stats.allocs}, Frees: ${stats.frees}, Current: ${(current / 1024 / 1024).toFixed(2)}MB`);
    }, 1000);

    setTimeout(() => {
      clearInterval(interval);
      mallocListener.detach();
      freeListener.detach();

      console.log("\n=== MEMORY ANALYSIS RESULTS ===");
      console.log(`Total Allocated : ${(stats.totalAllocated / 1024 / 1024).toFixed(2)} MB`);
      console.log(`Total Freed     : ${(stats.totalFreed / 1024 / 1024).toFixed(2)} MB`);
      console.log(`Current Usage   : ${((stats.totalAllocated - stats.totalFreed) / 1024 / 1024).toFixed(2)} MB`);
      console.log(`Allocation Count: ${stats.allocs}`);
      console.log(`Free Count      : ${stats.frees}`);
      console.log(`Suspected Leaks : ${allocations.size}`);

      if (allocations.size > 0) {
        const totalLeak = Array.from(allocations.values()).reduce((a, b) => a + b.size, 0);
        console.log(`\nLeak Details:`);
        console.log(`  Total Leaked : ${(totalLeak / 1024).toFixed(2)} KB`);
        console.log(`  Blocks       : ${allocations.size}`);
        console.log(`  Avg Block    : ${(totalLeak / allocations.size).toFixed(0)} bytes`);
      }
    }, duration * 1000);
  },

  /**
   * Profile function execution time
   */
  profileFunction(fnName: string, sampleCount = 100): void {
    const addr = U.findFunc(fnName);
    if (!addr) return;

    const timings: number[] = [];
    let count = 0;

    const listener = Interceptor.attach(addr, {
      onEnter() {
        (this as any).startTime = Date.now();
      },
      onLeave() {
        const duration = Date.now() - (this as any).startTime;
        timings.push(duration);
        count++;

        if (count >= sampleCount) {
          listener.detach();

          const sorted = [...timings].sort((a, b) => a - b);
          const avg = timings.reduce((a, b) => a + b, 0) / timings.length;
          const min = sorted[0];
          const max = sorted[sorted.length - 1];
          const median = sorted[Math.floor(sorted.length / 2)];

          console.log(`\n=== PROFILING: ${fnName} ===`);
          console.log(`Samples : ${timings.length}`);
          console.log(`Average : ${avg.toFixed(2)} ms`);
          console.log(`Min/Max : ${min} ms / ${max} ms`);
          console.log(`Median  : ${median} ms`);
        }
      },
    });

    console.log(`[*] Profiling ${fnName}... (collecting ${sampleCount} samples)`);
  },
};

// ============================================================================
// DEBUGGING MODULE
// ============================================================================

const D = {
  /**
   * Trace function calls with detailed info
   */
  traceFunction(fnName: string, maxCalls = 10): void {
    const addr = U.findFunc(fnName);
    if (!addr) return;

    let count = 0;

    const listener = Interceptor.attach(addr, {
      onEnter(args) {
        if (count >= maxCalls) {
          listener.detach();
          console.log(`[*] Max traces (${maxCalls}) reached, stopping`);
          return;
        }
        count++;

        console.log(`\n[TRACE #${count}] ${fnName}`);
        console.log(`  Address: ${addr}`);
        console.log(`  Args:`);

        for (let i = 0; i < 4; i++) {
          try {
            const arg = args[i];
            console.log(`    [${i}]: ${arg}`);
            try {
              const str = arg.readCString();
              if (str && str.length > 0 && str.length < 200) {
                console.log(`         → "${str}"`);
              }
            } catch (_) {}
          } catch (_) {}
        }

        const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
        console.log(`  Backtrace:`);
        bt.slice(0, 6).forEach((a, i) => {
          const sym = DebugSymbol.fromAddress(a);
          console.log(`    [${i}] ${sym}`);
        });
      },
    });

    console.log(`[+] Tracing ${fnName} (max ${maxCalls} calls)`);
  },

  /**
   * Get thread information
   */
  getThreads(): Array<{ id: number; state: string; pc?: string; sp?: string }> {
    return Process.enumerateThreads().map((t) => ({
      id: t.id,
      state: t.state,
      pc: t.context.pc?.toString(),
      sp: t.context.sp?.toString(),
    }));
  },

  /**
   * Show symbol at address
   */
  symbolAt(addr: NativePointer | string): DebugSymbol {
    const pointer = typeof addr === "string" ? ptr(addr) : addr;
    const sym = DebugSymbol.fromAddress(pointer);
    console.log(sym.toString());
    return sym;
  },
};

// ============================================================================
// INTERCEPTION MODULE
// ============================================================================

const C = {
  /**
   * Intercept function and modify arguments
   */
  intercept(fnName: string, modifier: (this: InvocationContext, args: InvocationArguments) => void): void {
    const addr = U.findFunc(fnName);
    if (!addr) return;

    Interceptor.attach(addr, {
      onEnter(args) {
        console.log(`[INTERCEPT] ${fnName}`);
        try {
          modifier.call(this, args);
        } catch (e: any) {
          console.log(`[!] Modifier error: ${e.message}`);
        }
      },
    });

    console.log(`[+] Intercepted ${fnName}`);
  },

  /**
   * Mock function to return specific value
   */
  mock(fnName: string, returnValue: any, returnType: NativeCallbackReturnType = "int"): void {
    const addr = U.findFunc(fnName);
    if (!addr) return;

    let callCount = 0;

    Interceptor.replace(
      addr,
      new NativeCallback(
        function () {
          callCount++;
          console.log(`[MOCK #${callCount}] ${fnName} returning ${returnValue}`);
          return returnValue;
        },
        returnType,
        []
      )
    );

    console.log(`[+] Mocked ${fnName}`);
  },

  /**
   * Log function arguments
   */
  logArgs(fnName: string, argTypes: string[] = []): void {
    const addr = U.findFunc(fnName);
    if (!addr) return;

    Interceptor.attach(addr, {
      onEnter(args) {
        console.log(`[${fnName}]:`);
        for (let i = 0; i < Math.max(argTypes.length, 4); i++) {
          const type = argTypes[i] || "unknown";
          console.log(`  arg${i} (${type}): ${args[i]}`);
        }
      },
    });

    console.log(`[+] Logging ${fnName} arguments`);
  },
};

// ============================================================================
// HELP
// ============================================================================

function help(): void {
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║          FRIDA UTILITIES TEMPLATE (TypeScript)                 ║
╚════════════════════════════════════════════════════════════════╝

MODULES:
  U  – Utilities   (memory, modules, native calls)
  H  – Hooking     (hooks, malloc tracking)
  A  – Analysis    (memory analysis, profiling)
  D  – Debugging   (tracing, threads, symbols)
  C  – Interception(modify args, mocking)

EXAMPLES:
  U.findFunc("strlen")
  U.hexDump("0x7f...")
  H.hook("malloc")
  H.hookMalloc()
  A.analyzeMemory(8)
  D.traceFunction("open", 5)
  C.mock("rand", 42)

Type help() anytime.
`);
}

// ============================================================================
// INIT
// ============================================================================

(globalThis as any).U = U;
(globalThis as any).H = H;
(globalThis as any).A = A;
(globalThis as any).D = D;
(globalThis as any).C = C;
(globalThis as any).help = help;

console.log(`
╔════════════════════════════════════════════════════════════════╗
║     FRIDA UTILITIES (TS) LOADED – type help() for usage        ║
╚════════════════════════════════════════════════════════════════╝
`);
