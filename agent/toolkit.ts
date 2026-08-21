/**
 * Ready-to-use scripts for common Frida tasks
 *
 * Compile:
 *   frida-compile toolkit.ts -o toolkit.js
 *
 * Load:
 *   frida -U com.example.app -l frida_utils_template.js -l frida_example_scripts.js
 */

// ============================================================================
// EXAMPLE 1: MEMORY LEAK DETECTOR
// ============================================================================

interface AllocationInfo {
  size: number;
  timestamp: number;
  type: string;
}

const MemoryLeakDetector = {
  allocations: new Map<string, AllocationInfo>(),
  frees: new Map<string, number>(),
  stats: {
    totalAllocated: 0,
    totalFreed: 0,
    suspectedLeaks: 0,
  },

  /**
   * Start tracking memory allocations
   */
  start(): void {
    const mallocAddr = Module.findExportByName(null, "malloc");
    const freeAddr = Module.findExportByName(null, "free");

    if (!mallocAddr || !freeAddr) {
      console.log("[!] malloc/free not found");
      return;
    }

    // Track malloc
    Interceptor.attach(mallocAddr, {
      onEnter(args) {
        (this as any).size = args[0].toInt32();
      },
      onLeave(retval) {
        const addr = retval.toString();
        const size = (this as any).size;

        MemoryLeakDetector.allocations.set(addr, {
          size,
          timestamp: Date.now(),
          type: "malloc",
        });

        MemoryLeakDetector.stats.totalAllocated += size;
      },
    });

    // Track free
    Interceptor.attach(freeAddr, {
      onEnter(args) {
        const addr = args[0].toString();

        if (MemoryLeakDetector.allocations.has(addr)) {
          const alloc = MemoryLeakDetector.allocations.get(addr)!;
          MemoryLeakDetector.stats.totalFreed += alloc.size;
          MemoryLeakDetector.allocations.delete(addr);
        }

        MemoryLeakDetector.frees.set(addr, Date.now());
      },
    });

    console.log("[+] Memory leak detector started");
  },

  /**
   * Get current leak report
   */
  report(): void {
    const leaks = Array.from(MemoryLeakDetector.allocations.values());
    const now = Date.now();

    const suspectedLeaks = leaks.filter((l) => now - l.timestamp > 5000);

    console.log("\n=== MEMORY LEAK REPORT ===");
    console.log(`Total Allocated        : ${(MemoryLeakDetector.stats.totalAllocated / 1024 / 1024).toFixed(2)} MB`);
    console.log(`Total Freed            : ${(MemoryLeakDetector.stats.totalFreed / 1024 / 1024).toFixed(2)} MB`);
    console.log(`Unreleased Blocks      : ${leaks.length}`);
    console.log(`Suspected Leaks (>5s)  : ${suspectedLeaks.length}`);

    // Group by size
    const bySize: Record<number, number> = {};
    suspectedLeaks.forEach((leak) => {
      bySize[leak.size] = (bySize[leak.size] || 0) + 1;
    });

    console.log("\nLeak patterns:");
    Object.entries(bySize)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .forEach(([size, count]) => {
        const total = Number(size) * count;
        console.log(`  ${count}x ${size} bytes (${(total / 1024).toFixed(2)} KB)`);
      });
  },

  /**
   * Stop tracking
   */
  stop(): void {
    Interceptor.detachAll();
    console.log("[+] Memory leak detector stopped");
  },
};

// ============================================================================
// EXAMPLE 2: API CALL INTERCEPTOR
// ============================================================================

interface ApiCall {
  id: number;
  name: string;
  time: number;
  args: string[];
}

const APIInterceptor = {
  calls: [] as ApiCall[],
  callCount: 0,


  /**
   * Hook common network / API functions
   */
  hookCommonAPI(): void {
    this.hookAPI(
      [
        "curl_easy_perform",
        "socket",
        "connect",
        "send",
        "recv",
        "sendto",
        "recvfrom",
      ]);
  },

  /**
   * Hook API functions
   */
  hookAPI(commonAPIs: string[]): void {
    commonAPIs.forEach((fnName) => {
      try {
        const addr = Module.findExportByName(null, fnName);
        if (!addr) return;

        Interceptor.attach(addr, {
          onEnter(args) {
            APIInterceptor.callCount++;
            console.log(`[${APIInterceptor.callCount}] ${fnName} called`);

            const argList: string[] = [];
            for (let i = 0; i < 4; i++) {
              try {
                argList.push(args[i].toString());
              } catch {
                break;
              }
            }

            APIInterceptor.calls.push({
              id: APIInterceptor.callCount,
              name: fnName,
              time: Date.now(),
              args: argList,
            });
          },
          onLeave(retval) {
            console.log(`  → returned: ${retval}`);
          },
        });
      } catch (e) {
        // Function not found – skip
      }
    });

    console.log("[+] API hooks installed");
  },

  /**
   * Log recent API calls
   */
  recentCalls(count = 10): void {
    console.log(`\n=== RECENT API CALLS ===`);
    APIInterceptor.calls.slice(-count).forEach((call) => {
      console.log(`[${call.id}] ${call.name}`);
      console.log(`  Time: ${new Date(call.time).toISOString()}`);
    });
  },

  /**
   * Get statistics
   */
  stats(): void {
    const byFunction: Record<string, number> = {};

    APIInterceptor.calls.forEach((call) => {
      byFunction[call.name] = (byFunction[call.name] || 0) + 1;
    });

    console.log("\n=== API STATISTICS ===");
    console.log(`Total Calls: ${APIInterceptor.callCount}`);
    console.log("\nBy function:");

    Object.entries(byFunction)
      .sort((a, b) => b[1] - a[1])
      .forEach(([fn, count]) => {
        console.log(`  ${fn}: ${count}`);
      });
  },
};

// ============================================================================
// EXAMPLE 3: FUNCTION CALL TRACER
// ============================================================================

interface TraceEntry {
  time: number;
  args: string[];
  backtrace: string[];
}

const FunctionTracer = {
  traces: {} as Record<string, TraceEntry[]>,

  /**
   * Trace function with call stack
   */
  trace(functionName: string, depth = 5): void {
    const addr = Module.findExportByName(null, functionName);
    if (!addr) {
      console.log(`[!] Function not found: ${functionName}`);
      return;
    }

    Interceptor.attach(addr, {
      onEnter(args) {
        const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);

        if (!FunctionTracer.traces[functionName]) {
          FunctionTracer.traces[functionName] = [];
        }

        const argList: string[] = [];
        for (let i = 0; i < 4; i++) {
          try {
            argList.push(args[i].toString());
          } catch {
            break;
          }
        }

        FunctionTracer.traces[functionName].push({
          time: Date.now(),
          args: argList,
          backtrace: bt.slice(0, depth).map((a) => DebugSymbol.fromAddress(a).toString()),
        });

        console.log(`\n>>> ${functionName} called`);
        bt.slice(0, depth).forEach((a, i) => {
          console.log(`  [${i}] ${DebugSymbol.fromAddress(a)}`);
        });
      },
    });

    console.log(`[+] Tracing ${functionName}`);
  },

  /**
   * Print trace summary
   */
  summary(): void {
    console.log("\n=== TRACE SUMMARY ===");
    Object.entries(FunctionTracer.traces).forEach(([fn, calls]) => {
      console.log(`${fn}: ${calls.length} calls`);
    });
  },
};

// ============================================================================
// EXAMPLE 4: FUNCTION BEHAVIOR MODIFIER
// ============================================================================

interface Modification {
  type: string;
  value: any;
}

const BehaviorModifier = {
  modifications: new Map<string, Modification>(),

  /**
   * Force function to return a value
   */
  forceReturn(functionName: string, returnValue: any, returnType: NativeCallbackReturnType = "int"): void {
    const addr = Module.findExportByName(null, functionName);
    if (!addr) {
      console.log(`[!] Function not found: ${functionName}`);
      return;
    }

    try {
      Interceptor.replace(
        addr,
        new NativeCallback(
          function () {
            console.log(`[MODIFIED] ${functionName} returning ${returnValue}`);
            return returnValue;
          },
          returnType,
          []
        )
      );

      BehaviorModifier.modifications.set(functionName, {
        type: "return",
        value: returnValue,
      });

      console.log(`[+] ${functionName} will always return ${returnValue}`);
    } catch (e: any) {
      console.log(`[!] Error: ${e.message}`);
    }
  },

  /**
   * Modify function argument before call
   */
  modifyArg(functionName: string, argIndex: number, newValue: NativePointerValue): void {
    const addr = Module.findExportByName(null, functionName);
    if (!addr) return;

    Interceptor.attach(addr, {
      onEnter(args) {
        console.log(`[MODIFY] ${functionName} arg[${argIndex}]: ${args[argIndex]} → ${newValue}`);
        args[argIndex] = newValue as any;
      },
    });

    console.log(`[+] Will modify arg ${argIndex} of ${functionName}`);
  },

  /**
   * Skip function execution
   */
  skip(functionName: string, returnValue: any = 0): void {
    const addr = Module.findExportByName(null, functionName);
    if (!addr) return;

    Interceptor.replace(
      addr,
      new NativeCallback(
        function () {
          console.log(`[SKIPPED] ${functionName}`);
          return returnValue;
        },
        "int",
        []
      )
    );

    console.log(`[+] ${functionName} will be skipped`);
  },

  /**
   * List modifications
   */
  listModifications(): void {
    console.log("\n=== ACTIVE MODIFICATIONS ===");
    BehaviorModifier.modifications.forEach((mod, fn) => {
      console.log(`${fn}: ${JSON.stringify(mod)}`);
    });
  },
};

// ============================================================================
// EXAMPLE 5: PERFORMANCE PROFILER
// ============================================================================

interface PerfStats {
  calls: number;
  times: number[];
  totalTime: number;
}

const PerformanceProfiler = {
  functions: new Map<string, PerfStats>(),

  /**
   * Profile a function's execution time
   */
  profile(functionName: string): void {
    const addr = Module.findExportByName(null, functionName);
    if (!addr) {
      console.log(`[!] Function not found: ${functionName}`);
      return;
    }

    if (!PerformanceProfiler.functions.has(functionName)) {
      PerformanceProfiler.functions.set(functionName, {
        calls: 0,
        times: [],
        totalTime: 0,
      });
    }

    Interceptor.attach(addr, {
      onEnter() {
        (this as any).startTime = Date.now();
      },
      onLeave() {
        const duration = Date.now() - (this as any).startTime;
        const stats = PerformanceProfiler.functions.get(functionName)!;

        stats.calls++;
        stats.times.push(duration);
        stats.totalTime += duration;
      },
    });

    console.log(`[+] Profiling ${functionName}`);
  },

  /**
   * Profile multiple functions at once
   */
  profileMultiple(functionNames: string[]): void {
    functionNames.forEach((fn) => this.profile(fn));
  },

  /**
   * Print performance report
   */
  report(functionName: string | null = null): void {
    console.log("\n=== PERFORMANCE REPORT ===\n");

    const fns = functionName
      ? [functionName]
      : Array.from(PerformanceProfiler.functions.keys());

    fns.forEach((fn) => {
      const stats = PerformanceProfiler.functions.get(fn);
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

  /**
   * Find slowest functions
   */
  slowest(count = 5): void {
    const sorted = Array.from(PerformanceProfiler.functions.entries()).sort((a, b) => {
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
// EXAMPLE 6: DATA EXFILTRATION DETECTOR
// ============================================================================

interface Detection {
  pattern: string;
  data: string;
  time: number;
}

const ExfiltrationDetector = {
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

  /**
   * Monitor write/send for sensitive data
   */
  monitor(): void {
    const targets = ["write", "send", "sendto"];

    targets.forEach((fnName) => {
      const addr = Module.findExportByName(null, fnName);
      if (!addr) return;

      Interceptor.attach(addr, {
        onEnter(args) {
          try {
            const bufPtr = args[1];
            const size = args[2].toInt32();

            if (size <= 0 || size > 4096) return;

            const data = bufPtr.readUtf8String(size);
            if (!data) return;

            const lower = data.toLowerCase();

            ExfiltrationDetector.suspiciousPatterns.forEach((pattern) => {
              if (lower.includes(pattern)) {
                console.log(`[ALERT] Suspicious data detected: ${pattern}`);
                console.log(`  Data: ${data.substring(0, 120)}`);

                ExfiltrationDetector.detectedData.push({
                  pattern,
                  data: data.substring(0, 300),
                  time: Date.now(),
                });
              }
            });
          } catch (e) {
            // Binary data or invalid pointer – ignore
          }
        },
      });
    });

    console.log("[+] Exfiltration detector active");
  },

  /**
   * Report detected data
   */
  report(): void {
    console.log("\n=== EXFILTRATION REPORT ===");
    console.log(`Detections: ${ExfiltrationDetector.detectedData.length}`);

    ExfiltrationDetector.detectedData.forEach((detection, i) => {
      console.log(`\n[${i + 1}] ${detection.pattern}`);
      console.log(`  ${detection.data}`);
    });
  },
};

// ============================================================================
// INITIALIZATION
// ============================================================================

(globalThis as any).MemoryLeakDetector = MemoryLeakDetector;
(globalThis as any).APIInterceptor = APIInterceptor;
(globalThis as any).FunctionTracer = FunctionTracer;
(globalThis as any).BehaviorModifier = BehaviorModifier;
(globalThis as any).PerformanceProfiler = PerformanceProfiler;
(globalThis as any).ExfiltrationDetector = ExfiltrationDetector;

console.log(`
╔════════════════════════════════════════════════════════════════╗
║          FRIDA EXAMPLE SCRIPTS (TypeScript) LOADED             ║
╚════════════════════════════════════════════════════════════════╝

Available modules:

  MemoryLeakDetector     – Track allocations & find leaks
  APIInterceptor         – Hook and log network/API calls
  FunctionTracer         – Trace functions with backtraces
  BehaviorModifier       – Force returns / skip / modify args
  PerformanceProfiler    – Measure execution time
  ExfiltrationDetector   – Detect sensitive data in write/send

Quick start examples:

  MemoryLeakDetector.start()
  setTimeout(() => MemoryLeakDetector.report(), 15000)

  APIInterceptor.hookAPI()
  FunctionTracer.trace("open")
  BehaviorModifier.forceReturn("check_license", 1)
  PerformanceProfiler.profileMultiple(["malloc", "free"])
  ExfiltrationDetector.monitor()
`);
