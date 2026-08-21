# Frida Utils Template - Customization Guide

Complete guide to using and extending the Frida utilities template.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Module Overview](#module-overview)
3. [Customization Examples](#customization-examples)
4. [Common Use Cases](#common-use-cases)
5. [Best Practices](#best-practices)
6. [Extending the Template](#extending-the-template)

---

## Quick Start

### Installation
```bash
# Copy the template to your working directory
cp frida_utils_template.js ./my_project/

# Or use directly
frida -U com.example.app -l frida_utils_template.js
```

### First Session
```bash
# Connect to app
frida -U com.example.app -l frida_utils_template.js

# In REPL
[frida Repl]> help()

# Start using
[frida Repl]> U.listModules()
[frida Repl]> U.findFunc("malloc")
[frida Repl]> H.hookMalloc()
```

---

## Module Overview

### U - Utilities Module
Memory operations, module inspection, native function calls.

```javascript
// Find and inspect
U.findFunc("strlen")
U.moduleInfo("libc.so.6")
U.listModules()

// Memory operations
U.readMem(ptr, "string")
U.writeMem(ptr, value, "int")
U.hexDump(ptr, 256)

// Search and find
U.findString("password")
U.findPattern("48 8b 45 f8")

// Native calls
U.callNative("strlen", "uint", ["pointer"], [strPtr])
```

### H - Hooking Module
Install and manage function hooks, track allocations.

```javascript
// Generic hooking
H.hook("malloc", {
  onEnter(args) { console.log("malloc called"); },
  onLeave(retval) { console.log("malloc returned:", retval); }
})

// Predefined hooks
H.hookMalloc()
H.hookFree()
H.hookIO()
H.hookStringOps()

// Management
H.unhook("malloc")
H.unhookAll()
H.listHooks()
```

### A - Analysis Module
Profiling, memory analysis, hotspot detection.

```javascript
// Run analysis (blocks for duration)
A.analyzeMemory(10)      // 10 seconds

// Profile specific function
A.profileFunction("strlen", 1000)  // 1000 samples

// Find hotspots
A.findHotspots(10)       // 10 seconds, all functions
```

### D - Debugging Module
Function tracing, thread inspection, backtraces.

```javascript
// Detailed tracing
D.traceFunction("read", 5)  // First 5 calls

// Thread info
D.getThreads()

// Symbol lookup
D.symbolAt(ptr(0x12345678))
```

### C - Interception Module
Modify function behavior, mock functions, log arguments.

```javascript
// Modify behavior
C.intercept("open", function(args) {
  args[0] = Memory.allocUtf8String("/tmp/fake.txt");
})

// Mock return value
C.mock("rand", 42, "int")

// Log arguments
C.logArgs("read", ["int", "pointer", "uint"])
```

---

## Customization Examples

### Example 1: Add Custom Hook

```javascript
// Add to your script or in REPL after loading template

// Create custom tracking
const myTracking = {
  calls: 0,
  errors: 0,
  times: []
};

// Hook a function with custom logic
H.hook("custom_function", {
  onEnter(args) {
    myTracking.calls++;
    this.startTime = Date.now();
    console.log(`Call #${myTracking.calls}`);
  },
  onLeave(retval) {
    const duration = Date.now() - this.startTime;
    myTracking.times.push(duration);

    if (retval < 0) {
      myTracking.errors++;
      console.log(`[ERROR] returned ${retval}`);
    }
  }
});

// Report
function reportCustom() {
  const avg = myTracking.times.reduce((a, b) => a + b, 0) / myTracking.times.length;
  console.log(`Calls: ${myTracking.calls}, Errors: ${myTracking.errors}, Avg time: ${avg}ms`);
}
```

### Example 2: Custom Analysis Function

Add to template or create separate file:

```javascript
// Custom memory leak detector
A.detectLeaks = function(duration = 30) {
  const suspected = new Map();

  const addr = U.findFunc("malloc");
  let id = 0;

  Interceptor.attach(addr, {
    onLeave(retval) {
      const alloc = {
        id: id++,
        ptr: retval.toString(),
        time: Date.now(),
        size: this.size
      };
      suspected.set(retval.toString(), alloc);
    }
  });

  const freeAddr = U.findFunc("free");
  Interceptor.attach(freeAddr, {
    onEnter(args) {
      suspected.delete(args[0].toString());
    }
  });

  setTimeout(() => {
    Interceptor.detach(addr);
    Interceptor.detach(freeAddr);

    console.log(`\n=== LEAK REPORT ===`);
    console.log(`Suspected leaks: ${suspected.size}`);

    const bySize = {};
    suspected.forEach(alloc => {
      bySize[alloc.size] = (bySize[alloc.size] || 0) + 1;
    });

    Object.entries(bySize)
      .sort((a, b) => b[1] - a[1])
      .forEach(([size, count]) => {
        console.log(`  ${count}x ${size} bytes`);
      });
  }, duration * 1000);
};

// Use it
A.detectLeaks(15);
```

### Example 3: Custom Module

Create `my_custom_module.js`:

```javascript
// Custom module for your app

const MyModule = {
  appVersion: "1.0.0",

  // Track specific app functions
  trackLogin() {
    H.hook("authenticate", {
      onEnter(args) {
        const username = Memory.readCString(args[0]);
        console.log(`[LOGIN] username: ${username}`);
      },
      onLeave(retval) {
        console.log(`[LOGIN] result: ${retval}`);
      }
    });
  },

  // Check API calls
  monitorAPI() {
    H.hook("api_call", {
      onEnter(args) {
        const endpoint = Memory.readCString(args[0]);
        const method = Memory.readCString(args[1]);
        console.log(`[API] ${method} ${endpoint}`);
      }
    });
  },

  // Dump specific data
  dumpAppState() {
    const statePtr = U.findFunc("get_app_state");
    if (statePtr) {
      const state = U.readMem(statePtr, "string");
      console.log("App state:", state);
    }
  }
};

// Export globally
globalThis.My = MyModule;
```

Then load both:
```bash
frida -U com.example.app -l frida_utils_template.js -l my_custom_module.js
```

Or combine in main file that loads both:

```javascript
// load template
load("frida_utils_template.js");

// load custom module
load("my_custom_module.js");

console.log("[+] Template and custom modules loaded");
```

---

## Common Use Cases

### Use Case 1: Debug App Crashes

```javascript
// Find crash location by tracing key functions

// Hook crash-prone functions
H.hookMultiple([
  "malloc", "free", "memcpy", "strcpy", "memset"
], {
  logArgs: true,
  logReturn: false
});

// When crash happens, look at logs for problematic call
// Then get detailed trace:
D.traceFunction("strcpy", 20)

// Examine memory around crash
U.hexDump(ptr("0x12345678"), 512)
```

### Use Case 2: Performance Bottleneck

```javascript
// Quick profiling
A.profileFunction("render_frame", 100)
A.profileFunction("process_data", 100)

// Find hotspots
A.findHotspots(5, "app.so")

// Analyze memory usage
A.analyzeMemory(30)
```

### Use Case 3: Security Testing

```javascript
// Intercept authentication
C.intercept("check_password", function(args) {
  console.log("[SECURITY] Password check called");
  // Modify to always succeed
  this.skip = true;
  return 0;
});

// Mock authentication
C.mock("is_authenticated", 1, "int")

// Log all file opens
C.logArgs("open", ["path", "flags"])
D.traceFunction("open", 50)
```

### Use Case 4: API Interception

```javascript
// Log all API calls
C.intercept("http_request", function(args) {
  const url = Memory.readCString(args[0]);
  const method = Memory.readCString(args[1]);
  console.log(`[API] ${method} ${url}`);
});

// Modify requests
C.intercept("set_header", function(args) {
  const key = Memory.readCString(args[0]);
  const value = Memory.readCString(args[1]);

  if (key === "User-Agent") {
    args[1] = Memory.allocUtf8String("Custom-Agent/1.0");
  }
});

// Track responses
H.hook("http_response", {
  onEnter(args) {
    const statusCode = args[0].toInt32();
    console.log(`[RESPONSE] Status: ${statusCode}`);
  }
});
```

### Use Case 5: Data Exfiltration Detection

```javascript
// Track file writes
H.hook("write", {
  onEnter(args) {
    const fd = args[0].toInt32();
    const buf = args[1];
    const count = args[2].toInt32();

    console.log(`[WRITE] fd=${fd}, size=${count}`);

    if (count < 256) {
      const data = Memory.readCString(buf);
      console.log(`  data: ${data}`);
    }
  }
});

// Track encryption
H.hook("encrypt", {
  onEnter(args) {
    const plaintext = Memory.readCString(args[0]);
    console.log(`[ENCRYPT] plaintext: ${plaintext}`);
  },
  onLeave(retval) {
    console.log(`[ENCRYPT] ciphertext: ${retval}`);
  }
});
```

---

## Best Practices

### 1. Start Simple
```javascript
// Don't hook everything at once
// Start with one function
H.hook("malloc", { logArgs: false, logReturn: false })

// Then add complexity
H.hook("malloc", {
  onLeave(retval) {
    console.log("malloc returned:", retval);
  }
})
```

### 2. Save Long Analyses to Variables
```javascript
// Don't re-run expensive operations
const modules = U.listModules();
const funcs = U.listFunctions("libc.so.6");

// Use them multiple times
funcs.forEach(fn => console.log(fn));
funcs.filter(f => f.includes("str")).forEach(fn => {
  H.hook(fn);
});
```

### 3. Use Conditional Hooks
```javascript
// Only log when condition is met
H.hook("read", {
  onEnter(args) {
    const size = args[2].toInt32();

    if (size > 1000) {  // Only log large reads
      console.log(`Large read: ${size} bytes`);
    }
  }
});
```

### 4. Handle Errors Gracefully
```javascript
// Wrap in try-catch
try {
  const addr = U.findFunc("non_existent");
  if (!addr) throw new Error("Not found");
  H.hook("non_existent");
} catch(e) {
  console.log(`[!] Error: ${e.message}`);
}

// Or use the built-in error handling
H.hookMultiple(["fn1", "fn2", "fn3"]);
// This already handles missing functions
```

### 5. Clean Up After Yourself
```javascript
// When done analyzing, detach hooks
H.unhookAll()

// Or detach specific hooks
H.unhook("malloc")

// Check what's still hooked
H.listHooks()
```

---

## Extending the Template

### Add New Utility Function

Edit the template and add to the module:

```javascript
const U = {
  // ... existing functions ...

  // Add new function
  customUtility() {
    // Implementation
  }
};
```

### Create a Plugin

```javascript
// plugin_network.js
// Plugin for network analysis

const Network = {
  interceptedUrls: [],

  hookHTTP() {
    H.hook("curl_easy_perform", {
      onEnter(args) {
        console.log("[HTTP] Request made");
      }
    });
  },

  hooLogResponses() {
    H.hook("curl_easy_getinfo", {
      onLeave(retval) {
        console.log("[HTTP] Response info:", retval);
      }
    });
  }
};

globalThis.Network = Network;
```

Load it:
```bash
frida -U app -l frida_utils_template.js -l plugin_network.js
```

### Override/Extend Modules

```javascript
// Load template first
load("frida_utils_template.js");

// Add new method to existing module
H.customHook = function(name) {
  console.log("[CUSTOM] Hooking:", name);
  H.hook(name);
};

// Use it
H.customHook("malloc");
```

---

## Troubleshooting

### "Function not found"
```javascript
// Check if it exists
U.findFunc("function_name") !== null

// List available functions
const funcs = U.listFunctions("module_name");
funcs.includes("function_name")
```

### Hooks not triggering
```javascript
// Verify hook was attached
H.listHooks().includes("malloc")

// Check if function is actually called
H.hook("malloc", { logArgs: true })

// Add timeout and check logs
setTimeout(() => console.log("Check logs above"), 5000);
```

### Memory issues
```javascript
// Too many hooks = slowdown
// Solution: Unhook unused ones
H.unhookAll()

// Only hook critical functions
H.hook("critical_function_only")

// Use sampling
let count = 0;
H.hook("frequently_called", {
  onEnter() {
    if (count++ % 100 === 0) {  // Log every 100th call
      console.log("Call:", count);
    }
  }
});
```

### Crashes
```javascript
// Be careful with memory operations
// Always check before reading
try {
  const str = U.readMem(ptr, "string");
} catch(e) {
  console.log("Failed to read:", e.message);
}

// Validate pointers
const ptr = U.findFunc("func");
if (ptr) {
  U.hexDump(ptr);
}
```

---

## Example Session

```bash
$ frida -U com.example.app -l frida_utils_template.js

[frida Repl]> help()
# (shows help menu)

[frida Repl]> U.moduleInfo("libc.so.6")
{
  name: "libc.so.6",
  base: "0x7dd00000",
  size: 1892352,
  path: "/lib64/libc.so.6",
  end: "0x7df cd000"
}

[frida Repl]> H.hookMalloc()
[+] malloc tracker available as: mallocTracker

[frida Repl]> mallocTracker.count()
42

[frida Repl]> mallocTracker.list().slice(0, 3)
[
  { address: "0x7f1c00000", size: 1024, age: 1234 },
  { address: "0x7f1c00400", size: 2048, age: 5678 },
  { address: "0x7f1c00c00", size: 512, age: 9012 }
]

[frida Repl]> A.analyzeMemory(5)
[*] Analyzing memory for 5 seconds...
[5%] Allocs: 12, Frees: 3, Current: 0.05MB
...
[100%] Allocs: 156, Frees: 89, Current: 0.23MB

=== MEMORY ANALYSIS RESULTS ===
Total Allocated: 1.45 MB
Total Freed: 1.22 MB
Current Usage: 0.23 MB
Allocation Count: 156
Free Count: 89
Suspected Leaks: 67

[frida Repl]> H.unhookAll()
[+] All hooks removed

[frida Repl]> exit()
```

---

## Quick Reference Card

```
MEMORY:
  U.readMem(addr)         - Read as string
  U.readMem(addr, "int")  - Read as int
  U.writeMem(addr, val)   - Write value
  U.hexDump(addr)         - Show hex

HOOKING:
  H.hook(name, {onEnter, onLeave})
  H.unhookAll()
  H.listHooks()

ANALYSIS:
  A.analyzeMemory(10)
  A.profileFunction(name)
  A.findHotspots(10)

DEBUGGING:
  D.traceFunction(name, 5)
  D.getThreads()

INTERCEPTION:
  C.intercept(name, fn)
  C.mock(name, value)
```

---

**Version:** 1.0
**Last Updated:** August 2026
