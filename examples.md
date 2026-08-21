**Usage:**
```bash
frida -U com.example.app -l frida_utils_template.js
```

**Example:**
```javascript
[frida Repl]> help()          # Show all functions
[frida Repl]> H.hookMalloc()  # Start tracking allocations
[frida Repl]> A.profileFunction("strlen", 100)
```

---

## Examples

### Find Memory Leaks
```javascript
H.hookMalloc()
H.hookFree()
setTimeout(() => {
  mallocTracker.list()
  A.analyzeMemory(5)
}, 10000)
```

### Profile Performance
```javascript
A.profileFunction("malloc", 1000)
A.profileFunction("free", 1000)
setTimeout(() => A.slowest(5), 15000)
```

### Hook API Calls
```javascript
MemoryLeakDetector.start()
APIInterceptor.hookAPI()
PerformanceProfiler.profileMultiple(["open", "read", "write"])
```

### Debug Function Behavior
```javascript
D.traceFunction("authenticate", 5)
BehaviorModifier.forceReturn("validate", 1, "int")
```

---

## Troubleshooting

### "Function not found"
```javascript
U.findFunc("name") === null  // Check existence
U.listFunctions("module")    // List available
```

### Hook not working
```javascript
H.listHooks().includes("name")  // Verify hooked
H.hook("name", { logArgs: true })  // Enable logging
```

### Slow performance
```javascript
H.unhookAll()  // Remove all hooks
H.listHooks()  // Check active hooks
# Hook only critical functions
```

### Memory issues
```javascript
# Be careful with strings
try {
  const str = U.readMem(ptr, "string");
} catch(e) {
  console.log("Invalid pointer:", e.message);
}
```

