# Real-World Testing Strategy for GhidraMCP

## Problem

GhidraMCP has good unit test coverage (~5,200 lines) but **zero integration testing** with real Ghidra. Every feature requires manual testing:
- Load binary in Ghidra GUI
- Install plugin manually
- Test endpoints one by one
- Verify results visually

**Result:** Features break frequently, testing is slow, regressions slip through.

## Solution: Ghidra Headless + Automated Integration Tests

Use **Ghidra headless mode** to run automated integration tests against real binaries.

```
┌──────────────────────────────────────┐
│  Unit Tests (current, keep)          │  < 10 sec
│  Fast, isolated, mocked              │
└──────────────────────────────────────┘
              ↓
┌──────────────────────────────────────┐
│  Integration Tests (NEW)             │  < 3 min
│  Ghidra headless + test binaries     │
│  Real HTTP endpoints                 │
└──────────────────────────────────────┘
              ↓
┌──────────────────────────────────────┐
│  E2E Tests (NEW)                     │  < 2 min
│  Full MCP stack workflows            │
└──────────────────────────────────────┘
```

**Target:** < 5 minutes total CI time

---

## Test Binaries

Create **one simple test binary** covering basic use cases:

### `tests/fixtures/test_binary.c`

```c
#include <stdio.h>

// Global for data reference tests
int counter = 0;

// Simple function for decompilation
int add(int a, int b) {
    return a + b;
}

// Function with local vars for renaming tests
void process(int x) {
    int temp = x * 2;
    printf("Result: %d\n", temp);
}

// Caller for xref tests
int main() {
    int sum = add(5, 10);
    process(sum);
    counter++;
    return sum;
}
```

**Build script:**
```bash
#!/bin/bash
# tests/fixtures/build.sh
gcc -o test_binary test_binary.c -O0 -g
strip test_binary
```

**Expected functions:** `main`, `add`, `process`
**Expected xrefs:** `main` → `add`, `main` → `process`
**Expected data:** `counter` global
**Size:** ~4 KB

---

## Ghidra Headless Wrapper

### Python wrapper: `tests/ghidra_headless.py`

```python
import subprocess
import tempfile
import requests
import time
from pathlib import Path

class GhidraHeadless:
    def __init__(self, ghidra_dir, port=8080):
        self.ghidra_dir = Path(ghidra_dir)
        self.port = port
        self.process = None
        self.project_dir = None

    def start(self, binary_path):
        """Start Ghidra headless with binary loaded."""
        self.project_dir = Path(tempfile.mkdtemp(prefix="ghidra_test_"))

        cmd = [
            str(self.ghidra_dir / "support" / "analyzeHeadless"),
            str(self.project_dir),
            "TestProject",
            "-import", binary_path,
            "-postScript", "StartGhidraMCP.java",
        ]

        self.process = subprocess.Popen(cmd)
        self._wait_for_server()

    def _wait_for_server(self, timeout=30):
        start = time.time()
        while time.time() - start < timeout:
            try:
                if requests.get(f"http://127.0.0.1:{self.port}/methods").ok:
                    return
            except:
                time.sleep(0.5)
        raise TimeoutError("Server didn't start")

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
```

### Ghidra script: `tests/scripts/StartGhidraMCP.java`

```java
import ghidra.app.script.GhidraScript;

public class StartGhidraMCP extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("Starting GhidraMCP on port 8080...");
        // Plugin auto-loads from Extensions
        println("Ready");
    }
}
```

---

## Integration Tests

### `tests/integration/test_endpoints.py`

```python
import pytest
import requests
from ghidra_headless import GhidraHeadless

@pytest.fixture(scope="module")
def ghidra():
    g = GhidraHeadless("/path/to/ghidra")
    g.start("tests/fixtures/test_binary")
    yield
    g.stop()

class TestDecompilation:
    def test_decompile_main(self, ghidra):
        r = requests.post("http://127.0.0.1:8080/decompile", data="main")
        assert r.ok
        assert "int" in r.text or "void" in r.text
        assert "return" in r.text

    def test_decompile_invalid(self, ghidra):
        r = requests.post("http://127.0.0.1:8080/decompile", data="fake_function")
        assert "not found" in r.text.lower() or "error" in r.text.lower()

class TestQuery:
    def test_list_functions(self, ghidra):
        r = requests.get("http://127.0.0.1:8080/methods")
        assert r.ok
        functions = r.text.split("\n")
        assert any("main" in f for f in functions)
        assert any("add" in f for f in functions)

    def test_pagination(self, ghidra):
        r = requests.get("http://127.0.0.1:8080/methods", params={"limit": 2})
        assert r.ok
        assert len(r.text.split("\n")) <= 2

class TestModification:
    def test_rename_function(self, ghidra):
        # Rename
        r1 = requests.post("http://127.0.0.1:8080/renameFunction", data="add|add_two")
        assert r1.ok

        # Verify
        r2 = requests.get("http://127.0.0.1:8080/methods")
        assert "add_two" in r2.text

class TestXRefs:
    def test_get_callers(self, ghidra):
        r = requests.get("http://127.0.0.1:8080/get_function_xrefs", params={"function_name": "add"})
        assert r.ok
        assert "main" in r.text
```

---

## CI/CD Integration

### `.github/workflows/test.yml`

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Java
        uses: actions/setup-java@v3
        with:
          java-version: '21'
          cache: 'maven'

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Download Ghidra
        run: |
          wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip
          unzip -q ghidra_11.3.2_PUBLIC_20250415.zip
          echo "GHIDRA_INSTALL_DIR=$PWD/ghidra_11.3.2_PUBLIC" >> $GITHUB_ENV

      - name: Build test binary
        run: |
          cd tests/fixtures
          chmod +x build.sh
          ./build.sh

      - name: Extract Ghidra JARs
        run: ./copy_libs.sh ghidra_11.3.2_PUBLIC

      - name: Build plugin
        run: mvn package

      - name: Install plugin
        run: |
          mkdir -p ghidra_11.3.2_PUBLIC/Ghidra/Extensions
          unzip -q target/GhidraMCP-1.0-SNAPSHOT.zip -d ghidra_11.3.2_PUBLIC/Ghidra/Extensions

      - name: Run unit tests
        run: mvn test && pytest tests/test_*.py

      - name: Run integration tests
        run: pytest tests/integration/ -v --timeout=60
```

---

## Implementation Roadmap

### Week 1: Foundation
- [ ] Create `tests/fixtures/test_binary.c` and build script
- [ ] Write `ghidra_headless.py` wrapper
- [ ] Write `StartGhidraMCP.java` script
- [ ] Verify headless startup works manually

### Week 2: Basic Integration Tests
- [ ] Write 10-15 integration tests for core endpoints:
  - Decompilation (3 tests)
  - Query/list functions (3 tests)
  - Renaming (2 tests)
  - XRefs (2 tests)
  - Error handling (3 tests)
- [ ] Get tests passing locally

### Week 3: CI/CD
- [ ] Update GitHub Actions workflow
- [ ] Add Ghidra download step
- [ ] Add test binary build step
- [ ] Get CI passing

### Week 4: Expand Coverage
- [ ] Add struct tests (if using struct features)
- [ ] Add disassembly tests
- [ ] Add BSim tests (if using BSim)
- [ ] Target: 30+ integration tests

---

## Running Tests Locally

```bash
# Build test binary
cd tests/fixtures && ./build.sh

# Set environment
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.3.2_PUBLIC

# Run tests
pytest tests/integration/ -v
```

---

## Expected Outcomes

- **80% less manual testing** - Automated integration catches most issues
- **Faster development** - Confidence to refactor and add features
- **Catch regressions** - Tests run on every PR
- **< 5 min CI time** - Fast feedback loop

---

## Next Steps

1. **Start small:** Build one test binary, write 5 basic tests
2. **Validate approach:** Get headless working in CI
3. **Expand gradually:** Add more tests as patterns emerge
4. **Iterate:** Adjust based on what breaks vs. what stays stable
