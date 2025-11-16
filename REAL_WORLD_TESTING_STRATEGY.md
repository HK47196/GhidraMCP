# Real-World Testing Strategy for GhidraMCP

## Executive Summary

GhidraMCP currently has **good unit test coverage** for utility functions (~5,200 lines of tests) but **lacks integration testing** against real Ghidra binaries. This document proposes a comprehensive strategy to add automated real-world testing that validates the entire stack: Java services → HTTP endpoints → Python MCP bridge.

**Current Testing Gaps:**
- ❌ No automated testing with real Ghidra Program objects
- ❌ No HTTP endpoint integration tests
- ❌ No end-to-end MCP tool validation
- ❌ No testing against diverse binary architectures (x86, ARM, etc.)
- ❌ Manual testing required for every feature change

**Proposed Solution:** Ghidra headless mode + test binary fixtures + automated integration test suite

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Testing Pyramid Strategy](#testing-pyramid-strategy)
3. [Test Binary Fixtures](#test-binary-fixtures)
4. [Ghidra Headless Automation](#ghidra-headless-automation)
5. [Integration Test Framework](#integration-test-framework)
6. [End-to-End Test Scenarios](#end-to-end-test-scenarios)
7. [CI/CD Integration](#cicd-integration)
8. [Mock Improvement Strategy](#mock-improvement-strategy)
9. [Performance Testing](#performance-testing)
10. [Implementation Roadmap](#implementation-roadmap)

---

## 1. Architecture Overview

### Current Testing Architecture

```
┌─────────────────────────────────────────────────────┐
│  UNIT TESTS (Current State)                         │
│  ✅ PluginUtils: Pagination, parsing                │
│  ✅ Python HTTP helpers: safe_get, safe_post        │
│  ✅ Address format validation                       │
│  ✅ Namespace parsing                               │
│  ⚠️  Service classes: Mocked Ghidra APIs            │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  INTEGRATION TESTS (Missing)                        │
│  ❌ HTTP endpoints with real Ghidra                 │
│  ❌ Service classes with real Program objects       │
│  ❌ MCP bridge end-to-end                           │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  MANUAL TESTING (Current Reality)                   │
│  👤 Load binary in Ghidra GUI                       │
│  👤 Install plugin                                  │
│  👤 Test each endpoint manually                     │
│  👤 Verify results visually                         │
└─────────────────────────────────────────────────────┘
```

### Proposed Testing Architecture

```
┌────────────────────────────────────────────────────────────┐
│  LAYER 1: Unit Tests (Keep existing)                       │
│  ✅ Fast, isolated, no dependencies                        │
│  ✅ Run on every commit                                    │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│  LAYER 2: Service Integration Tests (NEW)                  │
│  🔧 Ghidra headless mode                                   │
│  🔧 Real Program objects from test binaries                │
│  🔧 Direct service class testing                           │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│  LAYER 3: HTTP Endpoint Tests (NEW)                        │
│  🌐 Plugin running in headless Ghidra                      │
│  🌐 HTTP client testing against real server                │
│  🌐 Response format validation                             │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│  LAYER 4: End-to-End MCP Tests (NEW)                       │
│  🔄 Full stack: MCP client → Bridge → Plugin → Ghidra     │
│  🔄 Tool configuration validation                          │
│  🔄 Real-world usage scenarios                             │
└────────────────────────────────────────────────────────────┘
```

---

## 2. Testing Pyramid Strategy

### Test Distribution (Recommended)

```
         ┌─────────────────┐
        /  E2E Tests (10%)  \
       /─────────────────────\
      /  Integration (30%)    \
     /─────────────────────────\
    /    Unit Tests (60%)       \
   /─────────────────────────────\
```

**Test Count Goals:**

| Layer | Current | Target | Examples |
|-------|---------|--------|----------|
| **Unit Tests** | ~50 tests | 80 tests | Utility functions, parsers, validators |
| **Integration Tests** | 0 tests | 40 tests | Service classes with real Program |
| **HTTP Tests** | 0 tests | 30 tests | Endpoint responses, error handling |
| **E2E Tests** | 0 tests | 15 tests | Full MCP tool workflows |
| **Total** | ~50 | **165 tests** | |

### Test Execution Time Budget

| Layer | Target Time | Frequency |
|-------|-------------|-----------|
| Unit Tests | < 10 seconds | Every commit |
| Integration Tests | < 2 minutes | Pre-push, PR |
| HTTP Tests | < 3 minutes | Pre-push, PR |
| E2E Tests | < 5 minutes | PR, nightly |
| **Total** | **< 10 minutes** | **PR pipeline** |

---

## 3. Test Binary Fixtures

### Why Custom Test Binaries?

**Problems with existing binaries:**
- Unpredictable content
- License compliance issues
- Too large for version control
- Architecture-specific

**Solution:** Build minimal, purpose-specific test binaries

### Test Binary Catalog

Create a `tests/fixtures/binaries/` directory with:

```
tests/fixtures/binaries/
├── README.md                        # Build instructions
├── src/                             # C source files
│   ├── simple_x86_64.c             # Basic functions
│   ├── struct_heavy_x86_64.c       # Complex structs
│   ├── xrefs_x86_64.c              # Cross-reference testing
│   ├── namespace_cpp_x86_64.cpp    # C++ with namespaces
│   ├── simple_arm.c                # ARM architecture
│   └── far_pointers_x86.c          # 16-bit segmented
├── compiled/                        # Pre-compiled binaries
│   ├── simple_x86_64               # ELF64, stripped
│   ├── simple_x86_64.exe           # PE32+, stripped
│   ├── struct_heavy_x86_64
│   ├── xrefs_x86_64
│   ├── namespace_cpp_x86_64
│   ├── simple_arm                  # ARM32 ELF
│   └── far_pointers_x86.exe        # PE16, 8086
└── scripts/
    ├── build_all.sh                # Compile all test binaries
    └── verify_binaries.sh          # Check binary properties
```

### Example Test Binary: `simple_x86_64.c`

```c
// tests/fixtures/binaries/src/simple_x86_64.c
// Purpose: Basic function testing for decompilation, disassembly, renaming

#include <stdio.h>
#include <stdlib.h>

// Simple function for basic decompilation
int add_numbers(int a, int b) {
    return a + b;
}

// Function with multiple parameters
int calculate_sum(int x, int y, int z) {
    int result = x + y + z;
    return result;
}

// Function with local variables for variable renaming tests
void process_data(int input) {
    int temp1 = input * 2;
    int temp2 = temp1 + 10;
    printf("Result: %d\n", temp2);
}

// Function that calls others (for XRef testing)
void caller_function() {
    int sum = add_numbers(5, 10);
    process_data(sum);
}

int main(int argc, char** argv) {
    int result = calculate_sum(1, 2, 3);
    caller_function();
    return result;
}
```

**Expected Properties:**
- Functions: `main`, `add_numbers`, `calculate_sum`, `process_data`, `caller_function`
- Cross-references: `caller_function` → `add_numbers`, `caller_function` → `process_data`
- Local variables: `temp1`, `temp2`, `result`
- Size: ~4 KB (minimal)

### Example Test Binary: `struct_heavy_x86_64.c`

```c
// tests/fixtures/binaries/src/struct_heavy_x86_64.c
// Purpose: Struct parsing, field operations, data type testing

#include <stdio.h>
#include <stdint.h>

// Simple struct
typedef struct {
    int x;
    int y;
} Point;

// Nested struct
typedef struct {
    Point origin;
    int width;
    int height;
} Rectangle;

// Struct with arrays
typedef struct {
    char name[32];
    int values[10];
    uint8_t flags;
} DataBlock;

// Struct with pointers
typedef struct Node {
    int data;
    struct Node* next;
} Node;

// Union for testing
typedef union {
    int as_int;
    float as_float;
    char as_bytes[4];
} Value;

Point global_point = {10, 20};
Rectangle global_rect = {{0, 0}, 100, 50};

int use_structs() {
    Point p = {5, 10};
    Rectangle r = {p, 200, 100};

    DataBlock block;
    block.flags = 0xFF;

    return p.x + r.width;
}

int main() {
    return use_structs();
}
```

**Expected Properties:**
- Structs: `Point`, `Rectangle`, `DataBlock`, `Node`, `Value`
- Nested struct: `Rectangle.origin` (type `Point`)
- Arrays: `DataBlock.name[32]`, `DataBlock.values[10]`
- Pointers: `Node.next` (type `Node*`)
- Global data: `global_point`, `global_rect`

### Example Test Binary: `xrefs_x86_64.c`

```c
// tests/fixtures/binaries/src/xrefs_x86_64.c
// Purpose: Cross-reference testing (calls, jumps, data references)

#include <stdio.h>

// Global variable for data references
int global_counter = 0;
const char* global_message = "Hello";

// Leaf function (no calls)
int leaf_function(int x) {
    return x * 2;
}

// Function with multiple callers
int shared_function(int a, int b) {
    global_counter++;  // Data reference
    return a + b;
}

// Function that calls shared_function
void caller_1() {
    int result = shared_function(1, 2);
    printf("%s: %d\n", global_message, result);  // Data reference
}

// Another function that calls shared_function
void caller_2() {
    int result = shared_function(3, 4);
    printf("%s: %d\n", global_message, result);  // Data reference
}

// Function with conditional calls
void conditional_caller(int flag) {
    if (flag > 0) {
        caller_1();
    } else {
        caller_2();
    }
}

int main(int argc, char** argv) {
    if (argc > 1) {
        conditional_caller(1);
    } else {
        conditional_caller(0);
    }
    return global_counter;
}
```

**Expected Cross-References:**
- `shared_function` called by: `caller_1`, `caller_2`
- `global_counter` referenced by: `shared_function`, `main`
- `global_message` referenced by: `caller_1`, `caller_2`
- `caller_1` called by: `conditional_caller`, `main`
- `caller_2` called by: `conditional_caller`, `main`

### Build Script: `build_all.sh`

```bash
#!/bin/bash
# tests/fixtures/binaries/scripts/build_all.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../src"
OUT_DIR="$SCRIPT_DIR/../compiled"

mkdir -p "$OUT_DIR"

echo "Building test binaries..."

# x86-64 Linux (ELF)
gcc -o "$OUT_DIR/simple_x86_64" "$SRC_DIR/simple_x86_64.c" -O0 -g
strip "$OUT_DIR/simple_x86_64"

gcc -o "$OUT_DIR/struct_heavy_x86_64" "$SRC_DIR/struct_heavy_x86_64.c" -O0 -g
strip "$OUT_DIR/struct_heavy_x86_64"

gcc -o "$OUT_DIR/xrefs_x86_64" "$SRC_DIR/xrefs_x86_64.c" -O0 -g
strip "$OUT_DIR/xrefs_x86_64"

# C++ with namespaces (requires g++)
g++ -o "$OUT_DIR/namespace_cpp_x86_64" "$SRC_DIR/namespace_cpp_x86_64.cpp" -O0 -g
strip "$OUT_DIR/namespace_cpp_x86_64"

# x86-64 Windows (PE) - requires mingw-w64
if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    x86_64-w64-mingw32-gcc -o "$OUT_DIR/simple_x86_64.exe" "$SRC_DIR/simple_x86_64.c" -O0 -g
    x86_64-w64-mingw32-strip "$OUT_DIR/simple_x86_64.exe"
fi

# ARM (requires cross-compiler)
if command -v arm-linux-gnueabi-gcc &> /dev/null; then
    arm-linux-gnueabi-gcc -o "$OUT_DIR/simple_arm" "$SRC_DIR/simple_arm.c" -O0 -g -static
    arm-linux-gnueabi-strip "$OUT_DIR/simple_arm"
fi

echo "Build complete! Binaries in $OUT_DIR"
ls -lh "$OUT_DIR"
```

### Binary Verification Script

```bash
#!/bin/bash
# tests/fixtures/binaries/scripts/verify_binaries.sh
# Verify that test binaries have expected properties

OUT_DIR="$(dirname "$0")/../compiled"

echo "Verifying test binaries..."

# Check simple_x86_64
if [ -f "$OUT_DIR/simple_x86_64" ]; then
    echo "✓ simple_x86_64 exists"
    file "$OUT_DIR/simple_x86_64" | grep -q "ELF 64-bit" || echo "✗ Not 64-bit ELF"
    nm "$OUT_DIR/simple_x86_64" 2>/dev/null | grep -q "add_numbers" || echo "✗ Missing add_numbers symbol"
    nm "$OUT_DIR/simple_x86_64" 2>/dev/null | grep -q "calculate_sum" || echo "✗ Missing calculate_sum symbol"
else
    echo "✗ simple_x86_64 not found"
fi

# Check struct_heavy_x86_64
if [ -f "$OUT_DIR/struct_heavy_x86_64" ]; then
    echo "✓ struct_heavy_x86_64 exists"
    nm "$OUT_DIR/struct_heavy_x86_64" 2>/dev/null | grep -q "use_structs" || echo "✗ Missing use_structs symbol"
else
    echo "✗ struct_heavy_x86_64 not found"
fi

# Check xrefs_x86_64
if [ -f "$OUT_DIR/xrefs_x86_64" ]; then
    echo "✓ xrefs_x86_64 exists"
    nm "$OUT_DIR/xrefs_x86_64" 2>/dev/null | grep -q "shared_function" || echo "✗ Missing shared_function symbol"
    nm "$OUT_DIR/xrefs_x86_64" 2>/dev/null | grep -q "caller_1" || echo "✗ Missing caller_1 symbol"
else
    echo "✗ xrefs_x86_64 not found"
fi

echo "Verification complete!"
```

### Size Considerations

**Target binary sizes:**
- Simple test binaries: 4-8 KB
- Struct-heavy binaries: 8-12 KB
- Total fixture size: < 100 KB

**Git LFS consideration:** If binaries exceed 50 KB, use Git LFS to avoid bloating the repository.

---

## 4. Ghidra Headless Automation

### Overview

Ghidra provides **headless mode** for automated analysis without GUI. We'll use this to:
1. Import test binaries
2. Run auto-analysis
3. Start GhidraMCP plugin
4. Execute tests against the running server

### Headless Analyzer Basics

```bash
# Ghidra headless command structure
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    <project_location> <project_name> \
    -import <file_to_import> \
    -scriptPath <path_to_scripts> \
    -postScript <script_to_run> \
    -deleteProject  # Clean up after run
```

### Test Project Structure

```
tests/integration/
├── ghidra_headless.py           # Python wrapper for headless mode
├── scripts/                     # Ghidra Java scripts
│   ├── StartGhidraMCP.java     # Start plugin in headless mode
│   ├── ImportAndAnalyze.java   # Import binary and run analysis
│   └── ValidateProgram.java    # Verify analysis completed
├── test_service_integration.py # Service integration tests
├── test_http_endpoints.py      # HTTP endpoint tests
└── test_e2e_mcp.py             # End-to-end MCP tests
```

### Ghidra Headless Script: `StartGhidraMCP.java`

```java
// tests/integration/scripts/StartGhidraMCP.java
// Starts GhidraMCP plugin in headless mode

import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import com.lauriewired.GhidraMCPPlugin;

public class StartGhidraMCP extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("Starting GhidraMCP plugin in headless mode...");

        PluginTool tool = state.getTool();

        // Load GhidraMCPPlugin
        GhidraMCPPlugin plugin = new GhidraMCPPlugin(tool);

        // Configure plugin
        tool.getOptions("GhidraMCP")
            .setInt("Server Port", 8080);

        println("GhidraMCP plugin started on port 8080");
        println("Current program: " + currentProgram.getName());
        println("Server ready for requests");

        // Keep script running (for testing)
        // In actual tests, we'll control this from Python
    }
}
```

### Python Wrapper: `ghidra_headless.py`

```python
# tests/integration/ghidra_headless.py
"""
Wrapper for running Ghidra in headless mode with GhidraMCP plugin.
"""

import os
import subprocess
import time
import tempfile
import shutil
import signal
from pathlib import Path
from typing import Optional

class GhidraHeadless:
    """Manages Ghidra headless instances for testing."""

    def __init__(self, ghidra_install_dir: str, port: int = 8080):
        self.ghidra_install_dir = Path(ghidra_install_dir)
        self.port = port
        self.process: Optional[subprocess.Popen] = None
        self.project_dir: Optional[Path] = None

        # Validate Ghidra installation
        self.analyzer_script = self.ghidra_install_dir / "support" / "analyzeHeadless"
        if not self.analyzer_script.exists():
            raise FileNotFoundError(f"Ghidra not found at {ghidra_install_dir}")

    def start_with_binary(self, binary_path: str, project_name: str = "TestProject") -> None:
        """
        Start Ghidra headless with a binary loaded.

        Args:
            binary_path: Path to binary to analyze
            project_name: Name for the temporary project
        """
        # Create temporary project directory
        self.project_dir = Path(tempfile.mkdtemp(prefix="ghidra_test_"))

        # Build command
        cmd = [
            str(self.analyzer_script),
            str(self.project_dir),  # Project location
            project_name,           # Project name
            "-import", binary_path, # Import binary
            "-scriptPath", "tests/integration/scripts",  # Script directory
            "-postScript", "StartGhidraMCP.java",  # Start plugin after import
            "-noanalysis",  # Skip auto-analysis for faster startup (optional)
        ]

        # Set environment variables
        env = os.environ.copy()
        env["GHIDRAMCP_PORT"] = str(self.port)

        # Start process
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True
        )

        # Wait for server to be ready
        self._wait_for_server()

    def _wait_for_server(self, timeout: int = 30) -> None:
        """Wait for GhidraMCP server to be ready."""
        import requests

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"http://127.0.0.1:{self.port}/methods", timeout=1)
                if response.ok:
                    print(f"GhidraMCP server ready on port {self.port}")
                    return
            except requests.exceptions.RequestException:
                time.sleep(0.5)

        raise TimeoutError(f"GhidraMCP server did not start within {timeout} seconds")

    def stop(self) -> None:
        """Stop Ghidra headless instance and clean up."""
        if self.process:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

        # Clean up temporary project directory
        if self.project_dir and self.project_dir.exists():
            shutil.rmtree(self.project_dir)
            self.project_dir = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# Pytest fixture
import pytest

@pytest.fixture
def ghidra_simple_x86_64():
    """Fixture providing Ghidra headless with simple_x86_64 binary loaded."""
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir:
        pytest.skip("GHIDRA_INSTALL_DIR not set")

    binary_path = "tests/fixtures/binaries/compiled/simple_x86_64"
    if not os.path.exists(binary_path):
        pytest.skip(f"Test binary not found: {binary_path}")

    headless = GhidraHeadless(ghidra_dir, port=8080)
    headless.start_with_binary(binary_path)

    yield headless

    headless.stop()
```

### Configuration

Add to `pytest.ini`:

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short

# Environment variables
env =
    GHIDRA_INSTALL_DIR=/path/to/ghidra_11.3.2
    GHIDRAMCP_TEST_PORT=8080
```

---

## 5. Integration Test Framework

### Test Layer 2: Service Integration Tests

Test service classes with real Ghidra Program objects.

**File:** `tests/integration/test_service_integration.py`

```python
# tests/integration/test_service_integration.py
"""
Integration tests for GhidraMCP service classes.
Tests use real Ghidra Program objects in headless mode.
"""

import pytest
import requests
from .ghidra_headless import ghidra_simple_x86_64


class TestDecompilationService:
    """Test DecompilationService with real program."""

    def test_decompile_main_function(self, ghidra_simple_x86_64):
        """Decompile the main function from simple_x86_64."""
        response = requests.post(
            "http://127.0.0.1:8080/decompile",
            data="main"
        )

        assert response.ok
        decompiled = response.text

        # Verify basic decompilation structure
        assert "int main" in decompiled or "undefined" in decompiled
        assert "{" in decompiled  # Has function body
        assert "}" in decompiled
        assert "return" in decompiled

    def test_decompile_add_numbers(self, ghidra_simple_x86_64):
        """Decompile add_numbers function."""
        response = requests.post(
            "http://127.0.0.1:8080/decompile",
            data="add_numbers"
        )

        assert response.ok
        decompiled = response.text

        # Should have parameters
        assert "int" in decompiled
        # Should have addition operation (might be optimized)
        assert "+" in decompiled or "return" in decompiled

    def test_decompile_nonexistent_function(self, ghidra_simple_x86_64):
        """Decompiling nonexistent function should fail gracefully."""
        response = requests.post(
            "http://127.0.0.1:8080/decompile",
            data="this_function_does_not_exist"
        )

        assert "not found" in response.text.lower() or "error" in response.text.lower()

    def test_disassemble_function(self, ghidra_simple_x86_64):
        """Test disassembly output format."""
        response = requests.get(
            "http://127.0.0.1:8080/disassemble_function",
            params={"function_name": "main", "show_bytes": "true"}
        )

        assert response.ok
        disassembly = response.text

        # Should contain assembly instructions
        assert any(instr in disassembly for instr in ["mov", "push", "call", "ret"])
        # Should contain addresses (hex format)
        assert any(c in disassembly for c in "0123456789abcdef")


class TestProgramAnalyzer:
    """Test ProgramAnalyzer query functionality."""

    def test_list_methods(self, ghidra_simple_x86_64):
        """List all functions in simple_x86_64."""
        response = requests.get("http://127.0.0.1:8080/methods")

        assert response.ok
        functions = response.text.split("\n")

        # Should contain our test functions
        assert any("main" in f for f in functions)
        assert any("add_numbers" in f for f in functions)
        assert any("calculate_sum" in f for f in functions)
        assert any("process_data" in f for f in functions)

    def test_list_methods_pagination(self, ghidra_simple_x86_64):
        """Test pagination of function list."""
        # Get first 2 functions
        response = requests.get(
            "http://127.0.0.1:8080/methods",
            params={"offset": 0, "limit": 2}
        )

        assert response.ok
        functions = response.text.split("\n")
        assert len(functions) <= 2

    def test_search_functions(self, ghidra_simple_x86_64):
        """Search for functions by name pattern."""
        response = requests.get(
            "http://127.0.0.1:8080/searchFunctions",
            params={"searchTerm": "add"}
        )

        assert response.ok
        results = response.text.split("\n")

        # Should find add_numbers
        assert any("add_numbers" in r for r in results)
        # Should not find unrelated functions
        assert not any("process_data" in r for r in results)


class TestCrossReferenceAnalyzer:
    """Test cross-reference analysis."""

    def test_get_xrefs_to_shared_function(self, ghidra_simple_x86_64):
        """Test getting references to a function called by multiple callers."""
        # Note: This test requires xrefs_x86_64 binary
        # We'll use caller_function as an example

        response = requests.get(
            "http://127.0.0.1:8080/get_function_xrefs",
            params={"function_name": "add_numbers"}
        )

        assert response.ok
        xrefs = response.text.split("\n")

        # Should have at least one reference (from caller_function or main)
        assert len(xrefs) > 0
        assert any("caller_function" in ref or "main" in ref for ref in xrefs)


class TestSymbolManager:
    """Test renaming operations."""

    def test_rename_function(self, ghidra_simple_x86_64):
        """Test renaming a function."""
        # Rename add_numbers to add_two_numbers
        response = requests.post(
            "http://127.0.0.1:8080/renameFunction",
            data="add_numbers|add_two_numbers"
        )

        assert response.ok
        assert "success" in response.text.lower() or "renamed" in response.text.lower()

        # Verify the rename by listing functions
        list_response = requests.get("http://127.0.0.1:8080/methods")
        functions = list_response.text.split("\n")

        assert any("add_two_numbers" in f for f in functions)
        assert not any("add_numbers" == f.strip() for f in functions)  # Old name gone
```

### Test Layer 3: HTTP Endpoint Tests

More comprehensive HTTP endpoint testing with edge cases.

**File:** `tests/integration/test_http_endpoints.py`

```python
# tests/integration/test_http_endpoints.py
"""
HTTP endpoint integration tests.
Tests all 40+ endpoints with various input combinations.
"""

import pytest
import requests
from .ghidra_headless import ghidra_simple_x86_64


class TestQueryEndpoints:
    """Test all query endpoints."""

    @pytest.mark.parametrize("endpoint", [
        "/methods",
        "/classes",
        "/segments",
        "/imports",
        "/exports",
        "/namespaces",
        "/data",
        "/strings",
    ])
    def test_query_endpoints_return_200(self, ghidra_simple_x86_64, endpoint):
        """All query endpoints should return 200 OK."""
        response = requests.get(f"http://127.0.0.1:8080{endpoint}")
        assert response.status_code == 200

    def test_pagination_parameters(self, ghidra_simple_x86_64):
        """Test that pagination parameters are respected."""
        # No pagination
        response1 = requests.get("http://127.0.0.1:8080/methods")
        all_items = response1.text.split("\n")

        # With pagination
        response2 = requests.get(
            "http://127.0.0.1:8080/methods",
            params={"offset": 0, "limit": 2}
        )
        paginated = response2.text.split("\n")

        assert len(paginated) <= 2
        assert paginated[0] == all_items[0]  # First item matches

    def test_invalid_pagination_parameters(self, ghidra_simple_x86_64):
        """Test error handling for invalid pagination."""
        response = requests.get(
            "http://127.0.0.1:8080/methods",
            params={"offset": -1, "limit": -5}
        )

        # Should handle gracefully (either error or default to valid params)
        assert response.status_code in [200, 400]


class TestDecompilationEndpoints:
    """Test decompilation and disassembly endpoints."""

    def test_decompile_by_name(self, ghidra_simple_x86_64):
        """POST /decompile with function name."""
        response = requests.post(
            "http://127.0.0.1:8080/decompile",
            data="main"
        )

        assert response.ok
        assert len(response.text) > 0

    def test_decompile_by_address(self, ghidra_simple_x86_64):
        """GET /decompile_function with address."""
        # First, get the address of main
        methods = requests.get("http://127.0.0.1:8080/methods").text
        # Parse address from methods list (format: "address:function_name")
        main_line = [line for line in methods.split("\n") if "main" in line][0]
        address = main_line.split(":")[0].strip()

        response = requests.get(
            "http://127.0.0.1:8080/decompile_function",
            params={"address": address}
        )

        assert response.ok
        assert len(response.text) > 0

    def test_disassemble_with_bytes(self, ghidra_simple_x86_64):
        """Test disassembly with show_bytes parameter."""
        response = requests.get(
            "http://127.0.0.1:8080/disassemble_function",
            params={"function_name": "main", "show_bytes": "true"}
        )

        assert response.ok
        disassembly = response.text

        # Should contain byte sequences (hex digits)
        assert any(c in "0123456789abcdef" for c in disassembly.lower())

    def test_disassemble_without_bytes(self, ghidra_simple_x86_64):
        """Test disassembly without bytes (default)."""
        response = requests.get(
            "http://127.0.0.1:8080/disassemble_function",
            params={"function_name": "main", "show_bytes": "false"}
        )

        assert response.ok


class TestModificationEndpoints:
    """Test modification endpoints (renaming, type setting)."""

    def test_rename_function_and_revert(self, ghidra_simple_x86_64):
        """Test renaming a function and reverting."""
        # Rename
        response1 = requests.post(
            "http://127.0.0.1:8080/renameFunction",
            data="process_data|process_data_renamed"
        )
        assert response1.ok

        # Verify rename
        methods = requests.get("http://127.0.0.1:8080/methods").text
        assert "process_data_renamed" in methods

        # Revert
        response2 = requests.post(
            "http://127.0.0.1:8080/renameFunction",
            data="process_data_renamed|process_data"
        )
        assert response2.ok

    def test_set_function_prototype(self, ghidra_simple_x86_64):
        """Test setting a function prototype."""
        response = requests.post(
            "http://127.0.0.1:8080/set_function_prototype",
            data="add_numbers|int add_numbers(int a, int b)"
        )

        assert response.ok

        # Decompile and verify parameter names
        decomp = requests.post("http://127.0.0.1:8080/decompile", data="add_numbers").text
        # Parameter names might or might not appear depending on Ghidra version
        # Just verify it doesn't error


class TestErrorHandling:
    """Test error handling across all endpoints."""

    def test_decompile_invalid_function(self, ghidra_simple_x86_64):
        """Decompiling nonexistent function."""
        response = requests.post(
            "http://127.0.0.1:8080/decompile",
            data="nonexistent_function_12345"
        )

        assert "error" in response.text.lower() or "not found" in response.text.lower()

    def test_invalid_address_format(self, ghidra_simple_x86_64):
        """Test with invalid address format."""
        response = requests.get(
            "http://127.0.0.1:8080/decompile_function",
            params={"address": "invalid_address_xyz"}
        )

        # Should return error (not crash)
        assert response.status_code in [200, 400]

    def test_rename_to_empty_name(self, ghidra_simple_x86_64):
        """Renaming to empty string should fail."""
        response = requests.post(
            "http://127.0.0.1:8080/renameFunction",
            data="main|"
        )

        assert "error" in response.text.lower() or "invalid" in response.text.lower()
```

---

## 6. End-to-End Test Scenarios

### Test Layer 4: Full MCP Stack Testing

Test the complete flow from MCP client through bridge to Ghidra.

**File:** `tests/integration/test_e2e_mcp.py`

```python
# tests/integration/test_e2e_mcp.py
"""
End-to-end tests for the full MCP stack:
MCP Client → bridge_mcp_ghidra.py → HTTP → GhidraMCP Plugin → Ghidra
"""

import pytest
import subprocess
import time
import requests
from pathlib import Path


class TestMCPBridge:
    """Test MCP bridge with real Ghidra backend."""

    @pytest.fixture
    def mcp_server(self, ghidra_simple_x86_64):
        """Start MCP bridge server."""
        # Start bridge_mcp_ghidra.py
        process = subprocess.Popen(
            ["python", "bridge_mcp_ghidra.py", "--transport", "stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        time.sleep(2)  # Wait for server to start

        yield process

        process.terminate()
        process.wait()

    def test_list_methods_tool(self, mcp_server):
        """Test list_methods MCP tool."""
        # Send MCP tool call
        tool_call = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_methods",
                "arguments": {}
            }
        }

        # This would use MCP client library in real implementation
        # For now, we test the HTTP endpoint directly
        response = requests.get("http://127.0.0.1:8080/methods")
        assert response.ok

    def test_decompile_function_tool(self, mcp_server):
        """Test decompile_function MCP tool."""
        # Test via HTTP (in real test, would use MCP client)
        response = requests.post(
            "http://127.0.0.1:8080/decompile",
            data="main"
        )

        assert response.ok
        assert "int" in response.text or "void" in response.text


class TestToolConfiguration:
    """Test tool enabling/disabling via configuration."""

    def test_disabled_tools_not_exposed(self):
        """Tools disabled in config should not be exposed."""
        # This requires starting bridge with custom config
        # Example: config disables modification tools

        config_content = """
[server]
ghidra_server = "http://127.0.0.1:8080/"

[tools]
enable_modification = false
"""

        # Write config and start bridge
        # Verify modification tools are not listed
        # Implementation depends on MCP client library
        pass


class TestRealWorldWorkflows:
    """Test realistic reverse engineering workflows."""

    def test_analyze_and_rename_workflow(self, ghidra_simple_x86_64):
        """
        Realistic workflow:
        1. List functions
        2. Decompile interesting function
        3. Rename function
        4. Verify rename in function list
        """
        # Step 1: List functions
        methods_response = requests.get("http://127.0.0.1:8080/methods")
        assert methods_response.ok
        functions = methods_response.text.split("\n")

        # Step 2: Decompile add_numbers
        decomp_response = requests.post(
            "http://127.0.0.1:8080/decompile",
            data="add_numbers"
        )
        assert decomp_response.ok
        decompiled = decomp_response.text
        assert "return" in decompiled

        # Step 3: Rename based on understanding
        rename_response = requests.post(
            "http://127.0.0.1:8080/renameFunction",
            data="add_numbers|add_two_integers"
        )
        assert rename_response.ok

        # Step 4: Verify in list
        verify_response = requests.get("http://127.0.0.1:8080/methods")
        assert "add_two_integers" in verify_response.text

    def test_xref_analysis_workflow(self, ghidra_simple_x86_64):
        """
        Workflow for analyzing cross-references:
        1. Find a function of interest
        2. Get all callers
        3. Decompile each caller
        """
        # Step 1: Find caller_function
        methods = requests.get("http://127.0.0.1:8080/methods").text
        assert "caller_function" in methods

        # Step 2: Get XRefs to add_numbers
        xrefs_response = requests.get(
            "http://127.0.0.1:8080/get_function_xrefs",
            params={"function_name": "add_numbers"}
        )
        assert xrefs_response.ok
        xrefs = xrefs_response.text.split("\n")

        # Step 3: Decompile callers
        for xref in xrefs:
            if "caller_function" in xref:
                decomp = requests.post(
                    "http://127.0.0.1:8080/decompile",
                    data="caller_function"
                )
                assert decomp.ok
                assert "add_numbers" in decomp.text or "add_two_integers" in decomp.text
```

---

## 7. CI/CD Integration

### Updated GitHub Actions Workflow

**File:** `.github/workflows/build_and_test.yml`

```yaml
name: Build and Test

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  unit-tests:
    name: Unit Tests
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up JDK 21
        uses: actions/setup-java@v3
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'maven'

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install Python dependencies
        run: |
          pip install -r requirements.txt

      - name: Run Java unit tests
        run: mvn test

      - name: Run Python unit tests
        run: pytest tests/test_*.py -v

  integration-tests:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: unit-tests

    steps:
      - uses: actions/checkout@v3

      - name: Set up JDK 21
        uses: actions/setup-java@v3
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'maven'

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Download Ghidra
        run: |
          wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip
          unzip ghidra_11.3.2_PUBLIC_20250415.zip
          mv ghidra_11.3.2_PUBLIC ghidra

      - name: Build test binaries
        run: |
          sudo apt-get update
          sudo apt-get install -y gcc g++
          cd tests/fixtures/binaries/scripts
          chmod +x build_all.sh
          ./build_all.sh

      - name: Extract Ghidra JARs
        run: |
          mkdir -p lib
          cp ghidra/Ghidra/Framework/Generic/lib/Generic.jar lib/
          cp ghidra/Ghidra/Features/Decompiler/lib/Decompiler.jar lib/
          # ... copy other required JARs

      - name: Build GhidraMCP plugin
        run: mvn package

      - name: Install plugin
        run: |
          mkdir -p ghidra/Ghidra/Extensions
          cp target/GhidraMCP-1.0-SNAPSHOT.zip ghidra/Ghidra/Extensions/
          cd ghidra/Ghidra/Extensions
          unzip GhidraMCP-1.0-SNAPSHOT.zip

      - name: Install Python test dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest-timeout

      - name: Run integration tests
        env:
          GHIDRA_INSTALL_DIR: ${{ github.workspace }}/ghidra
        run: |
          pytest tests/integration/ -v --timeout=60

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: |
            target/surefire-reports/
            pytest-report.xml

  build:
    name: Build Artifacts
    runs-on: ubuntu-latest
    needs: integration-tests

    steps:
      - uses: actions/checkout@v3

      - name: Set up JDK 21
        uses: actions/setup-java@v3
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'maven'

      - name: Download Ghidra
        run: |
          wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip
          unzip ghidra_11.3.2_PUBLIC_20250415.zip
          mv ghidra_11.3.2_PUBLIC ghidra

      - name: Extract JARs
        run: ./copy_libs.sh ghidra

      - name: Build with Maven
        run: mvn package

      - name: Create release directory
        run: |
          mkdir -p release
          cp target/GhidraMCP-1.0-SNAPSHOT.zip release/
          cp bridge_mcp_ghidra.py release/
          cp tool_tracker.py release/
          cp requirements.txt release/

      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: ghidramcp-release
          path: release/
```

### Test Coverage Reporting

Add to `pom.xml`:

```xml
<plugin>
    <groupId>org.jacoco</groupId>
    <artifactId>jacoco-maven-plugin</artifactId>
    <version>0.8.10</version>
    <executions>
        <execution>
            <goals>
                <goal>prepare-agent</goal>
            </goals>
        </execution>
        <execution>
            <id>report</id>
            <phase>test</phase>
            <goals>
                <goal>report</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

Add to `requirements.txt`:

```
pytest-cov>=4.1.0
```

Update pytest command:

```bash
pytest tests/ --cov=bridge_mcp_ghidra --cov-report=html --cov-report=xml
```

---

## 8. Mock Improvement Strategy

### Current Mocking Limitations

**Problems with current mocks:**
- Mockito mocks don't capture Ghidra API complexity
- No validation of mock behavior against real Ghidra
- Mocks can drift from real implementation

### Solution: Record/Replay Pattern

**Concept:** Record real Ghidra responses during integration tests, replay in unit tests.

**File:** `tests/fixtures/responses/`

```
tests/fixtures/responses/
├── decompile_main.json           # Recorded decompilation
├── disassemble_add_numbers.json  # Recorded disassembly
├── xrefs_to_shared_function.json # Recorded XRefs
└── struct_point.json             # Recorded struct info
```

**Example:** Record decompilation response

```java
// tests/RecordResponsesTest.java
// Run once to record responses from real Ghidra

public class RecordResponsesTest {

    @Test
    public void recordDecompileResponse() throws Exception {
        // Load real program
        Program program = loadProgram("simple_x86_64");

        // Call real service
        DecompilationService service = new DecompilationService(...);
        String result = service.decompileFunction(program, "main");

        // Save to file
        Files.writeString(
            Path.of("tests/fixtures/responses/decompile_main.json"),
            toJson(result)
        );
    }
}
```

**Example:** Replay in unit test

```java
// tests/unit/DecompilationServiceMockTest.java

public class DecompilationServiceMockTest {

    @Test
    public void testDecompileMainMocked() throws Exception {
        // Load recorded response
        String expected = Files.readString(
            Path.of("tests/fixtures/responses/decompile_main.json")
        );

        // Mock Program
        Program mockProgram = mock(Program.class);
        Function mockFunction = mock(Function.class);
        when(mockProgram.getFunctionManager().getFunction("main"))
            .thenReturn(mockFunction);

        // Mock decompiler to return recorded response
        DecompileInterface mockDecompiler = mock(DecompileInterface.class);
        DecompileResults mockResults = mock(DecompileResults.class);
        when(mockResults.getDecompiledFunction())
            .thenReturn(parseDecompiledFunction(expected));

        // Test that service produces expected output
        // ...
    }
}
```

### Contract Testing

Define contracts between services and Ghidra APIs.

**File:** `tests/contracts/DecompilationContract.java`

```java
// tests/contracts/DecompilationContract.java
// Defines expected behavior of DecompilationService

public interface DecompilationContract {

    /**
     * Decompiling a valid function should return C code.
     */
    @Test
    default void decompile_validFunction_returnsCode() {
        String result = decompileFunction("main");
        assertThat(result).contains("{");
        assertThat(result).contains("}");
        assertThat(result).contains("return");
    }

    /**
     * Decompiling nonexistent function should return error message.
     */
    @Test
    default void decompile_invalidFunction_returnsError() {
        String result = decompileFunction("nonexistent");
        assertThat(result).containsIgnoringCase("error");
    }

    // Implement in both mock tests and integration tests
    String decompileFunction(String name);
}
```

**Usage:**

```java
// Unit test with mocks
public class DecompilationServiceMockTest implements DecompilationContract {
    @Override
    public String decompileFunction(String name) {
        // Use mocked service
        return mockedService.decompile(mockProgram, name);
    }
}

// Integration test with real Ghidra
public class DecompilationServiceIntegrationTest implements DecompilationContract {
    @Override
    public String decompileFunction(String name) {
        // Use real service with real program
        return realService.decompile(realProgram, name);
    }
}
```

This ensures mocks and real implementation both pass the same contract tests.

---

## 9. Performance Testing

### Load Testing

Test performance under realistic load.

**File:** `tests/performance/test_load.py`

```python
# tests/performance/test_load.py
"""
Performance and load testing for GhidraMCP.
"""

import pytest
import requests
import time
import concurrent.futures
from statistics import mean, median, stdev


class TestPerformance:
    """Performance benchmarks."""

    def test_decompile_performance(self, ghidra_simple_x86_64):
        """Measure decompilation time."""
        times = []

        for _ in range(10):
            start = time.time()
            response = requests.post(
                "http://127.0.0.1:8080/decompile",
                data="main"
            )
            end = time.time()

            assert response.ok
            times.append(end - start)

        print(f"Decompile times (10 runs):")
        print(f"  Mean: {mean(times):.3f}s")
        print(f"  Median: {median(times):.3f}s")
        print(f"  StdDev: {stdev(times):.3f}s")
        print(f"  Min: {min(times):.3f}s")
        print(f"  Max: {max(times):.3f}s")

        # Performance assertions
        assert mean(times) < 1.0, "Decompilation too slow"

    def test_concurrent_requests(self, ghidra_simple_x86_64):
        """Test concurrent request handling."""
        def make_request():
            response = requests.get("http://127.0.0.1:8080/methods")
            return response.ok

        # Send 20 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request) for _ in range(20)]
            results = [f.result() for f in futures]

        # All should succeed
        assert all(results)

    def test_large_function_list_pagination(self, ghidra_simple_x86_64):
        """Test pagination performance with large result sets."""
        # Request 1000 functions
        start = time.time()
        response = requests.get(
            "http://127.0.0.1:8080/methods",
            params={"limit": 1000}
        )
        end = time.time()

        assert response.ok
        assert (end - start) < 2.0, "Pagination too slow"
```

### Memory Testing

Test for memory leaks.

**File:** `tests/performance/test_memory.py`

```python
# tests/performance/test_memory.py
"""
Memory leak testing.
"""

import pytest
import requests
import psutil
import os


class TestMemory:
    """Memory usage tests."""

    def test_no_memory_leak_decompile(self, ghidra_simple_x86_64):
        """Verify decompilation doesn't leak memory."""
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Decompile 100 times
        for _ in range(100):
            response = requests.post(
                "http://127.0.0.1:8080/decompile",
                data="main"
            )
            assert response.ok

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        print(f"Memory: {initial_memory:.1f}MB -> {final_memory:.1f}MB (+{memory_increase:.1f}MB)")

        # Allow small increase (JVM warmup, caching) but not massive leak
        assert memory_increase < 50, f"Possible memory leak: +{memory_increase}MB"
```

---

## 10. Implementation Roadmap

### Phase 1: Foundation (Week 1-2)

**Deliverables:**
- [ ] Create test binary fixtures
  - [ ] Write `simple_x86_64.c`
  - [ ] Write `struct_heavy_x86_64.c`
  - [ ] Write `xrefs_x86_64.c`
  - [ ] Write `namespace_cpp_x86_64.cpp`
  - [ ] Create `build_all.sh`
  - [ ] Create `verify_binaries.sh`
  - [ ] Build and commit binaries (or use Git LFS)

- [ ] Set up Ghidra headless wrapper
  - [ ] Write `ghidra_headless.py`
  - [ ] Write `StartGhidraMCP.java`
  - [ ] Create pytest fixtures
  - [ ] Test manual headless startup

- [ ] Configure CI/CD
  - [ ] Update `.github/workflows/build_and_test.yml`
  - [ ] Add Ghidra download step
  - [ ] Add test binary build step
  - [ ] Test workflow locally with `act` tool

**Success Criteria:**
- Build script produces valid binaries
- Ghidra headless starts successfully
- Plugin loads in headless mode
- CI workflow passes

### Phase 2: Integration Tests (Week 3-4)

**Deliverables:**
- [ ] Service integration tests (`test_service_integration.py`)
  - [ ] TestDecompilationService (5 tests)
  - [ ] TestProgramAnalyzer (5 tests)
  - [ ] TestCrossReferenceAnalyzer (3 tests)
  - [ ] TestSymbolManager (3 tests)

- [ ] HTTP endpoint tests (`test_http_endpoints.py`)
  - [ ] TestQueryEndpoints (10 tests)
  - [ ] TestDecompilationEndpoints (5 tests)
  - [ ] TestModificationEndpoints (5 tests)
  - [ ] TestErrorHandling (5 tests)

**Success Criteria:**
- 30+ integration tests pass
- Tests run in < 3 minutes
- Coverage for all major service classes

### Phase 3: End-to-End Tests (Week 5)

**Deliverables:**
- [ ] E2E MCP tests (`test_e2e_mcp.py`)
  - [ ] TestMCPBridge (3 tests)
  - [ ] TestToolConfiguration (2 tests)
  - [ ] TestRealWorldWorkflows (5 tests)

- [ ] Struct service tests
  - [ ] Create test with `struct_heavy_x86_64`
  - [ ] Test C code parsing
  - [ ] Test field operations
  - [ ] Test struct queries

**Success Criteria:**
- 10+ E2E tests pass
- Full MCP stack tested
- Tool configuration validated

### Phase 4: Advanced Testing (Week 6)

**Deliverables:**
- [ ] Performance tests (`test_load.py`, `test_memory.py`)
- [ ] Mock improvement (record/replay pattern)
- [ ] Contract testing framework
- [ ] BSim integration tests

**Success Criteria:**
- Performance benchmarks established
- No memory leaks detected
- Mocks validated against real behavior

### Phase 5: Documentation and Polish (Week 7)

**Deliverables:**
- [ ] Update README with testing instructions
- [ ] Write `TESTING.md` guide
- [ ] Add test coverage badges
- [ ] Document expected test times
- [ ] Create troubleshooting guide

**Success Criteria:**
- New contributors can run tests
- CI/CD workflow is stable
- Test coverage > 70%

---

## Maintenance and Continuous Improvement

### Test Maintenance Guidelines

1. **Update tests when features change**
   - Add new integration tests for new tools
   - Update expected responses when output format changes

2. **Monitor test execution time**
   - Keep unit tests under 10 seconds
   - Keep integration tests under 3 minutes
   - Investigate slow tests

3. **Review test failures promptly**
   - Don't ignore flaky tests
   - Fix root cause, not symptoms
   - Update fixtures if Ghidra behavior changes

4. **Keep test binaries minimal**
   - Remove unused binaries
   - Compress large binaries
   - Document binary purpose

### Metrics to Track

| Metric | Target | Measurement |
|--------|--------|-------------|
| Test Coverage | > 70% | JaCoCo + pytest-cov |
| Unit Test Time | < 10s | CI logs |
| Integration Test Time | < 3min | CI logs |
| E2E Test Time | < 5min | CI logs |
| Test Pass Rate | > 95% | CI history |
| Flaky Test Rate | < 2% | CI history |

### Future Enhancements

**Year 1:**
- Add ARM test binaries
- Add MIPS test binaries
- Test with Ghidra 11.4+
- Add regression test suite

**Year 2:**
- Automated fuzz testing
- Chaos engineering (network failures, timeouts)
- Multi-platform testing (Windows, macOS)
- Performance regression testing

---

## Appendix A: Quick Start Guide

### Running Tests Locally

```bash
# 1. Build test binaries
cd tests/fixtures/binaries/scripts
./build_all.sh

# 2. Set environment variables
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.3.2

# 3. Run unit tests
pytest tests/test_*.py -v

# 4. Run integration tests (requires Ghidra)
pytest tests/integration/ -v

# 5. Run all tests
./build_and_test.sh
```

### Environment Setup

```bash
# Install dependencies
pip install -r requirements.txt
sudo apt-get install gcc g++ maven

# Download Ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip
unzip ghidra_11.3.2_PUBLIC_20250415.zip
export GHIDRA_INSTALL_DIR=$PWD/ghidra_11.3.2_PUBLIC
```

### Troubleshooting

**Problem:** "GHIDRA_INSTALL_DIR not set"
**Solution:** Export the variable: `export GHIDRA_INSTALL_DIR=/path/to/ghidra`

**Problem:** "Test binary not found"
**Solution:** Run `tests/fixtures/binaries/scripts/build_all.sh`

**Problem:** "GhidraMCP server did not start"
**Solution:** Check that plugin is installed and Ghidra headless is working

**Problem:** Tests are slow
**Solution:** Run subset of tests: `pytest tests/integration/test_service_integration.py::TestDecompilationService -v`

---

## Appendix B: Test Binary Reference

### simple_x86_64

**Purpose:** Basic decompilation, disassembly, renaming
**Functions:** main, add_numbers, calculate_sum, process_data, caller_function
**Size:** ~4 KB
**Architecture:** x86-64 ELF

### struct_heavy_x86_64

**Purpose:** Struct operations, data type testing
**Structs:** Point, Rectangle, DataBlock, Node, Value
**Size:** ~8 KB
**Architecture:** x86-64 ELF

### xrefs_x86_64

**Purpose:** Cross-reference analysis
**Functions:** leaf_function, shared_function, caller_1, caller_2, conditional_caller
**XRefs:** Multiple callers to shared_function, data references to globals
**Size:** ~6 KB
**Architecture:** x86-64 ELF

### namespace_cpp_x86_64

**Purpose:** C++ namespace handling
**Namespaces:** MyApp::Utils, std::chrono
**Size:** ~10 KB
**Architecture:** x86-64 ELF

---

## Conclusion

This comprehensive real-world testing strategy addresses the current manual testing burden by:

1. **Automating integration testing** with Ghidra headless mode
2. **Creating purpose-built test binaries** for consistent, reproducible testing
3. **Testing the full stack** from MCP client to Ghidra analysis
4. **Integrating into CI/CD** for every commit and pull request
5. **Improving test reliability** with better mocking and contract testing

**Expected outcomes:**
- Reduce manual testing time by 80%
- Catch regressions before merge
- Increase confidence in new features
- Enable faster development cycles

**Total implementation effort:** ~7 weeks for complete implementation

**Next steps:**
1. Review and approve this strategy
2. Create GitHub issues for each phase
3. Begin Phase 1: Foundation
4. Iterate based on feedback
