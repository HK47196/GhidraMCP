# E2E Testing Quick Start Guide

## Prerequisites Check

Before running the tests, ensure you have:

1. **Ghidra** - Installed (tested with 11.4.2)
   ```bash
   # Check if Ghidra is installed
   ls /opt/ghidra  # or your Ghidra installation directory
   ```

2. **Python 3.11+**
   ```bash
   python3 --version
   ```

3. **Xvfb** (for headless testing on Linux)
   ```bash
   sudo apt-get install xvfb
   ```

4. **Maven** (for building the plugin)
   ```bash
   mvn --version
   ```

5. **Java 21**
   ```bash
   java --version
   ```

## Step-by-Step Setup

### Step 1: Build the Plugin

From the repository root:

```bash
# Build the plugin (this creates target/GhidraMCP-1.0-SNAPSHOT.zip)
mvn clean package
```

Expected output:
```
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Final artifact: target/GhidraMCP-1.0-SNAPSHOT.zip
```

Verify the plugin was created:
```bash
ls -lh target/GhidraMCP-1.0-SNAPSHOT.zip
```

### Step 2: Install Python Test Dependencies

```bash
# Install test dependencies
pip install -r requirements-test.txt
```

This installs:
- pytest
- pytest-timeout  
- requests
- mcp

### Step 3: Verify Test Binary

The test binary should already be built, but verify:

```bash
ls -lh tests/fixtures/binaries/test_simple
```

If missing, rebuild it:
```bash
./tests/fixtures/build_test_binary.sh
```

### Step 4: Run the Tests

#### Basic test run (using default Ghidra location):

```bash
pytest tests/e2e/ --ghidra-dir=/opt/ghidra
```

#### Specify your Ghidra installation:

```bash
pytest tests/e2e/ --ghidra-dir=/path/to/your/ghidra_11.4.2_PUBLIC
```

#### Run without Xvfb (if you have a display):

```bash
pytest tests/e2e/ --ghidra-dir=/opt/ghidra --no-xvfb
```

#### Run with verbose output:

```bash
pytest tests/e2e/ \
  --ghidra-dir=/opt/ghidra \
  --verbose-ghidra \
  -vv
```

#### Run a specific test:

```bash
pytest tests/e2e/test_mcp_basic_queries.py::TestMCPBasicQueries::test_tools_are_available \
  --ghidra-dir=/opt/ghidra \
  -v
```

#### Keep test project for debugging:

```bash
pytest tests/e2e/ \
  --ghidra-dir=/opt/ghidra \
  --keep-project
```

## Expected Test Output

When tests run successfully, you should see:

```
2025-11-16 10:30:00 [INFO] ============================================================
2025-11-16 10:30:00 [INFO] Starting Ghidra Runner
2025-11-16 10:30:00 [INFO] ============================================================
2025-11-16 10:30:00 [INFO] Starting Xvfb on display :99
2025-11-16 10:30:02 [INFO] Xvfb started on display :99
2025-11-16 10:30:02 [INFO] Installing plugin to /home/user/.ghidra/.ghidra_11.4.2_PUBLIC/Extensions
2025-11-16 10:30:02 [INFO] Extracted plugin from target/GhidraMCP-1.0-SNAPSHOT.zip
2025-11-16 10:30:02 [INFO] Importing test_simple into Ghidra project
2025-11-16 10:30:15 [INFO] Binary import completed
2025-11-16 10:30:15 [INFO] Starting Ghidra GUI with project: /tmp/ghidra_test_xyz/TestProject.gpr
2025-11-16 10:30:20 [INFO] Ghidra GUI process started
2025-11-16 10:30:20 [INFO] Waiting for HTTP server on port 8080
2025-11-16 10:30:25 [INFO] HTTP server is ready on port 8080
2025-11-16 10:30:25 [INFO] Ghidra Runner started successfully
2025-11-16 10:30:25 [INFO] ============================================================
2025-11-16 10:30:26 [INFO] Starting MCP bridge server
2025-11-16 10:30:28 [INFO] MCP bridge server started

tests/e2e/test_mcp_basic_queries.py::TestMCPBasicQueries::test_tools_are_available PASSED
tests/e2e/test_mcp_basic_queries.py::TestMCPBasicQueries::test_query_list_functions PASSED
...
```

## Troubleshooting

### Plugin not found

**Error:**
```
SKIPPED (Plugin not found. Please build the plugin first with: mvn clean package)
```

**Solution:**
```bash
mvn clean package
ls -lh target/GhidraMCP-1.0-SNAPSHOT.zip  # Verify it exists
```

### Xvfb not found

**Error:**
```
FileNotFoundError: [Errno 2] No such file or directory: 'Xvfb'
```

**Solution:**
```bash
sudo apt-get install xvfb
```

Or run without Xvfb:
```bash
pytest tests/e2e/ --ghidra-dir=/opt/ghidra --no-xvfb
```

### Ghidra not found

**Error:**
```
FileNotFoundError: Ghidra directory not found: /opt/ghidra
```

**Solution:**
```bash
pytest tests/e2e/ --ghidra-dir=/path/to/your/ghidra
```

### Tests timeout

**Error:**
```
TIMEOUT after 300s
```

**Solution:**
Increase timeout:
```bash
pytest tests/e2e/ --timeout=600 --ghidra-dir=/opt/ghidra
```

### Port 8080 already in use

**Error:**
```
Address already in use
```

**Solution:**
```bash
# Find and kill the process using port 8080
lsof -ti:8080 | xargs kill -9
```

## Test Suite Overview

The E2E tests validate the complete MCP integration stack:

1. **test_mcp_basic_queries.py** - Basic operations
   - Tool availability
   - List functions
   - Get current function
   - Manual command

2. **test_mcp_decompilation.py** - Decompilation
   - Decompile function
   - Disassemble function

3. **test_mcp_modifications.py** - Program modifications
   - Rename function
   - Set decompiler comment

4. **test_mcp_struct_ops.py** - Struct operations
   - Create struct
   - Add struct field
   - Get struct info

## Architecture

```
┌─────────────┐
│  pytest     │
│  (test)     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  MCPClient  │  ◄── Communicates via stdio
│  (Python)   │
└──────┬──────┘
       │
       ▼
┌──────────────┐
│ bridge_mcp_  │
│ ghidra.py    │
└──────┬───────┘
       │ HTTP
       ▼
┌──────────────┐
│  Ghidra      │  ◄── Runs in Xvfb (virtual display)
│  Plugin      │
│  (Java)      │
└──────────────┘
```

## CI/CD

Tests run automatically in GitHub Actions on push/PR. See `.github/workflows/e2e-tests.yml`.

## Next Steps

Once tests pass locally:
1. Create a PR with your changes
2. Tests will run automatically in CI
3. Review test results in GitHub Actions

For more details, see `tests/README.md`.
