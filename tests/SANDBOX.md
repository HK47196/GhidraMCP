# Sandbox Testing Guide

This guide explains how to run GhidraMCP E2E tests in complete isolation from your desktop Ghidra installation.

## Why Sandbox?

The E2E tests:
- Install the GhidraMCP plugin to `~/.ghidra/.ghidra_*/Extensions/`
- Create Ghidra projects
- Modify Ghidra preferences and settings
- Run a Ghidra GUI instance

**Without sandboxing, tests might interfere with your desktop Ghidra configuration!**

## Sandboxing Options

### Option 1: Isolated Directory Mode (Default - Recommended) ⭐

**What it does:**
- Creates a temporary directory for Ghidra user data
- Sets `HOME` environment variable to this temporary directory
- Ghidra uses `/tmp/ghidra_test_home_XXXXX/.ghidra/` instead of `~/.ghidra/`
- **Your desktop Ghidra remains completely untouched**

**Usage:**
```bash
# Isolated mode is DEFAULT - just run normally
pytest tests/e2e/ --ghidra-dir=/opt/ghidra

# Be explicit about isolated mode (same as default)
pytest tests/e2e/ --ghidra-dir=/opt/ghidra --isolated
```

**Verification:**
```bash
# Run with verbose output to see the isolated directory
pytest tests/e2e/ --ghidra-dir=/opt/ghidra --verbose-ghidra -v
```

Look for output like:
```
2025-11-16 10:30:00 [INFO] Using isolated Ghidra user directory: /tmp/ghidra_test_home_abc123
2025-11-16 10:30:00 [INFO] Setting isolated HOME=/tmp/ghidra_test_home_abc123
```

**Cleanup:**
The isolated directory is automatically deleted after tests complete (unless you use `--keep-project`).

---

### Option 2: Docker Container (Maximum Isolation) 🐳

**What it does:**
- Runs tests in a completely isolated Docker container
- Separate filesystem, no access to your home directory
- Includes Ghidra installation
- Perfect for CI/CD and guaranteed isolation

**Prerequisites:**
- Docker installed
- Docker Compose installed (optional, makes it easier)

**Quick Start:**

```bash
# Build and run tests in one command
cd tests/
docker-compose up --build

# Or manually build and run
docker build -t ghidra-mcp-tests -f tests/Dockerfile .
docker run --rm ghidra-mcp-tests
```

**Run specific tests:**
```bash
docker run --rm ghidra-mcp-tests \
  pytest tests/e2e/test_mcp_basic_queries.py -v
```

**Interactive shell:**
```bash
docker run --rm -it ghidra-mcp-tests bash
# Inside container:
pytest tests/e2e/ --ghidra-dir=/opt/ghidra -v
```

**Advantages:**
- ✅ Complete isolation (filesystem, network, processes)
- ✅ Reproducible environment
- ✅ Works identically on all machines
- ✅ No cleanup needed (container is deleted after)
- ✅ Doesn't require Ghidra installation on host

**Disadvantages:**
- ⚠️ Slower first build (~5-10 minutes to download Ghidra)
- ⚠️ Requires Docker installed
- ⚠️ Larger disk space usage

---

### Option 3: Non-Isolated Mode (NOT Recommended) ⚠️

**What it does:**
- Uses your actual `~/.ghidra/` directory
- Installs plugin to your real Extensions directory
- **May interfere with desktop Ghidra!**

**When to use:**
- Debugging issues with your actual Ghidra setup
- Testing plugin compatibility with existing configuration
- You know what you're doing and want to test with real settings

**Usage:**
```bash
pytest tests/e2e/ --ghidra-dir=/opt/ghidra --no-isolated
```

**⚠️ WARNING:** This will:
- Install GhidraMCP plugin to your Extensions
- Potentially modify Ghidra preferences
- Create test projects in `/tmp/`

---

## Comparison Table

| Feature | Isolated Mode | Docker | Non-Isolated |
|---------|--------------|--------|--------------|
| Setup Time | Instant | 5-10 min first time | Instant |
| Isolation Level | High | Maximum | None |
| Desktop Ghidra Safety | ✅ Safe | ✅ Safe | ❌ May interfere |
| Requires Ghidra Install | Yes (on host) | No (in container) | Yes (on host) |
| Cleanup | Automatic | Automatic | Manual |
| Speed | Fast | Medium | Fast |
| CI/CD Ready | Yes | Yes | No |

---

## Detailed Usage Examples

### Isolated Mode with Custom Options

```bash
# Keep isolated directory for inspection
pytest tests/e2e/ --ghidra-dir=/opt/ghidra --keep-project

# Find the directory
ls -d /tmp/ghidra_test_home_*

# Inspect what was created
ls -la /tmp/ghidra_test_home_*/.ghidra/
```

### Docker with Source Code Mounting

For development, mount your source code:

```bash
docker run --rm -v $(pwd):/workspace ghidra-mcp-tests \
  pytest tests/e2e/ --ghidra-dir=/opt/ghidra -v
```

This allows you to edit code on your host and run tests in the container.

### Docker with Cached Build

Speed up subsequent runs:

```bash
# Build once
docker build -t ghidra-mcp-tests -f tests/Dockerfile .

# Run many times (fast)
docker run --rm ghidra-mcp-tests
docker run --rm ghidra-mcp-tests pytest tests/e2e/test_mcp_basic_queries.py
docker run --rm ghidra-mcp-tests pytest tests/e2e/test_mcp_decompilation.py
```

---

## Verification

### Verify Isolated Mode is Working

Run this test and check the logs:

```bash
pytest tests/e2e/test_mcp_basic_queries.py::TestMCPBasicQueries::test_tools_are_available \
  --ghidra-dir=/opt/ghidra \
  --verbose-ghidra \
  -vv
```

Look for:
```
[INFO] Using isolated Ghidra user directory: /tmp/ghidra_test_home_XXXXX
[INFO] Installing plugin to /tmp/ghidra_test_home_XXXXX/.ghidra/.ghidra_11.4.2_PUBLIC/Extensions
```

Then verify your desktop Ghidra is untouched:
```bash
# Check your actual Extensions directory
ls ~/.ghidra/.ghidra_*/Extensions/
# Should NOT contain GhidraMCP unless you installed it separately
```

### Verify Docker Isolation

```bash
# Run tests in Docker
docker run --rm ghidra-mcp-tests

# Check your home directory - should be unchanged
ls ~/.ghidra/  # Should not exist or unchanged from before
```

---

## Troubleshooting

### "Using isolated mode" but plugin appears in my desktop Ghidra

**Cause:** You might have run with `--no-isolated` previously, or installed the plugin manually.

**Solution:**
```bash
# Remove plugin from your desktop Ghidra
rm -rf ~/.ghidra/.ghidra_*/Extensions/GhidraMCP

# Run tests in isolated mode
pytest tests/e2e/ --ghidra-dir=/opt/ghidra
```

### Docker build fails downloading Ghidra

**Cause:** Network issues or Ghidra download URL changed.

**Solution:**
```bash
# Check the Ghidra release URL is correct in tests/Dockerfile
# Update GHIDRA_VERSION and GHIDRA_BUILD if needed

# Or download Ghidra manually and modify Dockerfile:
# COPY ghidra_11.4.2_PUBLIC /opt/ghidra
```

### Isolated directory not cleaning up

**Cause:** Tests crashed or were interrupted.

**Solution:**
```bash
# Manually clean up
rm -rf /tmp/ghidra_test_home_*
rm -rf /tmp/ghidra_test_project_*
```

### Want to inspect isolated directory after tests

**Use `--keep-project` flag:**
```bash
pytest tests/e2e/ --ghidra-dir=/opt/ghidra --keep-project

# Find and inspect the directory
ls -la /tmp/ghidra_test_home_*/
ls -la /tmp/ghidra_test_home_*/.ghidra/
ls -la /tmp/ghidra_test_home_*/.ghidra/.ghidra_*/Extensions/
```

---

## Best Practices

1. **Default to Isolated Mode** ✅
   - Always use isolated mode unless you have a specific reason not to
   - It's enabled by default - just run `pytest tests/e2e/`

2. **Use Docker for CI/CD** ✅
   - Ensures reproducible builds
   - No setup required on build servers

3. **Never commit with `--no-isolated`** ❌
   - This flag should only be used for local debugging
   - Don't add it to CI/CD scripts

4. **Clean up manually if interrupted** 🧹
   ```bash
   # After crashes or Ctrl+C
   rm -rf /tmp/ghidra_test_*
   ```

5. **Use `--keep-project` for debugging** 🐛
   ```bash
   pytest tests/e2e/ --keep-project --verbose-ghidra -vv
   ```

---

## Summary

**For most users:**
```bash
# Just run this - it's automatically sandboxed!
mvn clean package
pytest tests/e2e/ --ghidra-dir=/opt/ghidra
```

**For maximum isolation or CI/CD:**
```bash
cd tests/
docker-compose up --build
```

**For debugging with real Ghidra (use carefully):**
```bash
pytest tests/e2e/ --ghidra-dir=/opt/ghidra --no-isolated
```

Your desktop Ghidra is safe by default! 🎉
