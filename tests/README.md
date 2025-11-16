# GhidraMCP Integration Tests

## Quick Start

### Prerequisites
- Ghidra installed (tested with 11.4.2)
- Python 3.11+
- Xvfb (Linux) or XQuartz (macOS)

### Installation

```bash
# Install Python dependencies
pip install -r requirements-test.txt

# Build test binary
./tests/fixtures/build_test_binary.sh

# Build plugin (if not already built)
# cd java && gradle buildExtension
```

### Running Tests

```bash
# Run all tests (with Xvfb)
pytest tests/e2e/

# Specify Ghidra location
pytest tests/e2e/ --ghidra-dir=/path/to/ghidra

# Run without Xvfb (if you have a display)
pytest tests/e2e/ --no-xvfb

# Keep test project for debugging
pytest tests/e2e/ --keep-project

# Verbose output
pytest tests/e2e/ --verbose-ghidra -vv

# Run specific test
pytest tests/e2e/test_mcp_basic_queries.py::TestMCPBasicQueries::test_query_list_functions
```

### Troubleshooting

**Tests timeout:**
```bash
pytest tests/e2e/ --timeout=600
```

**Ghidra won't start:**
```bash
# Check Xvfb
ps aux | grep Xvfb

# Test manually
DISPLAY=:99 /opt/ghidra/ghidraRun
```

**Plugin not loading:**
```bash
# Check plugin exists
ls ~/.ghidra/.ghidra_*/Extensions/

# Check logs
cat ~/.ghidra/.ghidra_*/application.log
```

### CI/CD

Tests run automatically on push via GitHub Actions. See `.github/workflows/e2e-tests.yml`.

## Test Structure

- `e2e/` - End-to-end integration tests
- `utils/` - Test utilities (GhidraRunner, MCPClient)
- `fixtures/` - Test data (binaries, plugin)
- `conftest.py` - pytest configuration
- `pytest.ini` - pytest settings
