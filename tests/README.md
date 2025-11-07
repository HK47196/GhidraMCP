# Python Test Suite

This directory contains the Python test suite for the GhidraMCP bridge.

## Overview

The test suite uses pytest and pytest-mock to test the MCP bridge functionality,
including HTTP client helpers and MCP tool implementations.

## Running Tests

```bash
# Install test dependencies
pip install -r requirements.txt

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_bridge_mcp_ghidra.py

# Run specific test class
pytest tests/test_bridge_mcp_ghidra.py::TestSafeGet

# Run specific test
pytest tests/test_bridge_mcp_ghidra.py::TestSafeGet::test_safe_get_success
```

## Test Coverage

The test suite covers:

- **HTTP Client Functions**: `safe_get()` and `safe_post()` with various scenarios
  - Successful requests
  - Error responses (4xx, 5xx)
  - Network exceptions
  - Timeout handling
  - Different data types (string, dict)

- **MCP Tools**: Various tool implementations
  - `list_methods()`
  - `list_classes()`
  - `list_segments()`
  - `decompile_function()`
  - `rename_function()`
  - `rename_data()`

- **Configuration**: Global configuration variables

- **Edge Cases**: Empty responses, null values, boundary conditions

## Test Structure

```
tests/
├── __init__.py                    # Package marker
├── test_bridge_mcp_ghidra.py     # Main test file
└── README.md                      # This file
```

## Writing New Tests

When adding new tools or functionality to `bridge_mcp_ghidra.py`:

1. Add corresponding test class in `test_bridge_mcp_ghidra.py`
2. Mock external HTTP calls using `@patch`
3. Test both success and failure scenarios
4. Include edge cases (empty, null, invalid input)

Example:
```python
@patch('bridge_mcp_ghidra.safe_post')
def test_new_tool(self, mock_safe_post):
    mock_safe_post.return_value = "Expected result"

    result = bridge_mcp_ghidra.new_tool("param")

    assert result == "Expected result"
    mock_safe_post.assert_called_once_with("endpoint", "param")
```

## Continuous Integration

Tests are automatically run as part of the CI/CD pipeline when:
- Pull requests are created
- Code is pushed to main branches
- Manual workflow triggers

See `.github/workflows/` for CI configuration.
