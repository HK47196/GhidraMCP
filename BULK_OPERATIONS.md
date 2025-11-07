# Bulk Operations Support

## Overview

GhidraMCP now supports bulk operations, allowing you to execute multiple commands in a single request. This is more efficient than making multiple individual requests, especially when you need to perform many operations in sequence.

## Usage

### Python MCP Bridge

Use the `bulk_operations` tool to execute multiple operations:

```python
from bridge_mcp_ghidra import bulk_operations

# Example: Execute multiple operations
operations = [
    {
        "endpoint": "/methods",
        "params": {"offset": 0, "limit": 10}
    },
    {
        "endpoint": "/decompile",
        "params": {"name": "main"}
    },
    {
        "endpoint": "/rename_function_by_address",
        "params": {
            "function_address": "0x401000",
            "new_name": "initialize"
        }
    }
]

result = bulk_operations(operations)
```

### Direct HTTP API

Send a POST request to the `/bulk` endpoint:

```bash
curl -X POST http://localhost:8080/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "operations": [
      {
        "endpoint": "/methods",
        "params": {"offset": "0", "limit": "10"}
      },
      {
        "endpoint": "/decompile_function",
        "params": {"address": "0x401000"}
      }
    ]
  }'
```

## Supported Endpoints

All existing GhidraMCP endpoints are supported in bulk operations:

### Function Operations
- `/methods` - List function names
- `/list_functions` - List all functions
- `/decompile` - Decompile function by name
- `/decompile_function` - Decompile function by address
- `/disassemble_function` - Get assembly code
- `/rename_function` - Rename function by name
- `/rename_function_by_address` - Rename function by address
- `/get_function_by_address` - Get function details
- `/search_functions` - Search functions by name
- `/set_function_prototype` - Set function signature

### Program Structure
- `/classes` - List classes/namespaces
- `/segments` - List memory segments
- `/imports` - List imported symbols
- `/exports` - List exported functions
- `/namespaces` - List non-global namespaces
- `/data` - List defined data items
- `/strings` - List strings

### Code Modification
- `/rename_function` (or `/renameFunction`) - Rename function by name
- `/rename_data` (or `/renameData`) - Rename data label
- `/rename_variable` (or `/renameVariable`) - Rename local variable
- `/set_local_variable_type` - Set variable type
- `/set_decompiler_comment` - Add decompiler comment
- `/set_disassembly_comment` - Add disassembly comment
- `/set_plate_comment` - Add plate comment

### Cross-References
- `/xrefs_to` - Get references to address
- `/xrefs_from` - Get references from address
- `/function_xrefs` - Get function references

### Context
- `/get_current_address` - Get current address
- `/get_current_function` - Get current function

### BSim Integration
- `/bsim/select_database` - Connect to BSim database
- `/bsim/disconnect` - Disconnect from BSim
- `/bsim/status` - Get connection status
- `/bsim/query_function` - Query single function
- `/bsim/query_all_functions` - Query all functions
- `/bsim/get_match_disassembly` - Get match assembly
- `/bsim/get_match_decompile` - Get match decompilation

## Response Format

The bulk endpoint returns a JSON response with a `results` array:

```json
{
  "results": [
    {
      "success": true,
      "result": "function1\nfunction2\nfunction3"
    },
    {
      "success": true,
      "result": "void main() {\n  // decompiled code\n}"
    },
    {
      "success": true,
      "result": "Function renamed successfully"
    }
  ]
}
```

Each result corresponds to the operation at the same index in the request.

## Error Handling

If an individual operation fails, it will be included in the results array with an error message:

```json
{
  "results": [
    {
      "success": true,
      "result": "Error: Unknown endpoint: /invalid"
    }
  ]
}
```

If the entire bulk request fails (e.g., malformed JSON), the response will contain an error field:

```json
{
  "error": "Missing 'operations' field in JSON"
}
```

## Benefits

1. **Performance**: Reduced network overhead by batching multiple requests
2. **Atomicity**: All operations are executed in sequence within a single request
3. **Simplicity**: Single API call instead of managing multiple async requests
4. **Compatibility**: All existing endpoints work with bulk operations

## Example Use Cases

### 1. Batch Rename Functions
```python
operations = [
    {"endpoint": "/rename_function_by_address", "params": {"function_address": "0x401000", "new_name": "init"}},
    {"endpoint": "/rename_function_by_address", "params": {"function_address": "0x401100", "new_name": "cleanup"}},
    {"endpoint": "/rename_function_by_address", "params": {"function_address": "0x401200", "new_name": "process"}}
]
```

### 2. Batch Rename Data Labels
```python
operations = [
    {"endpoint": "/rename_data", "params": {"address": "0x405000", "newName": "g_config_table"}},
    {"endpoint": "/rename_data", "params": {"address": "0x405100", "newName": "g_user_data"}},
    {"endpoint": "/rename_data", "params": {"address": "0x405200", "newName": "g_error_messages"}}
]
```

### 3. Analyze Multiple Functions
```python
operations = [
    {"endpoint": "/decompile_function", "params": {"address": "0x401000"}},
    {"endpoint": "/xrefs_to", "params": {"address": "0x401000"}},
    {"endpoint": "/disassemble_function", "params": {"address": "0x401000"}}
]
```

### 4. Set Multiple Comments
```python
operations = [
    {"endpoint": "/set_decompiler_comment", "params": {"address": "0x401000", "comment": "Entry point"}},
    {"endpoint": "/set_plate_comment", "params": {"address": "0x401100", "comment": "Critical function"}},
    {"endpoint": "/set_disassembly_comment", "params": {"address": "0x401200", "comment": "TODO: Review"}}
]
```

## Notes

- Operations are executed sequentially in the order provided
- Each operation is independent; one failure doesn't stop subsequent operations
- Parameter types in JSON should be strings (they're converted internally)
- The bulk endpoint maintains backward compatibility - all single-operation endpoints still work as before
