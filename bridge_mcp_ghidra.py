# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
import os
import functools
from pathlib import Path
from urllib.parse import urljoin
from typing import Dict, Set, Optional, Literal, Union

# TOML support for config files
try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # Python 3.10

from mcp.server.fastmcp import FastMCP
from tool_tracker import ToolTracker

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
DEFAULT_REQUEST_TIMEOUT = 60

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER
# Initialize ghidra_request_timeout with default value
ghidra_request_timeout = DEFAULT_REQUEST_TIMEOUT

# Tool categories for configuration
TOOL_CATEGORIES = {
    "query": [
        "query", "get_current_address", "get_current_function",
        "get_function_by_address", "get_data_by_address", "get_data_in_range",
        "get_function_data", "get_xrefs_to", "get_xrefs_from", "get_function_xrefs",
        "man"
    ],
    "decompile": [
        "decompile_function", "decompile_function_by_address", "disassemble_function",
        "get_address_context"
    ],
    "search": [
        "search_decompiled_text"
    ],
    "modification": [
        "rename_function", "rename_function_by_address", "rename_data",
        "rename_variable", "set_function_prototype", "set_local_variable_type",
        "set_data_type", "set_decompiler_comment", "set_disassembly_comment",
        "set_plate_comment"
    ],
    "bsim": [
        "bsim_select_database", "bsim_query_function", "bsim_query_all_functions",
        "bsim_disconnect", "bsim_status", "bsim_get_match_disassembly",
        "bsim_get_match_decompile"
    ],
    "struct": [
        "create_struct", "parse_c_struct", "add_struct_field",
        "insert_struct_field_at_offset", "replace_struct_field",
        "delete_struct_field", "clear_struct_field", "get_struct_info",
        "rename_struct", "delete_struct"
    ],
    "bulk": ["bulk_operations"]
}

# Global configuration
_enabled_tools: Optional[Set[str]] = None
_tool_registry: Dict[str, any] = {}  # Store tool functions before registration
_tools_registered: bool = False
_tool_tracker: Optional[ToolTracker] = None  # Track tool call statistics


def load_config(config_path: Optional[str] = None) -> Dict:
    """Load configuration from TOML file (defaults to mcp-config.toml)."""
    if config_path is None:
        config_path = "mcp-config.toml"

    if not os.path.exists(config_path):
        logger.info(f"No config file found at {config_path}, using default settings (all tools enabled)")
        return {"tools": {}}

    try:
        with open(config_path, "rb") as f:
            config = tomllib.load(f)
        logger.info(f"Loaded configuration from {config_path}")
        return config
    except Exception as e:
        logger.warning(f"Failed to load config file {config_path}: {e}. Using default settings.")
        return {"tools": {}}


def get_enabled_tools(config: Dict) -> Set[str]:
    """Determine enabled tools from config (categories, disabled_tools, enabled_tools)."""
    tools_config = config.get("tools", {})

    # If explicit enabled_tools list is provided, use it
    if "enabled_tools" in tools_config:
        enabled = set(tools_config["enabled_tools"])
        logger.info(f"Using explicit enabled_tools list: {len(enabled)} tools")
        return enabled

    # Otherwise, start with all tools and apply category/disabled filters
    all_tools = set()
    for category_tools in TOOL_CATEGORIES.values():
        all_tools.update(category_tools)

    enabled = set(all_tools)

    # Apply category-level filters
    for category, category_tools in TOOL_CATEGORIES.items():
        category_key = f"enable_{category}"
        if category_key in tools_config and not tools_config[category_key]:
            logger.info(f"Disabling category '{category}': {len(category_tools)} tools")
            enabled -= set(category_tools)

    # Apply individual disabled_tools filter
    if "disabled_tools" in tools_config:
        disabled = set(tools_config["disabled_tools"])
        logger.info(f"Disabling {len(disabled)} individual tools")
        enabled -= disabled

    logger.info(f"Total enabled tools: {len(enabled)}")
    return enabled


def conditional_tool(func):
    """
    Decorator that collects tool functions for later registration.
    Tools are actually registered in register_tools() after config is loaded.
    """
    tool_name = func.__name__
    _tool_registry[tool_name] = func
    return func


def register_tools():
    """
    Register tools with MCP based on configuration.
    This must be called after config is loaded.
    """
    global _tools_registered

    if _tools_registered:
        logger.warning("Tools already registered, skipping")
        return

    # If no config loaded, enable all tools (backward compatibility)
    enabled_tools = _enabled_tools if _enabled_tools is not None else set(_tool_registry.keys())

    registered_count = 0
    for tool_name, tool_func in _tool_registry.items():
        if tool_name in enabled_tools:
            # Wrap tool function with tracking if tracker is available
            if _tool_tracker is not None:
                # Create a wrapper that increments the tracker before calling the tool
                def create_tracked_wrapper(name, func):
                    @functools.wraps(func)
                    def tracked_tool(*args, **kwargs):
                        _tool_tracker.increment(name)
                        return func(*args, **kwargs)
                    return tracked_tool

                wrapped_func = create_tracked_wrapper(tool_name, tool_func)
                mcp.tool()(wrapped_func)
            else:
                mcp.tool()(tool_func)

            registered_count += 1
        else:
            logger.debug(f"Tool '{tool_name}' disabled by configuration")

    logger.info(f"Registered {registered_count} of {len(_tool_registry)} available tools")
    _tools_registered = True

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=ghidra_request_timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            # BSim queries might be a bit slower, using configurable timeout
            response = requests.post(url, data=data, timeout=ghidra_request_timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=ghidra_request_timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

# ==================== TOOL MANUAL ====================
# Detailed documentation for tools (original docstrings preserved for reference)

MANUAL = {}

MANUAL["get_data_by_address"] = """Get information about data at a specific address.

Params:
    address: Memory address in hex or segment:offset format (e.g., "5356:3cd8" or "0x1400010a0")

Returns:
    Data information including name, type, value, and size"""

MANUAL["set_data_type"] = """Set the data type at a specific address in the Ghidra program.

Params:
    address: Memory address in hex format (e.g. "0x1400010a0")
    type_name: Name of the data type to set (e.g. "int", "dword", "byte[20]", "PCHAR")

Returns:
    Success or error message"""

MANUAL["get_xrefs_to"] = """Get all references to the specified address (xref to).

Params:
    address: Target address in hex format (e.g. "0x1400010a0")
    offset: Pagination offset (default: 0)
    limit: Maximum number of references to return (default: 100)
    include_instruction: Control instruction display (default: False)
        - False: Don't include instruction text
        - True or 0: Include instruction only (e.g., "tst.l (0x3936,A4)")
        - N (int > 0): Include instruction plus N context lines before and after

Returns:
    List of references to the specified address. When include_instruction is enabled,
    each reference includes the instruction text and optional surrounding context."""

MANUAL["get_xrefs_from"] = """Get all references from the specified address (xref from).

Params:
    address: Source address in hex format (e.g. "0x1400010a0")
    offset: Pagination offset (default: 0)
    limit: Maximum number of references to return (default: 100)
    include_instruction: Control instruction display (default: False)
        - False: Don't include instruction text
        - True or 0: Include instruction only at the source address
        - N (int > 0): Include instruction plus N context lines before and after

Returns:
    List of references from the specified address. When include_instruction is enabled,
    each reference includes the instruction text at the source address with optional context."""

MANUAL["get_function_xrefs"] = """Get all references to the specified function by name.

Params:
    name: Function name to search for
    offset: Pagination offset (default: 0)
    limit: Maximum number of references to return (default: 100)
    include_instruction: Control instruction display (default: False)
        - False: Don't include instruction text
        - True or 0: Include instruction only (e.g., "call FUN_00401234")
        - N (int > 0): Include instruction plus N context lines before and after

Returns:
    List of references to the specified function. When include_instruction is enabled,
    each reference includes the instruction text with optional surrounding context."""

MANUAL["list_strings"] = """List all defined strings in the program with their addresses.

Params:
    offset: Pagination offset (default: 0)
    limit: Maximum number of strings to return (default: 2000)
    filter: Optional filter to match within string content

Returns:
    List of strings with their addresses"""

MANUAL["bsim_select_database"] = """Select and connect to a BSim database for function similarity matching.

Params:
    database_path: Path to BSim database file (e.g., "/path/to/database.bsim")
                  or URL (e.g., "postgresql://host:port/dbname")

Returns:
    Connection status and database information"""

MANUAL["bsim_query_function"] = """Query a single function against the BSim database to find similar functions.

Params:
    function_address: Address of the function to query (e.g., "0x401000")
    max_matches: Maximum number of matches to return (default: 10)
    similarity_threshold: Minimum similarity score (inclusive, 0.0-1.0, default: 0.7)
    confidence_threshold: Minimum confidence score (inclusive, 0.0-1.0, default: 0.0)
    max_similarity: Maximum similarity score (exclusive, 0.0-1.0, default: unbounded)
    max_confidence: Maximum confidence score (exclusive, 0.0-1.0, default: unbounded)
    offset: Pagination offset (default: 0)
    limit: Maximum number of results to return (default: 100)

Returns:
    List of matching functions with similarity scores and metadata"""

MANUAL["bsim_query_all_functions"] = """Query all functions in the current program against the BSim database.
Returns an overview of matches for all functions.

Params:
    max_matches_per_function: Max matches per function (default: 5)
    similarity_threshold: Minimum similarity score (inclusive, 0.0-1.0, default: 0.7)
    confidence_threshold: Minimum confidence score (inclusive, 0.0-1.0, default: 0.0)
    max_similarity: Maximum similarity score (exclusive, 0.0-1.0, default: unbounded)
    max_confidence: Maximum confidence score (exclusive, 0.0-1.0, default: unbounded)
    offset: Pagination offset (default: 0)
    limit: Maximum number of results to return (default: 100)

Returns:
    Summary and detailed results for all matching functions"""

MANUAL["bsim_disconnect"] = """Disconnect from the current BSim database.

Returns:
    Disconnection status message"""

MANUAL["bsim_status"] = """Get the current BSim database connection status.

Returns:
    Current connection status and database path if connected"""

MANUAL["bsim_get_match_disassembly"] = """Get the disassembly of a specific BSim match. This requires the matched
executable to be available in the Ghidra project.

Params:
    executable_path: Path to the matched executable (from BSim match result)
    function_name: Name of the matched function
    function_address: Address of the matched function (e.g., "0x401000")

Returns:
    Function prototype and assembly code for the matched function.
    Returns an error message if the program is not found in the project."""

MANUAL["bsim_get_match_decompile"] = """Get the decompilation of a specific BSim match. This requires the matched
executable to be available in the Ghidra project.

Params:
    executable_path: Path to the matched executable (from BSim match result)
    function_name: Name of the matched function
    function_address: Address of the matched function (e.g., "0x401000")

Returns:
    Function prototype and decompiled C code for the matched function.
    Returns an error message if the program is not found in the project."""

MANUAL["bulk_operations"] = """Execute multiple operations in a single request. This is more efficient than
making multiple individual requests.

Params:
    operations: List of operations to execute. Each operation is a dict with:
        - endpoint: The API endpoint path (e.g., "/methods", "/decompile")
        - params: Dict of parameters for that endpoint (e.g., {"name": "main"})

Example:
    operations = [
        {"endpoint": "/methods", "params": {"offset": 0, "limit": 10}},
        {"endpoint": "/decompile", "params": {"name": "main"}},
        {"endpoint": "/rename_function_by_address", "params": {"function_address": "0x401000", "new_name": "initialize"}}
    ]

Returns:
    JSON string containing results array with the response for each operation."""

MANUAL["create_struct"] = """Create a new empty struct with a given name and optional size.

Params:
    name: Struct name
    size: Initial size in bytes (0 for empty/auto-sized)
    category_path: Category path like "/MyStructs" (default: "/")

Returns:
    JSON string with struct details (name, size, category, path)"""

MANUAL["parse_c_struct"] = """Parse C struct definition from text and add to program.

Params:
    c_code: C struct definition (e.g., "struct MyStruct { int field1; char field2; };")
    category_path: Where to place the struct (default: "/")

Returns:
    JSON string with parsed struct names and details

Note: C code must be preprocessed (no #includes, macros expanded).
Basic types must exist (int, char, void, etc.)."""

MANUAL["add_struct_field"] = """Add a field to an existing struct.

Params:
    struct_name: Name of struct to modify
    field_type: Data type name (e.g., "int", "char", "void*", "MyStruct")
    field_name: Name of new field
    length: Size in bytes (-1 for default based on type)
    comment: Optional field comment

Returns:
    JSON string with field details (offset, size, type, name)"""

MANUAL["insert_struct_field_at_offset"] = """Insert a field at a specific offset in the struct.

Params:
    struct_name: Name of struct
    offset: Byte offset for insertion
    field_type: Data type name
    field_name: Name of field
    length: Size in bytes (-1 for default)
    comment: Optional field comment

Returns:
    JSON string with field details"""

MANUAL["replace_struct_field"] = """Replace an existing field at a given ordinal position.

Params:
    struct_name: Name of struct
    ordinal: Component index (0-based)
    field_type: Data type name
    field_name: Field name (empty to keep existing)
    length: Size in bytes (-1 for default)
    comment: Field comment (empty to keep existing)

Returns:
    JSON string with field details"""

MANUAL["delete_struct_field"] = """Delete a field from a struct.

Params:
    struct_name: Name of struct
    ordinal: Component index (0-based, use -1 if using offset)
    offset: Byte offset (use -1 if using ordinal)

Note: Must specify either ordinal OR offset, not both.

Returns:
    JSON string with result"""

MANUAL["clear_struct_field"] = """Clear a field (keeps struct size, fills with undefined).

Params:
    struct_name: Name of struct
    ordinal: Component index (0-based, use -1 if using offset)
    offset: Byte offset (use -1 if using ordinal)

Note: Must specify either ordinal OR offset, not both.

Returns:
    JSON string with result"""

MANUAL["get_struct_info"] = """Get detailed information about a struct.

Params:
    name: Struct name

Returns:
    JSON string with complete struct details including all fields
    (name, path, size, numComponents, numDefined, isPacked, alignment, components)"""

MANUAL["list_structs"] = """List all struct types in the program.

Params:
    category_path: Filter by category (empty for all)
    offset: Pagination offset
    limit: Max results

Returns:
    JSON string with array of struct summaries"""

MANUAL["rename_struct"] = """Rename a struct.

Params:
    old_name: Current struct name
    new_name: New struct name

Returns:
    JSON string with result"""

MANUAL["delete_struct"] = """Delete a struct from the program.

Params:
    name: Name of struct to delete

Returns:
    JSON string with result"""

MANUAL["query"] = """Query/list items of a specified type from the program with optional filtering.

Params:
    type: Type of items to query. Options:
        - "methods": Function names (supports search with namespace:: syntax)
        - "classes": Namespace/class names
        - "segments": Memory segments
        - "imports": Imported symbols
        - "exports": Exported functions/symbols
        - "namespaces": Non-global namespaces
        - "data": Data labels and values (supports search parameter)
        - "strings": Defined strings with addresses (supports filter)
        - "structs": Struct types (supports search and category_path)
        - "instruction_pattern": Instruction patterns (requires search parameter with regex)
    search: Search/filter query. Usage varies by type:
        - "methods": Supports namespace syntax (e.g., "funcName", "MyClass::", "MyClass::funcName")
        - "data": Substring search on data labels
        - "structs": Case-insensitive substring search on struct names
        - "instruction_pattern": Regex pattern to match against disassembly (REQUIRED)
    start_address: Start address of range to search (optional for instruction_pattern)
    end_address: End address of range to search (optional for instruction_pattern)
    offset: Pagination offset (default: 0)
    limit: Max results (default: 100 for most types, 2000 for strings)
    filter: String content filter for "strings" type
    category_path: Category filter for "structs" type

Instruction Pattern Search:
    Uses Java regex (java.util.regex.Pattern) to match against disassembly text.
    Regex syntax: Standard Java regex with full support for lookahead, lookbehind,
    character classes, quantifiers, etc. Case-sensitive by default.

    Note: Special regex characters must be escaped (e.g., "\\." for literal dot,
    "\\(" for literal parenthesis). Backslashes need to be escaped in Python strings.

    Examples:
        # Find all "move.b" instructions with A4 register
        query(type="instruction_pattern", search="move\\.b.*A4")

        # Find all JSR/BSR calls
        query(type="instruction_pattern", search="[jb]sr")

        # Find instructions accessing a specific address
        query(type="instruction_pattern", search="0x3932")

        # Search in specific address range
        query(type="instruction_pattern", search="move", start_address="0x1000", end_address="0x2000")

        # Find indirect addressing with parentheses
        query(type="instruction_pattern", search=".*\\(.*,.*\\)")

        # Find hex addresses (0x followed by hex digits)
        query(type="instruction_pattern", search="0x[0-9a-fA-F]+")

Returns:
    List of items matching type and filters with pagination"""

MANUAL["disassemble_function"] = """Disassemble one or more functions showing comprehensive assembly information.

Displays enhanced Ghidra-style disassembly including:
- PLATE comment boxes (function documentation)
- Function signatures with calling conventions
- Register assumptions (e.g., assume CS = 0x2a0a)
- Local variables table with XREFs
- Function labels with caller XREFs
- Assembly instructions with mnemonics and operands
- Enhanced annotations, labels, and cross-references
- EOL, PRE, POST, and REPEATABLE comments
- Call destinations with function signatures

Params:
    address: Single address string (e.g., "0x401000") or list of addresses for bulk disassembly
    include_bytes: Include raw instruction bytes in output (default: False)

Returns:
    - For single address: List of assembly lines with full disassembly details
    - For multiple addresses: JSON string with array of results, each containing the disassembly for that address

Example (single):
    disassemble_function("0x401000")
    disassemble_function("0x401000", include_bytes=True)  # With instruction bytes

Example (bulk):
    disassemble_function(["0x401000", "0x402000", "0x403000"])

Note: Bulk operations are more efficient than multiple individual requests."""

MANUAL["get_address_context"] = """Get disassembly context around an address showing both code and data.

Displays listing items (instructions AND data) in strict memory order, exactly like the Ghidra
UI listing view. This tool is ideal for understanding what's at a specific address and its
surrounding context.

Params:
    address: Target address in hex format (e.g., "0x00231fec", "5356:3cd8")
    before: Number of code units to show before the address (default: 5)
    after: Number of code units to show after the address (default: 5)
    include_bytes: Include raw instruction/data bytes in output (default: False)

Returns:
    Formatted disassembly showing:
    - Instructions with mnemonics and operands
    - Data items with type and value
    - Labels and symbols with namespaces
    - XREFs (cross-references) showing where items are used
    - Plate comments (bordered documentation boxes)
    - EOL and POST comments
    - Proper column alignment matching Ghidra UI

Key Features:
    - Shows BOTH instructions and data in memory order (not just instructions)
    - If address points to data, shows the data (doesn't jump to nearest instruction)
    - Data formatting includes type (uint8_t, dword, etc.), value, and symbol names
    - Large data items (arrays) show first few bytes with ellipsis
    - Target address marked with "  --> " arrow
    - Function context displayed when address is within a function

Use Cases:
    - Examining data structures and their surrounding context
    - Understanding mixed code/data regions
    - Following pointers and references in memory
    - Verifying data types and values at specific addresses
    - Getting comprehensive context for reverse engineering analysis

Example Output:
    Disassembly context for address: 00231fec
    Context window: -5 to +5 code units

                                 g_FileDialog_SavedDrawMode                      XREF[2]: File_SaveGraphicsState:0022bf12(*), ...
           00231fe4  uint32_t   0h
                                 Script::g_Bytecode_Stack                        XREF[24]: Stack_PushWord:00224762(*), ...
      --> 00231fec  uint8_t[   ""
           002320e6  uint16_t   0h
           00224832  lea       (0x3834,A4)=>g_Bytecode_Stack,A0"""

@conditional_tool
def man(tool_name: str) -> str:
    """Get detailed documentation for a tool. Returns the full manual page with parameters and examples."""
    if tool_name in MANUAL:
        return f"=== Manual: {tool_name} ===\n\n{MANUAL[tool_name]}"
    elif tool_name == "man":
        available_tools = sorted(MANUAL.keys())
        return f"""=== Manual: man ===

Get detailed documentation for a tool.

Params:
    tool_name: Name of the tool to get documentation for

Returns:
    Detailed documentation including parameters, return values, and examples

Available manual pages ({len(available_tools)}):
{', '.join(available_tools)}"""
    else:
        # Tool might exist but not have extended documentation
        available_tools = sorted(MANUAL.keys())
        return f"""Tool '{tool_name}' not found in manual.

Available manual pages ({len(available_tools)}):
{', '.join(available_tools)}

Note: Some tools may not have extended documentation in the manual.
Use the tool's inline docstring for basic information."""

@conditional_tool
def query(
    type: Literal["methods", "classes", "segments", "imports", "exports", "namespaces", "data", "strings", "structs", "instruction_pattern"],
    search: str = None,
    start_address: str = None,
    end_address: str = None,
    offset: int = 0,
    limit: int = None,
    filter: str = None,
    category_path: str = None
) -> list | str:
    """Query items by type with filtering. Supports search (search param with namespace::), instruction pattern, and address range filters."""
    valid_types = ["methods", "classes", "segments", "imports", "exports", "namespaces", "data", "strings", "structs", "instruction_pattern"]

    if type not in valid_types:
        return [f"Error: Invalid type '{type}'. Valid types: {', '.join(valid_types)}"]

    # Handle query/search filtering
    if search is not None:
        if type == "methods":
            # Use search endpoint with namespace support
            query_str = str(search) if search is not None else ""
            if not query_str:
                return ["Error: query string is required"]

            params = {"offset": offset, "limit": limit if limit else 100}

            # Check if query contains namespace syntax (::)
            if "::" in query_str:
                if query_str.endswith("::"):
                    # Query ends with ::, search for all functions in namespace
                    namespace = query_str[:-2]
                    function_name = ""
                else:
                    # Split by :: and take last part as function name
                    parts = query_str.rsplit("::", 1)
                    namespace = parts[0] if len(parts) > 1 else ""
                    function_name = parts[1] if len(parts) > 1 else parts[0]

                if namespace:
                    params["namespace"] = namespace
                    params["function_name"] = function_name
                else:
                    # Empty namespace (e.g., "::func" for global namespace)
                    if function_name:
                        params["query"] = function_name
                    else:
                        return ["Error: query string is required"]
            else:
                # No namespace syntax, use standard substring search
                params["query"] = query_str

            return safe_get("searchFunctions", params)
        elif type == "data":
            # Use search endpoint for data
            query_str = str(search) if search is not None else ""
            if not query_str:
                return ["Error: query string is required"]
            params = {"query": query_str, "offset": offset, "limit": limit if limit else 100}
            return safe_get("searchData", params)
        elif type == "structs":
            # Use struct/list endpoint with search parameter
            query_str = str(search) if search is not None else ""
            if not query_str:
                return ["Error: query string is required"]
            params = {"search": query_str, "offset": offset, "limit": limit if limit else 100}
            if category_path:
                params["category_path"] = category_path
            return safe_get("struct/list", params)
        elif type == "instruction_pattern":
            # Handle instruction pattern search with regex
            # Validate that search is not empty
            if not search or str(search).strip() == "":
                return ["Error: search parameter (regex pattern) is required for instruction_pattern search"]

            params = {
                "search": search,
                "offset": offset,
                "limit": limit if limit else 100
            }

            if start_address:
                params["start_address"] = start_address
            if end_address:
                params["end_address"] = end_address

            return safe_get("search_instruction_pattern", params)
        else:
            return [f"Error: search parameter not supported for type '{type}'"]

    # Handle instruction pattern search (when search parameter is not provided)
    if type == "instruction_pattern":
        return ["Error: search parameter (regex pattern) is required for instruction_pattern search"]

    # Handle address range filtering
    if start_address is not None and end_address is not None:
        if type == "methods":
            params = {
                "start_address": start_address,
                "end_address": end_address,
                "offset": offset,
                "limit": limit if limit else 100
            }
            return safe_get("functions_by_segment", params)
        elif type == "data":
            params = {
                "start_address": start_address,
                "end_address": end_address,
                "offset": offset,
                "limit": limit if limit else 100
            }
            return safe_get("data_by_segment", params)
        else:
            return [f"Error: address range filtering not supported for type '{type}'"]

    # Standard list endpoints (no filtering)
    endpoint_mapping = {
        "methods": "methods",
        "classes": "classes",
        "segments": "segments",
        "imports": "imports",
        "exports": "exports",
        "namespaces": "namespaces",
        "data": "data",
        "strings": "strings",
        "structs": "struct/list",
    }

    endpoint = endpoint_mapping[type]
    params = {}

    # Add pagination for all types
    if limit is None:
        limit = 2000 if type == "strings" else 100
    params["offset"] = offset
    params["limit"] = limit

    # Add type-specific parameters
    if type == "strings" and filter:
        params["filter"] = filter

    if type == "structs" and category_path:
        params["category_path"] = category_path

    return safe_get(endpoint, params)


@conditional_tool
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@conditional_tool
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@conditional_tool
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})


@conditional_tool
def get_data_by_address(address: str) -> str:
    """Get data info at address (hex or segment:offset format)."""
    return "\n".join(safe_get("get_data_by_address", {"address": address}))

@conditional_tool
def get_data_in_range(start_address: str, end_address: str, include_undefined: bool = False) -> str:
    """
    Get all data items within a specific address range.
    """
    params = {
        "start_address": start_address,
        "end_address": end_address,
        "include_undefined": str(include_undefined).lower()
    }
    return "\n".join(safe_get("data_in_range", params))


@conditional_tool
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@conditional_tool
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@conditional_tool
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@conditional_tool
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))


@conditional_tool
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@conditional_tool
def disassemble_function(address: str | list[str], include_bytes: bool = False) -> str | list:
    """
    Get assembly code (address: instruction; comment) for one or more functions.
    """
    # Handle bulk disassemble
    if isinstance(address, list):
        if not address:
            return "Error: address list cannot be empty"

        # Build bulk operations for each address
        operations = [
            {"endpoint": "/disassemble_function", "params": {"address": addr, "include_bytes": str(include_bytes).lower()}}
            for addr in address
        ]

        # Use bulk_operations to process all at once
        return bulk_operations(operations)

    # Single address - original behavior
    return safe_get("disassemble_function", {"address": address, "include_bytes": str(include_bytes).lower()})

@conditional_tool
def get_address_context(address: str, before: int = 5, after: int = 5, include_bytes: bool = False) -> list:
    """Get disassembly context around an address with instructions and data."""
    return safe_get("get_address_context", {"address": address, "before": before, "after": after, "include_bytes": str(include_bytes).lower()})

@conditional_tool
def get_function_data(address: str = None, name: str = None) -> list:
    """
    Get all data (DAT_* symbols, strings, constants, etc.) referenced by a function.
    """
    params = {}
    if address:
        params["address"] = address
    elif name:
        params["name"] = name
    else:
        return ["Error: Either 'address' or 'name' parameter is required"]

    return safe_get("get_function_data", params)

@conditional_tool
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@conditional_tool
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@conditional_tool
def set_plate_comment(address: str, comment: str) -> str:
    """
    Set a plate comment for a given address. Plate comments are multi-line bordered
    comments typically displayed above functions or code sections in Ghidra's listing view.
    """
    return safe_post("set_plate_comment", {"address": address, "comment": comment})

@conditional_tool
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@conditional_tool
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@conditional_tool
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@conditional_tool
def set_data_type(address: str, type_name: str) -> str:
    """Set data type at address (e.g. "int", "dword", "byte[20]", "PCHAR")."""
    return safe_post("set_data_type", {"address": address, "type_name": type_name})

@conditional_tool
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, include_instruction: Union[bool, int] = False) -> list:
    """Get all references to the specified address (xref to)."""
    params = {"address": address, "offset": offset, "limit": limit}
    if include_instruction is not False:
        # Handle both boolean True and integer values
        if include_instruction is True:
            params["include_instruction"] = "true"
        elif isinstance(include_instruction, int):
            params["include_instruction"] = str(include_instruction)
    return safe_get("xrefs_to", params)

@conditional_tool
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, include_instruction: Union[bool, int] = False) -> list:
    """Get all references from the specified address (xref from)."""
    params = {"address": address, "offset": offset, "limit": limit}
    if include_instruction is not False:
        # Handle both boolean True and integer values
        if include_instruction is True:
            params["include_instruction"] = "true"
        elif isinstance(include_instruction, int):
            params["include_instruction"] = str(include_instruction)
    return safe_get("xrefs_from", params)

@conditional_tool
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, include_instruction: Union[bool, int] = False) -> list:
    """Get all references to the specified function by name."""
    params = {"name": name, "offset": offset, "limit": limit}
    if include_instruction is not False:
        # Handle both boolean True and integer values
        if include_instruction is True:
            params["include_instruction"] = "true"
        elif isinstance(include_instruction, int):
            params["include_instruction"] = str(include_instruction)
    return safe_get("function_xrefs", params)

@conditional_tool
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """List all defined strings in the program with their addresses."""
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@conditional_tool
def search_decompiled_text(
    pattern: str,
    is_regex: bool = True,
    case_sensitive: bool = True,
    multiline: bool = False,
    function_names: list[str] | None = None,
    max_results: int = 100,
    offset: int = 0,
    limit: int = 100
) -> str:
    """
    Search for text patterns in decompiled function code using regex.
    """
    data = {
        "pattern": pattern,
        "is_regex": is_regex,
        "case_sensitive": case_sensitive,
        "multiline": multiline,
        "max_results": max_results,
        "offset": offset,
        "limit": limit
    }

    if function_names:
        data["function_names"] = ",".join(function_names)

    return safe_post("search_decompiled_text", data)

@conditional_tool
def bsim_select_database(database_path: str) -> str:
    """Connect to BSim database (file path or postgresql:// URL)."""
    return safe_post("bsim/select_database", {"database_path": database_path})

@conditional_tool
def bsim_query_function(
    function_address: str,
    max_matches: int = 10,
    similarity_threshold: float = 0.7,
    confidence_threshold: float = 0.0,
    max_similarity: float | None = None,
    max_confidence: float | None = None,
    offset: int = 0,
    limit: int = 100,
) -> str:
    """Query function against BSim database. Thresholds are inclusive, max values exclusive (0.0-1.0)."""
    data = {
        "function_address": function_address,
        "max_matches": str(max_matches),
        "similarity_threshold": str(similarity_threshold),
        "confidence_threshold": str(confidence_threshold),
        "offset": str(offset),
        "limit": str(limit),
    }
    
    if max_similarity is not None:
        data["max_similarity"] = str(max_similarity)
    if max_confidence is not None:
        data["max_confidence"] = str(max_confidence)
    
    return safe_post("bsim/query_function", data)

@conditional_tool
def bsim_query_all_functions(
    max_matches_per_function: int = 5,
    similarity_threshold: float = 0.7,
    confidence_threshold: float = 0.0,
    max_similarity: float | None = None,
    max_confidence: float | None = None,
    offset: int = 0,
    limit: int = 100,
) -> str:
    """Query all program functions against BSim database. Thresholds are inclusive, max values exclusive (0.0-1.0)."""
    data = {
        "max_matches_per_function": str(max_matches_per_function),
        "similarity_threshold": str(similarity_threshold),
        "confidence_threshold": str(confidence_threshold),
        "offset": str(offset),
        "limit": str(limit),
    }
    
    if max_similarity is not None:
        data["max_similarity"] = str(max_similarity)
    if max_confidence is not None:
        data["max_confidence"] = str(max_confidence)
    
    return safe_post("bsim/query_all_functions", data)

@conditional_tool
def bsim_disconnect() -> str:
    """Disconnect from the current BSim database."""
    return safe_post("bsim/disconnect", {})

@conditional_tool
def bsim_status() -> str:
    """Get current BSim database connection status."""
    return "\n".join(safe_get("bsim/status"))

@conditional_tool
def bsim_get_match_disassembly(
    executable_path: str,
    function_name: str,
    function_address: str,
) -> str:
    """Get disassembly of BSim match. Requires matched executable in Ghidra project."""
    return safe_post("bsim/get_match_disassembly", {
        "executable_path": executable_path,
        "function_name": function_name,
        "function_address": function_address,
    })

@conditional_tool
def bsim_get_match_decompile(
    executable_path: str,
    function_name: str,
    function_address: str,
) -> str:
    """Get decompiled code of BSim match. Requires matched executable in Ghidra project."""
    return safe_post("bsim/get_match_decompile", {
        "executable_path": executable_path,
        "function_name": function_name,
        "function_address": function_address,
    })

@conditional_tool
def bulk_operations(operations: list[dict]) -> str:
    """Execute multiple operations in a single request. Each operation: {endpoint: str, params: dict}."""
    import json

    # Mapping from endpoint paths to tool names for stats tracking
    ENDPOINT_TO_TOOL = {
        "/decompile": "decompile_function",
        "/renameFunction": "rename_function",
        "/renameData": "rename_data",
        "/renameVariable": "rename_variable",
        "/set_decompiler_comment": "set_decompiler_comment",
        "/set_disassembly_comment": "set_disassembly_comment",
        "/set_plate_comment": "set_plate_comment",
        "/rename_function_by_address": "rename_function_by_address",
        "/set_function_prototype": "set_function_prototype",
        "/set_local_variable_type": "set_local_variable_type",
        "/set_data_type": "set_data_type",
        "/search_decompiled_text": "search_decompiled_text",
        "/methods": "query",
        "/classes": "query",
        "/segments": "query",
        "/imports": "query",
        "/exports": "query",
        "/namespaces": "query",
        "/data": "query",
        "/strings": "list_strings",
        "/struct/list": "list_structs",
        "/get_data_by_address": "get_data_by_address",
        "/get_function_by_address": "get_function_by_address",
        "/get_current_address": "get_current_address",
        "/get_current_function": "get_current_function",
        "/decompile_function": "decompile_function_by_address",
        "/disassemble_function": "disassemble_function",
        "/get_address_context": "get_address_context",
        "/get_function_data": "get_function_data",
        "/xrefs_to": "get_xrefs_to",
        "/xrefs_from": "get_xrefs_from",
        "/function_xrefs": "get_function_xrefs",
        "/bsim/select_database": "bsim_select_database",
        "/bsim/query_function": "bsim_query_function",
        "/bsim/query_all_functions": "bsim_query_all_functions",
        "/bsim/disconnect": "bsim_disconnect",
        "/bsim/status": "bsim_status",
        "/bsim/get_match_disassembly": "bsim_get_match_disassembly",
        "/bsim/get_match_decompile": "bsim_get_match_decompile",
        "/struct/create": "create_struct",
        "/struct/parse_c": "parse_c_struct",
        "/struct/add_field": "add_struct_field",
        "/struct/insert_field": "insert_struct_field_at_offset",
        "/struct/replace_field": "replace_struct_field",
        "/struct/delete_field": "delete_struct_field",
        "/struct/clear_field": "clear_struct_field",
        "/struct/get_info": "get_struct_info",
        "/struct/rename": "rename_struct",
        "/struct/delete": "delete_struct",
        "/data_in_range": "get_data_in_range",
        "/searchFunctions": "query",
        "/searchData": "query",
        "/functions_by_segment": "query",
        "/data_by_segment": "query",
        "/search_instruction_pattern": "query",
    }

    # Track individual operations if tracker is available
    if _tool_tracker is not None:
        for operation in operations:
            endpoint = operation.get("endpoint", "")
            # Normalize endpoint (remove leading slash if needed for comparison)
            normalized_endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"

            # Get the corresponding tool name
            tool_name = ENDPOINT_TO_TOOL.get(normalized_endpoint)

            if tool_name:
                _tool_tracker.increment(tool_name)
            else:
                # Log warning for unmapped endpoints
                logger.debug(f"Bulk operation endpoint '{endpoint}' not mapped to a tool for stats tracking")

    try:
        # Build JSON payload
        payload = {
            "operations": operations
        }

        url = urljoin(ghidra_server_url, "bulk")
        response = requests.post(url, json=payload, timeout=ghidra_request_timeout)
        response.encoding = 'utf-8'

        if response.ok:
            return response.text
        else:
            return f"Error {response.status_code}: {response.text}"
    except Exception as e:
        return f"Request failed: {str(e)}"

# ==================== STRUCT OPERATIONS ====================

@conditional_tool
def create_struct(name: str, size: int = 0, category_path: str = "") -> str:
    """Create new empty struct with optional size and category path."""
    return safe_post("struct/create", {
        "name": name,
        "size": size,
        "category_path": category_path
    })

@conditional_tool
def parse_c_struct(c_code: str, category_path: str = "") -> str:
    """Parse C struct definition and add to program. Code must be preprocessed (no #includes, macros expanded)."""
    return safe_post("struct/parse_c", {
        "c_code": c_code,
        "category_path": category_path
    })

@conditional_tool
def add_struct_field(struct_name: str, field_type: str, field_name: str,
                     length: int = -1, comment: str = "") -> str:
    """Add field to struct. Type examples: "int", "char", "void*", "MyStruct"."""
    return safe_post("struct/add_field", {
        "struct_name": struct_name,
        "field_type": field_type,
        "field_name": field_name,
        "length": length,
        "comment": comment
    })

@conditional_tool
def insert_struct_field_at_offset(struct_name: str, offset: int, field_type: str,
                                  field_name: str, length: int = -1, comment: str = "") -> str:
    """Insert field at specific byte offset in struct."""
    return safe_post("struct/insert_field", {
        "struct_name": struct_name,
        "offset": offset,
        "field_type": field_type,
        "field_name": field_name,
        "length": length,
        "comment": comment
    })

@conditional_tool
def replace_struct_field(struct_name: str, ordinal: int, field_type: str,
                        field_name: str = "", length: int = -1, comment: str = "") -> str:
    """Replace field at ordinal position (0-based). Empty name/comment preserves existing."""
    return safe_post("struct/replace_field", {
        "struct_name": struct_name,
        "ordinal": ordinal,
        "field_type": field_type,
        "field_name": field_name,
        "length": length,
        "comment": comment
    })

@conditional_tool
def delete_struct_field(struct_name: str, ordinal: int = -1, offset: int = -1) -> str:
    """Delete field by ordinal (0-based) OR offset. Must specify one, not both."""
    return safe_post("struct/delete_field", {
        "struct_name": struct_name,
        "ordinal": ordinal,
        "offset": offset
    })

@conditional_tool
def clear_struct_field(struct_name: str, ordinal: int = -1, offset: int = -1) -> str:
    """Clear field by ordinal OR offset (keeps struct size, fills with undefined). Must specify one, not both."""
    return safe_post("struct/clear_field", {
        "struct_name": struct_name,
        "ordinal": ordinal,
        "offset": offset
    })

@conditional_tool
def get_struct_info(name: str) -> str:
    """Get detailed struct information including all fields."""
    return safe_get("struct/get_info", {"name": name})

@conditional_tool
def list_structs(category_path: str = "", offset: int = 0, limit: int = 100) -> str:
    """List all struct types in program, optionally filtered by category."""
    params = {"offset": offset, "limit": limit}
    if category_path:
        params["category_path"] = category_path
    return safe_get("struct/list", params)

@conditional_tool
def rename_struct(old_name: str, new_name: str) -> str:
    """Rename a struct."""
    return safe_post("struct/rename", {
        "old_name": old_name,
        "new_name": new_name
    })

@conditional_tool
def delete_struct(name: str) -> str:
    """Delete a struct from the program."""
    return safe_post("struct/delete", {"name": name})

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    parser.add_argument("--ghidra-timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                        help=f"MCP requests timeout, default: {DEFAULT_REQUEST_TIMEOUT}")
    parser.add_argument("--config", type=str, default=None,
                        help="Path to configuration file (TOML format), default: mcp-config.toml if it exists")
    args = parser.parse_args()

    # Load configuration
    global _enabled_tools, _tool_tracker
    config = load_config(args.config)
    if config.get("tools"):
        _enabled_tools = get_enabled_tools(config)
    else:
        logger.info("No tool configuration found, all tools enabled")

    # Initialize tool tracker with enabled tools
    enabled_tools = _enabled_tools if _enabled_tools is not None else set(_tool_registry.keys())
    try:
        _tool_tracker = ToolTracker(list(enabled_tools))
        logger.info("Tool call tracking initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize tool tracker: {e}. Continuing without tracking.")
        _tool_tracker = None

    # Register tools based on configuration
    register_tools()

    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    elif "server" in config and "ghidra_server" in config["server"]:
        ghidra_server_url = config["server"]["ghidra_server"]

    global ghidra_request_timeout
    if args.ghidra_timeout:
        ghidra_request_timeout = args.ghidra_timeout
    elif "server" in config and "request_timeout" in config["server"]:
        ghidra_request_timeout = config["server"]["request_timeout"]

    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

