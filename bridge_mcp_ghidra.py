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
from typing import Dict, Set, Optional

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
        "list_methods", "list_classes", "list_segments", "list_imports",
        "list_exports", "list_namespaces", "list_data_items", "list_functions",
        "list_strings", "get_current_address", "get_current_function",
        "get_function_by_address", "get_data_by_address", "get_data_in_range",
        "get_function_data", "get_xrefs_to", "get_xrefs_from", "get_function_xrefs",
        "man"
    ],
    "decompile": [
        "decompile_function", "decompile_function_by_address", "disassemble_function",
        "get_address_context"
    ],
    "search": [
        "search_functions_by_name", "search_data_by_name",
        "list_functions_by_segment", "list_data_by_segment", "search_decompiled_text"
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
        "list_structs", "rename_struct", "delete_struct"
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
    include_instruction: Include instruction text at each xref location (default: False)

Returns:
    List of references to the specified address. When include_instruction is True,
    each reference includes the instruction text (e.g., "tst.l (0x3936,A4)")."""

MANUAL["get_xrefs_from"] = """Get all references from the specified address (xref from).

Params:
    address: Source address in hex format (e.g. "0x1400010a0")
    offset: Pagination offset (default: 0)
    limit: Maximum number of references to return (default: 100)
    include_instruction: Include instruction text at the source address (default: False)

Returns:
    List of references from the specified address. When include_instruction is True,
    each reference includes the instruction text at the source address."""

MANUAL["get_function_xrefs"] = """Get all references to the specified function by name.

Params:
    name: Function name to search for
    offset: Pagination offset (default: 0)
    limit: Maximum number of references to return (default: 100)
    include_instruction: Include instruction text at each xref location (default: False)

Returns:
    List of references to the specified function. When include_instruction is True,
    each reference includes the instruction text (e.g., "call FUN_00401234")."""

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

MANUAL["get_address_context"] = """Get disassembly context around an address showing both code and data.

Displays listing items (instructions AND data) in strict memory order, exactly like the Ghidra
UI listing view. This tool is ideal for understanding what's at a specific address and its
surrounding context.

Params:
    address: Target address in hex format (e.g., "0x00231fec", "5356:3cd8")
    before: Number of code units to show before the address (default: 5)
    after: Number of code units to show after the address (default: 5)

Returns:
    Formatted disassembly showing:
    - Instructions with mnemonics, operands, and bytes
    - Data items with type, value, and bytes
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
           00231fe4  00 00 00 00    uint32_t   0h
                                 Script::g_Bytecode_Stack                        XREF[24]: Stack_PushWord:00224762(*), ...
      --> 00231fec  00 00 00 ...   uint8_t[   ""
           002320e6  00 00          uint16_t   0h
           00224832  41 ec 38 34    lea       (0x3834,A4)=>g_Bytecode_Stack,A0"""

# ==================== QUERY TOOLS ====================

MANUAL["list_methods"] = """List all function names in the program with pagination support.

This tool retrieves function names from the program's symbol table. It includes both
user-defined functions and auto-generated function names (e.g., FUN_00401000). Use this
for getting an overview of available functions or iterating through all functions.

Params:
    offset: Starting position for pagination (default: 0)
    limit: Maximum number of function names to return (default: 100)

Returns:
    List of function names, one per line. Names may include namespace prefixes
    (e.g., "MyClass::myMethod").

Use Cases:
    - Getting a list of all functions in the program
    - Finding functions with specific naming patterns
    - Iterating through functions in batches
    - Building an index of program functions

Example:
    To get the first 10 functions: offset=0, limit=10
    To get the next 10 functions: offset=10, limit=10

Note: For searching by name substring, use search_functions_by_name instead."""

MANUAL["list_classes"] = """List all namespace and class names in the program with pagination.

Retrieves all non-global namespaces/classes from the program. In Ghidra, namespaces are
used to organize symbols hierarchically, often representing C++ classes, modules, or
logical groupings of code.

Params:
    offset: Starting position for pagination (default: 0)
    limit: Maximum number of namespace names to return (default: 100)

Returns:
    List of namespace/class names, one per line.

Use Cases:
    - Discovering the program's organizational structure
    - Finding C++ class names
    - Understanding module organization in the binary
    - Identifying code grouped by functionality

Example:
    Results may include: "std", "MyNamespace", "ClassName", "Module::SubModule"

Note: This shows only non-global namespaces. Global namespace symbols are accessed
through other tools like list_methods."""

MANUAL["list_segments"] = """List all memory segments in the program with their properties.

Memory segments (also called memory blocks in Ghidra) define regions of the program's
address space. Each segment has specific attributes like read/write/execute permissions,
initialization status, and purpose (code, data, etc.).

Params:
    offset: Starting position for pagination (default: 0)
    limit: Maximum number of segments to return (default: 100)

Returns:
    List of memory segments with properties including:
    - Segment name (e.g., ".text", ".data", ".rodata", "RAM")
    - Start address and end address
    - Size in bytes
    - Permissions (read, write, execute)
    - Initialization status (initialized/uninitialized)

Use Cases:
    - Understanding program memory layout
    - Identifying code vs data sections
    - Finding executable regions for analysis
    - Locating specific sections like .rodata or .bss
    - Planning analysis scope by memory region

Common Segments:
    - .text: Executable code
    - .data: Initialized data
    - .rodata: Read-only data (constants, strings)
    - .bss: Uninitialized data
    - .plt/.got: Dynamic linking tables

Note: Use list_functions_by_segment or list_data_by_segment to get contents of specific segments."""

MANUAL["list_imports"] = """List imported symbols (external functions/data) in the program.

Imports are symbols that the program references but are defined in external libraries
(DLLs, shared objects). These are typically library functions that the program calls.

Params:
    offset: Starting position for pagination (default: 0)
    limit: Maximum number of imports to return (default: 100)

Returns:
    List of imported symbols with information including:
    - Symbol name (e.g., "malloc", "printf", "CreateFileA")
    - Library name (e.g., "msvcrt.dll", "kernel32.dll", "libc.so.6")
    - Import address (location in import table)
    - Ordinal number (if imported by ordinal)

Use Cases:
    - Identifying external dependencies
    - Understanding what libraries the program uses
    - Finding specific API calls (e.g., file I/O, network, crypto)
    - Security analysis (identifying dangerous functions)
    - Determining program capabilities from imports

Example Imports:
    - Windows: CreateFileA, ReadFile, WriteFile from kernel32.dll
    - Linux: fopen, fread, fwrite from libc.so.6
    - Crypto: CryptEncrypt from advapi32.dll

Note: Imports are resolved at runtime by the dynamic linker."""

MANUAL["list_exports"] = """List exported symbols (functions/data made available to other programs).

Exports are symbols that this program makes available to other programs or libraries.
Typically found in DLLs, shared libraries, or executables that expose an API.

Params:
    offset: Starting position for pagination (default: 0)
    limit: Maximum number of exports to return (default: 100)

Returns:
    List of exported symbols with information including:
    - Symbol name (e.g., "DllMain", "MyFunction", "exported_variable")
    - Export address (where the symbol is defined)
    - Ordinal number (position in export table)
    - Type (function or data)

Use Cases:
    - Understanding the API a DLL/library provides
    - Finding entry points in a library
    - Identifying the public interface of a module
    - Locating important functions by their exported names
    - Analyzing malware DLL exports

Example Exports:
    - DLL entry: DllMain, DllRegisterServer
    - API functions: MyFunction, ProcessData, Initialize
    - Exported variables: g_SharedData

Note: Executables typically have few or no exports. DLLs and shared libraries have many."""

MANUAL["list_namespaces"] = """List all non-global namespaces in the program with pagination.

Namespaces in Ghidra provide hierarchical organization of symbols. This tool returns
all namespaces except the global namespace. Namespaces can represent C++ classes,
modules, packages, or logical groupings created during analysis.

Params:
    offset: Starting position for pagination (default: 0)
    limit: Maximum number of namespaces to return (default: 100)

Returns:
    List of namespace names, showing the full namespace hierarchy.

Use Cases:
    - Discovering program structure and organization
    - Finding C++ class hierarchies
    - Understanding modular organization
    - Navigating large codebases
    - Identifying related groups of functions

Example Namespaces:
    - C++: "std", "MyClass", "OuterClass::InnerClass"
    - Modules: "Crypto", "Network", "FileIO"
    - Manual: "Utilities", "Helpers"

Note: This is similar to list_classes but includes all namespace types, not just classes."""

MANUAL["list_data_items"] = """List all defined data labels and their values with pagination.

Retrieves data items that have been explicitly defined in the program, including global
variables, static data, string literals, constants, and data structures. This excludes
undefined bytes.

Params:
    offset: Starting position for pagination (default: 0)
    limit: Maximum number of data items to return (default: 100)

Returns:
    List of data items with information including:
    - Address
    - Label/name (e.g., "DAT_00404000", "g_Config", "s_ErrorMessage")
    - Data type (e.g., "dword", "char[20]", "MyStruct")
    - Value or representation
    - Size in bytes

Use Cases:
    - Finding global variables
    - Locating string literals
    - Discovering data structures
    - Analyzing program constants
    - Understanding data organization

Example Data Items:
    - Global variables: g_Counter (int), g_FileName (char*)
    - String literals: s_Hello_World (char[12])
    - Constants: DAT_00404000 (dword) = 0x12345678
    - Structures: g_Config (ConfigStruct)

Note: For searching by name, use search_data_by_name. For data in specific regions,
use list_data_by_segment or get_data_in_range."""

MANUAL["get_data_in_range"] = """Get all data items within a specific address range.

Retrieves data items (variables, strings, structures) that fall within the specified
address range. Useful for analyzing data in a specific memory region or between two
known addresses.

Params:
    start_address: Beginning of address range (e.g., "0x404000")
    end_address: End of address range (e.g., "0x405000")
    include_undefined: Include undefined bytes in results (default: False)

Returns:
    List of data items in the range with:
    - Address
    - Label/name
    - Data type
    - Value or representation
    - Size

Use Cases:
    - Analyzing data in a specific memory region
    - Examining a data segment or section
    - Finding all data between two addresses
    - Investigating memory around a specific location
    - Analyzing arrays or sequential data structures

Example:
    start_address="0x404000", end_address="0x405000"
    Returns all defined data between these addresses.

Note: By default, only defined data is returned. Set include_undefined=True to see
all bytes in the range, including undefined regions."""

MANUAL["get_current_address"] = """Get the address currently selected in the Ghidra UI.

Returns the address where the user's cursor is positioned in the Ghidra Code Browser.
This is useful for interactive workflows where the user navigates to a location and
wants analysis at that specific address.

Params:
    None

Returns:
    The currently selected address in hex format (e.g., "0x00401000").
    Returns an error message if no address is selected.

Use Cases:
    - Interactive analysis based on user navigation
    - "Analyze current location" workflows
    - Context-aware assistance
    - Building tools that operate on the selected address

Example:
    User positions cursor at 0x00401234 in Ghidra.
    Tool returns: "0x00401234"

Note: Requires active Ghidra UI with a selected address. Useful for MCP tools that
provide interactive assistance."""

MANUAL["get_current_function"] = """Get the function currently selected in the Ghidra UI.

Returns information about the function where the user's cursor is currently positioned
in the Ghidra Code Browser. If the cursor is not within a function, returns an error.

Params:
    None

Returns:
    Function information including:
    - Function name
    - Entry point address
    - Function signature/prototype
    - Size in bytes

Use Cases:
    - Interactive function analysis
    - "Analyze current function" workflows
    - Context-aware code assistance
    - Quick function information lookup

Example:
    User positions cursor inside a function.
    Tool returns function details like: "main @ 0x00401000"

Note: Requires active Ghidra UI with cursor inside a function."""

MANUAL["get_function_by_address"] = """Get function information for the function at a specific address.

Retrieves detailed information about the function at the given address. The address
can be anywhere within the function body, not just the entry point.

Params:
    address: Address within the function (e.g., "0x00401000")
            Can be entry point or any address inside the function

Returns:
    Function information including:
    - Function name
    - Entry point address
    - Function signature/prototype
    - Address range (start and end)
    - Size in bytes
    - Return type and parameters

Use Cases:
    - Getting function details when you know an address
    - Finding which function contains a specific address
    - Retrieving function metadata for analysis
    - Verifying function boundaries

Example:
    address="0x00401234" (inside a function starting at 0x00401000)
    Returns information about that function.

Note: If the address is not within a function, returns an error."""

MANUAL["list_functions"] = """List all functions in the program without pagination.

Returns a complete list of all functions defined in the program. This includes both
user-defined and auto-generated function names. Unlike list_methods, this returns
the full list without pagination.

Params:
    None

Returns:
    Complete list of all function names in the program, one per line.

Use Cases:
    - Getting a complete function inventory
    - Exporting all function names
    - Counting total functions
    - Bulk analysis operations

Warning:
    For large programs with thousands of functions, this can return a very large
    result. Consider using list_methods with pagination for better performance.

Note: For most use cases, prefer list_methods with pagination for better control
and performance."""

MANUAL["get_function_data"] = """Get all data references used by a specific function.

Retrieves all data items (global variables, strings, constants, etc.) that are
referenced by the specified function. This includes both direct references and
data accessed through pointers.

Params:
    address: Function address (e.g., "0x00401000"), OR
    name: Function name (e.g., "main")

    Note: Must specify either address OR name, not both.

Returns:
    List of data items referenced by the function, including:
    - Data address
    - Label/name (e.g., "s_ErrorMsg", "g_Counter")
    - Data type
    - Value or representation
    - Reference type (read, write, pointer)

Use Cases:
    - Understanding what data a function uses
    - Finding string literals used by a function
    - Identifying global variables accessed
    - Analyzing function dependencies
    - Tracking data flow

Example:
    Function "ProcessFile" may reference:
    - s_FileName_404000: "config.txt"
    - g_FileHandle: dword
    - DAT_405000: byte array

Note: This shows data referenced, not local variables on the stack."""

# ==================== DECOMPILE TOOLS ====================

MANUAL["decompile_function"] = """Decompile a function by name and return the decompiled C code.

Uses Ghidra's decompiler to convert assembly code back into readable C-like pseudocode.
The decompiled code shows the function's logic, control flow, and operations in a
high-level format.

Params:
    name: Function name (e.g., "main", "MyClass::myMethod", "FUN_00401000")

Returns:
    Decompiled C code including:
    - Function signature with return type and parameters
    - Local variable declarations with inferred types
    - Function body with control flow (if/else, loops, etc.)
    - Comments from the Ghidra database

Use Cases:
    - Understanding function logic
    - Reverse engineering algorithms
    - Analyzing malware behavior
    - Verifying function purpose
    - Code review and documentation

Example Output:
    void processData(char *input, int size) {
        int i;
        char *buffer;

        buffer = malloc(size);
        for (i = 0; i < size; i++) {
            buffer[i] = input[i] ^ 0x55;
        }
        return;
    }

Note: Decompilation quality depends on Ghidra's analysis. Complex or obfuscated
code may produce less readable output. For assembly code, use disassemble_function."""

MANUAL["decompile_function_by_address"] = """Decompile a function at a specific address and return C code.

Uses Ghidra's decompiler to convert the function at the given address into C-like
pseudocode. The address can be the function entry point or any address within the
function.

Params:
    address: Address of the function (e.g., "0x00401000")
            Can be entry point or any address inside the function

Returns:
    Decompiled C code including:
    - Function signature with return type and parameters
    - Local variable declarations with inferred types
    - Function body with control flow
    - Comments from the Ghidra database

Use Cases:
    - Decompiling when you know the address but not the name
    - Analyzing functions at specific locations
    - Following call targets from disassembly
    - Analyzing unnamed or dynamically called functions

Example:
    address="0x00401234"
    Returns decompiled C code for the function containing that address.

Note: Functionally equivalent to decompile_function but uses address instead of name.
If the address is not within a function, returns an error."""

MANUAL["disassemble_function"] = """Get the assembly code disassembly for a function.

Returns the complete assembly listing for the specified function, showing each
instruction with its address, bytes, mnemonic, and operands. Also includes comments.

Params:
    address: Address of the function (e.g., "0x00401000")
            Can be entry point or any address inside the function

Returns:
    Assembly listing with format:
    address: instruction ; comment

    Each line shows:
    - Memory address
    - Assembly instruction (mnemonic + operands)
    - Comments (if any)

Use Cases:
    - Low-level analysis of function behavior
    - Understanding exact instruction sequence
    - Analyzing optimization or compiler output
    - Finding specific instruction patterns
    - Debugging or exploit development

Example Output:
    00401000: push    ebp
    00401001: mov     ebp,esp ; setup stack frame
    00401003: sub     esp,0x10
    00401006: call    00402000 ; call helper function
    0040100b: xor     eax,eax
    0040100d: pop     ebp
    0040100e: ret

Note: For high-level code view, use decompile_function instead. For context around
a specific address including data, use get_address_context."""

# ==================== SEARCH TOOLS ====================

MANUAL["search_functions_by_name"] = """Search for functions whose name contains a given substring or matches namespace criteria.

Performs substring search on function names with support for namespace filtering.
This is more flexible than list_methods as it filters results and supports namespace syntax.

Params:
    query: Search query - can be:
           - Simple substring (e.g., "crypt" finds "encrypt", "decrypt")
           - Namespace::function (e.g., "MyClass::process")
           - Namespace only (e.g., "MyClass::" finds all functions in MyClass)
    offset: Starting position for pagination (default: 0)
    limit: Maximum number of results to return (default: 100)

Returns:
    List of matching function names with their addresses.

Use Cases:
    - Finding functions by partial name
    - Locating functions in a specific namespace/class
    - Discovering related functions (e.g., all "init" functions)
    - Finding API functions (e.g., all "Create*" functions)
    - Narrowing down function lists

Examples:
    query="encrypt" → finds encrypt, decrypt, EncryptData, etc.
    query="std::" → finds all functions in std namespace
    query="File" → finds OpenFile, CloseFile, FileRead, etc.

Note: Search is case-sensitive by default and uses substring matching."""

MANUAL["search_data_by_name"] = """Search for data variables whose label or name contains a given substring.

Searches through all data labels (global variables, strings, constants) to find
those matching the query string. Useful for finding specific data items when you
know part of the name.

Params:
    query: Search substring (e.g., "error", "config", "password")
    offset: Starting position for pagination (default: 0)
    limit: Maximum number of results to return (default: 100)

Returns:
    List of matching data items with:
    - Address
    - Label/name
    - Data type
    - Value or representation

Use Cases:
    - Finding global variables by partial name
    - Locating string literals containing specific text
    - Discovering configuration data
    - Finding error messages or debug strings
    - Searching for suspicious variable names

Examples:
    query="password" → finds g_Password, s_PasswordPrompt, etc.
    query="config" → finds g_Config, ConfigData, etc.
    query="error" → finds error messages and error variables

Note: Searches the label/symbol name, not the actual string contents. For searching
string contents, use list_strings with filter parameter."""

MANUAL["list_functions_by_segment"] = """List all functions within a specific memory segment or address range.

Retrieves functions located in a particular segment (like .text) or within a custom
address range. Useful for analyzing functions in specific code sections.

Params:
    segment_name: Name of the segment (e.g., ".text", ".init", "RAM"), OR
    start_address: Beginning of address range (e.g., "0x401000"), AND
    end_address: End of address range (e.g., "0x402000")

    Note: Provide either segment_name OR both start_address and end_address.

    offset: Starting position for pagination (default: 0)
    limit: Maximum number of results to return (default: 100)

Returns:
    List of functions in the specified region with:
    - Function name
    - Entry point address
    - Size

Use Cases:
    - Analyzing all code in a specific section
    - Finding functions in executable segments
    - Analyzing initialization code (.init section)
    - Examining code in specific memory regions
    - Segmenting analysis by memory layout

Examples:
    segment_name=".text" → all functions in main code section
    start_address="0x401000", end_address="0x402000" → functions in range

Note: Most executable code is in .text segment. Other segments like .init may
contain initialization code."""

MANUAL["list_data_by_segment"] = """List all data items within a specific memory segment or address range.

Retrieves data items located in a particular segment (like .data, .rodata) or within
a custom address range. Useful for analyzing data in specific memory sections.

Params:
    segment_name: Name of the segment (e.g., ".data", ".rodata", ".bss"), OR
    start_address: Beginning of address range (e.g., "0x404000"), AND
    end_address: End of address range (e.g., "0x405000")

    Note: Provide either segment_name OR both start_address and end_address.

    offset: Starting position for pagination (default: 0)
    limit: Maximum number of results to return (default: 100)

Returns:
    List of data items in the specified region with:
    - Address
    - Label/name
    - Data type
    - Value or representation

Use Cases:
    - Analyzing global variables (.data section)
    - Finding read-only constants (.rodata section)
    - Examining uninitialized data (.bss section)
    - Analyzing data in specific memory regions
    - Understanding data organization by segment

Examples:
    segment_name=".rodata" → constants and string literals
    segment_name=".data" → initialized global variables
    start_address="0x404000", end_address="0x405000" → data in range

Common Segments:
    - .data: Initialized global/static variables
    - .rodata: Read-only data (constants, strings)
    - .bss: Uninitialized global/static variables"""

MANUAL["search_decompiled_text"] = """Search for text patterns in decompiled function code using regular expressions.

Searches through the decompiled C code of functions to find patterns. This is
extremely powerful for finding specific code patterns, API calls, or logic across
the entire program.

Params:
    pattern: Regular expression pattern to search for (e.g., "malloc.*free")
    is_regex: Treat pattern as regex (default: True)
    case_sensitive: Case-sensitive matching (default: True)
    multiline: Enable multiline regex mode (default: False)
    function_names: Optional list of specific functions to search in
                   If None, searches all functions
    max_results: Maximum results per function (default: 100)
    offset: Starting position for pagination (default: 0)
    limit: Maximum total results to return (default: 100)

Returns:
    JSON string containing:
    - Matched functions
    - Matching line numbers and content
    - Context around matches

Use Cases:
    - Finding all uses of specific API calls
    - Locating error handling patterns
    - Discovering crypto operations
    - Finding buffer operations (memcpy, strcpy)
    - Searching for vulnerable code patterns
    - Locating specific algorithms

Examples:
    pattern="malloc" → find memory allocations
    pattern="strcpy|strcat" → find unsafe string functions
    pattern="AES.*encrypt" → find AES encryption code
    pattern="if.*==.*NULL" → find NULL checks

Note: Searches decompiled code, not assembly. Decompilation quality affects results."""

# ==================== MODIFICATION TOOLS ====================

MANUAL["rename_function"] = """Rename a function by its current name to a new user-defined name.

Changes the name of a function from its current name to a new name. The new name
persists in the Ghidra database and appears in decompilation, disassembly, and
cross-references.

Params:
    old_name: Current function name (e.g., "FUN_00401000", "sub_401000")
    new_name: New name for the function (e.g., "processData", "decrypt")

Returns:
    Success message if renamed, error message if function not found or name invalid.

Use Cases:
    - Giving descriptive names to auto-generated function names
    - Improving code readability during analysis
    - Documenting function purposes
    - Standardizing naming conventions
    - Making analysis notes permanent

Examples:
    old_name="FUN_00401000", new_name="decryptBuffer"
    old_name="sub_402000", new_name="initializeConfig"

Naming Guidelines:
    - Use descriptive, meaningful names
    - Follow C naming conventions (alphanumeric + underscore)
    - Avoid special characters except underscore
    - Names should reflect function purpose

Note: If you know the address but not the current name, use rename_function_by_address."""

MANUAL["rename_function_by_address"] = """Rename a function by its address rather than current name.

Changes the name of the function at the specified address. This is useful when you
know the address but not the current function name, or when the current name is
auto-generated.

Params:
    function_address: Address of the function (e.g., "0x00401000")
                     Can be entry point or any address within the function
    new_name: New name for the function (e.g., "processData", "decrypt")

Returns:
    Success message if renamed, error message if no function at address or name invalid.

Use Cases:
    - Renaming when you have an address from analysis
    - Renaming functions at known locations
    - Batch renaming using address lists
    - Renaming from cross-reference analysis

Examples:
    function_address="0x00401000", new_name="main"
    function_address="0x00402500", new_name="encryptData"

Naming Guidelines:
    - Use descriptive, meaningful names
    - Follow C naming conventions
    - Avoid special characters except underscore

Note: If you know the current name, rename_function may be more readable."""

MANUAL["rename_data"] = """Rename a data label at a specific address.

Changes the label/symbol name for data at the specified address. This applies to
global variables, strings, constants, and other data items.

Params:
    address: Address of the data item (e.g., "0x00404000")
    new_name: New label name (e.g., "g_Config", "s_ErrorMessage")

Returns:
    Success message if renamed, error message if no data at address or name invalid.

Use Cases:
    - Naming global variables descriptively
    - Labeling string literals
    - Marking configuration data
    - Documenting data structures
    - Improving data cross-reference readability

Examples:
    address="0x404000", new_name="g_ServerConfig"
    address="0x405000", new_name="s_WelcomeMessage"

Naming Conventions:
    - g_ prefix for globals (e.g., g_Counter)
    - s_ prefix for strings (e.g., s_ErrorMsg)
    - Use descriptive names reflecting data purpose

Note: The renamed label appears in all cross-references and disassembly."""

MANUAL["rename_variable"] = """Rename a local variable within a specific function.

Changes the name of a local variable (stack variable or register variable) in the
decompiled code of a function. This improves code readability during analysis.

Params:
    function_name: Name of the function containing the variable
    old_name: Current variable name (e.g., "local_10", "param_1", "iVar2")
    new_name: New variable name (e.g., "buffer", "fileSize", "counter")

Returns:
    Success message if renamed, error message if function or variable not found.

Use Cases:
    - Making decompiled code more readable
    - Documenting variable purposes
    - Clarifying function logic
    - Tracking data flow through variables
    - Making analysis notes in code

Examples:
    function_name="processData", old_name="local_10", new_name="buffer"
    function_name="main", old_name="param_1", new_name="argc"
    function_name="decrypt", old_name="iVar2", new_name="keyIndex"

Variable Types:
    - local_XX: Stack variables
    - param_X: Function parameters
    - iVar, uVar, etc.: Temporary variables

Note: Variable names are local to the function and appear in decompilation."""

MANUAL["set_function_prototype"] = """Set or modify a function's prototype (signature).

Defines the function's return type, parameters, and calling convention. This improves
decompilation quality and correctness by providing type information to Ghidra's analyzer.

Params:
    function_address: Address of the function (e.g., "0x00401000")
    prototype: Complete function signature (e.g., "int processData(char* buffer, int size)")

Returns:
    Success message if prototype set, error message if invalid syntax or address.

Use Cases:
    - Correcting auto-analyzed function signatures
    - Adding type information for better decompilation
    - Documenting function interfaces
    - Specifying calling conventions
    - Improving parameter and return value analysis

Examples:
    prototype="void encrypt(char* data, int length, char* key)"
    prototype="int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)"
    prototype="char* malloc(size_t size)"

Prototype Format:
    return_type [calling_convention] function_name(param_type param_name, ...)

Common Calling Conventions:
    - __cdecl: C default
    - __stdcall: Windows API
    - __fastcall: Register passing
    - __thiscall: C++ methods

Note: Correct prototypes significantly improve decompilation quality. Types must
exist in Ghidra's data type manager."""

MANUAL["set_local_variable_type"] = """Set the data type of a local variable within a function.

Changes the type of a local variable in the decompiled code, which can improve
decompilation accuracy and readability. Ghidra will propagate this type information
through the function's dataflow.

Params:
    function_address: Address of the function (e.g., "0x00401000")
    variable_name: Name of the local variable (e.g., "local_10", "buffer")
    new_type: Data type specification (e.g., "int", "char*", "MyStruct*", "byte[256]")

Returns:
    Success message if type set, error message if function, variable, or type not found.

Use Cases:
    - Correcting auto-inferred variable types
    - Specifying pointer types for clarity
    - Defining structure types for local variables
    - Improving decompilation readability
    - Fixing type propagation issues

Examples:
    variable_name="local_10", new_type="char*"
    variable_name="buffer", new_type="byte[256]"
    variable_name="config", new_type="ConfigStruct*"

Common Types:
    - Basic: int, char, short, long, byte, word, dword
    - Pointers: int*, char*, void*
    - Arrays: char[256], byte[100]
    - Structures: MyStruct, MyStruct*

Note: Type must exist in Ghidra's data type manager. Setting types can cascade
through dataflow analysis."""

MANUAL["set_decompiler_comment"] = """Add a comment at a specific address in the decompiled function pseudocode.

Creates a comment that appears in the decompiled C code view. This is ideal for
documenting code logic, algorithms, or analysis findings at the C code level.

Params:
    address: Address where the comment should appear (e.g., "0x00401234")
    comment: Comment text (can be multi-line)

Returns:
    Success message if comment set, error message if address invalid.

Use Cases:
    - Documenting function logic in decompiled view
    - Explaining complex algorithms
    - Noting analysis findings
    - Marking interesting or suspicious code
    - Adding reverse engineering notes

Example:
    address="0x00401234"
    comment="This XOR loop decrypts the configuration data"

Comment appears in decompiled C code:
    // This XOR loop decrypts the configuration data
    for (i = 0; i < size; i++) {
        buffer[i] = buffer[i] ^ 0x55;
    }

Note: Comments appear only in decompiler view. For assembly comments, use
set_disassembly_comment. For large headers, use set_plate_comment."""

MANUAL["set_disassembly_comment"] = """Add a comment at a specific address in the disassembly listing.

Creates a comment that appears in the assembly code view (EOL comment - End Of Line).
This is ideal for documenting specific instructions or assembly-level details.

Params:
    address: Address where the comment should appear (e.g., "0x00401234")
    comment: Comment text (single or multi-line)

Returns:
    Success message if comment set, error message if address invalid.

Use Cases:
    - Documenting assembly instructions
    - Explaining instruction purpose or effect
    - Noting register usage
    - Marking important instructions
    - Adding low-level analysis notes

Example:
    address="0x00401234"
    comment="XOR with key byte for decryption"

Comment appears in disassembly:
    00401234: xor al, byte [esi]  ; XOR with key byte for decryption

Note: Comments appear in assembly listing view. For decompiler comments, use
set_decompiler_comment. For large headers, use set_plate_comment."""

MANUAL["set_plate_comment"] = """Add a plate comment at a specific address.

Creates a large, bordered comment box that appears above the specified address in
the listing view. Plate comments are ideal for function headers, section markers,
or important notices that should stand out visually.

Params:
    address: Address where the plate comment should appear (e.g., "0x00401000")
    comment: Comment text (typically multi-line)

Returns:
    Success message if comment set, error message if address invalid.

Use Cases:
    - Creating function header documentation
    - Marking major code sections
    - Adding important warnings or notes
    - Documenting APIs or interfaces
    - Creating visual separators in listings

Example:
    address="0x00401000"
    comment=\"\"\"Decryption Function

Decrypts the configuration buffer using XOR encryption.
Parameters: buffer (char*), size (int), key (char*)
Returns: 0 on success, -1 on error\"\"\"

Appears as bordered box in listing:
    ┌─────────────────────────────────────────┐
    │ Decryption Function                     │
    │                                         │
    │ Decrypts the configuration buffer...    │
    │ Parameters: buffer (char*), size (int)  │
    │ Returns: 0 on success, -1 on error      │
    └─────────────────────────────────────────┘

Note: Plate comments are prominently displayed and ideal for important documentation.
They appear in both disassembly and listing views."""

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
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@conditional_tool
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

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
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@conditional_tool
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@conditional_tool
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@conditional_tool
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@conditional_tool
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

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
def search_functions_by_name(query: str | int, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    # Convert query to string to handle numeric inputs (e.g., "4140" parsed as int 4140)
    # Use 'is not None' check instead of truthiness to handle zero and empty strings correctly
    query_str = str(query) if query is not None else ""
    if not query_str:
        return ["Error: query string is required"]

    params = {"offset": offset, "limit": limit}

    # Check if query contains namespace syntax (::)
    if "::" in query_str:
        # Parse namespace and function name
        if query_str.endswith("::"):
            # Query ends with ::, search for all functions in namespace
            namespace = query_str[:-2]  # Remove trailing ::
            function_name = ""
        else:
            # Split by :: and take last part as function name
            # Use rsplit with maxsplit=1 to handle nested namespaces correctly
            parts = query_str.rsplit("::", 1)
            namespace = parts[0] if len(parts) > 1 else ""
            function_name = parts[1] if len(parts) > 1 else parts[0]

        # Add namespace-specific parameters
        if namespace:
            params["namespace"] = namespace
        if function_name:
            params["function_name"] = function_name
        # If no function_name (ends with ::), backend should return all functions in namespace
    else:
        # No namespace syntax, use standard substring search
        params["query"] = query_str

    return safe_get("searchFunctions", params)

@conditional_tool
def search_data_by_name(query: str | int, offset: int = 0, limit: int = 100) -> list:
    """Search for data variables whose label/name contains the query substring."""
    # Convert query to string to handle numeric inputs (e.g., "4140" parsed as int 4140)
    # Use 'is not None' check instead of truthiness to handle zero and empty strings correctly
    query_str = str(query) if query is not None else ""
    if not query_str:
        return ["Error: query string is required"]
    return safe_get("searchData", {"query": query_str, "offset": offset, "limit": limit})

@conditional_tool
def list_functions_by_segment(
    segment_name: str = None,
    start_address: str = None,
    end_address: str = None,
    offset: int = 0,
    limit: int = 100
) -> list:
    """
    List functions within a specific memory segment or address range.
    """
    params = {"offset": offset, "limit": limit}

    if segment_name:
        params["segment_name"] = segment_name
    elif start_address and end_address:
        params["start_address"] = start_address
        params["end_address"] = end_address
    else:
        return ["Error: Either segment_name or both start_address and end_address must be provided"]

    return safe_get("functions_by_segment", params)

@conditional_tool
def list_data_by_segment(
    segment_name: str = None,
    start_address: str = None,
    end_address: str = None,
    offset: int = 0,
    limit: int = 100
) -> list:
    """
    List defined data items within a specific memory segment or address range.
    """
    params = {"offset": offset, "limit": limit}

    if segment_name:
        params["segment_name"] = segment_name
    elif start_address and end_address:
        params["start_address"] = start_address
        params["end_address"] = end_address
    else:
        return ["Error: Either segment_name or both start_address and end_address must be provided"]

    return safe_get("data_by_segment", params)

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
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@conditional_tool
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@conditional_tool
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@conditional_tool
def get_address_context(address: str, before: int = 5, after: int = 5) -> list:
    """Get disassembly context around an address with instructions and data."""
    return safe_get("get_address_context", {"address": address, "before": before, "after": after})

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
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, include_instruction: bool = False) -> list:
    """Get all references to the specified address (xref to)."""
    params = {"address": address, "offset": offset, "limit": limit}
    if include_instruction:
        params["include_instruction"] = "true"
    return safe_get("xrefs_to", params)

@conditional_tool
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, include_instruction: bool = False) -> list:
    """Get all references from the specified address (xref from)."""
    params = {"address": address, "offset": offset, "limit": limit}
    if include_instruction:
        params["include_instruction"] = "true"
    return safe_get("xrefs_from", params)

@conditional_tool
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, include_instruction: bool = False) -> list:
    """Get all references to the specified function by name."""
    params = {"name": name, "offset": offset, "limit": limit}
    if include_instruction:
        params["include_instruction"] = "true"
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

