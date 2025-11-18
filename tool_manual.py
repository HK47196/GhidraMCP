# Tool manual documentation for GhidraMCP tools
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

MANUAL["get_function_callees"] = """Get a hierarchical tree of functions called by the specified function.

This tool analyzes the call graph starting from a given function and returns a tree
showing all functions it calls (callees) up to a specified depth. This is particularly
useful for understanding function call hierarchies and tracing through thunks to actual
implementations.

Params:
    address: Function address in hex format (e.g., "0x002233b0")
    depth: Maximum depth to traverse in the call tree (default: 1, minimum: 1)
        - 1: Show only immediate callees
        - 2: Show callees and their callees
        - N: Traverse up to N levels deep

Returns:
    Hierarchical tree representation of called functions with addresses.

Example output:
    Opcode143 (0x002233b0)
    ├─ thunk_FUN_0022d858 (0x002233d8)
    │   └─ FUN_0022d858 (0x0022d858)
    └─ thunk_FUN_0022d91c (0x002233e2)
        └─ FUN_0022d91c (0x0022d91c)

Notes:
    - Detects and reports circular references to prevent infinite loops
    - Only includes CALL and JUMP type references (actual function calls)
    - Results are sorted by address for consistent output"""

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
    character classes, quantifiers, etc. Case-insensitive matching.

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

MANUAL["rename"] = """Rename items by type with a unified interface.

Params:
    type: Type of item to rename. Options:
        - "function": Rename a function by its current name
        - "function_by_address": Rename a function by its address
        - "data": Rename a data label at a specific address
        - "variable": Rename a local variable within a function
        - "struct": Rename a struct type
    new_name: The new name to assign to the item (required for all types)
    old_name: Current name (required for types: "function", "variable", "struct")
    function_address: Function address in hex (required for type: "function_by_address")
    address: Memory address in hex (required for type: "data")
    function_name: Function containing the variable (required for type: "variable")

Examples:
    # Rename a function by name
    rename(type="function", old_name="FUN_00401000", new_name="main")

    # Rename a function by address
    rename(type="function_by_address", function_address="0x401000", new_name="initialize")

    # Rename a data label
    rename(type="data", address="0x403000", new_name="g_config")

    # Rename a local variable
    rename(type="variable", function_name="main", old_name="local_8", new_name="counter")

    # Rename a struct
    rename(type="struct", old_name="struct_1", new_name="ConfigData")

Returns:
    Success or error message"""

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
