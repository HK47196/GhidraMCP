"""GhidraMCP tools package - imports all tool modules."""

# Import all tools to register them with the @conditional_tool decorator
from tools.query_tools import (
    man, query, get_data_by_address, get_data_in_range,
    get_function_by_address, get_current_address, get_current_function,
    get_function_data, get_xrefs_to, get_xrefs_from, get_function_xrefs,
    get_function_callees, list_strings
)

from tools.decompilation_tools import (
    decompile_function, decompile_function_by_address,
    disassemble_function, get_address_context
)

from tools.modification_tools import (
    rename, set_decompiler_comment, set_disassembly_comment,
    set_plate_comment, set_function_prototype, set_local_variable_type,
    set_data_type
)

from tools.search_tools import search_decompiled_text

from tools.bsim_tools import (
    bsim_select_database, bsim_query_function, bsim_query_all_functions,
    bsim_disconnect, bsim_status, bsim_get_match_disassembly,
    bsim_get_match_decompile
)

from tools.struct_tools import (
    create_struct, parse_c_struct, add_struct_field,
    insert_struct_field_at_offset, replace_struct_field,
    delete_struct_field, clear_struct_field, get_struct_info,
    list_structs, delete_struct
)

from tools.undo_tools import can_undo, undo, clear_undo

from tools.bulk_tools import bulk_operations

# Export all tools
__all__ = [
    # Query tools
    "man", "query", "get_data_by_address", "get_data_in_range",
    "get_function_by_address", "get_current_address", "get_current_function",
    "get_function_data", "get_xrefs_to", "get_xrefs_from", "get_function_xrefs",
    "get_function_callees", "list_strings",
    # Decompilation tools
    "decompile_function", "decompile_function_by_address",
    "disassemble_function", "get_address_context",
    # Modification tools
    "rename", "set_decompiler_comment", "set_disassembly_comment",
    "set_plate_comment", "set_function_prototype", "set_local_variable_type",
    "set_data_type",
    # Search tools
    "search_decompiled_text",
    # BSim tools
    "bsim_select_database", "bsim_query_function", "bsim_query_all_functions",
    "bsim_disconnect", "bsim_status", "bsim_get_match_disassembly",
    "bsim_get_match_decompile",
    # Struct tools
    "create_struct", "parse_c_struct", "add_struct_field",
    "insert_struct_field_at_offset", "replace_struct_field",
    "delete_struct_field", "clear_struct_field", "get_struct_info",
    "list_structs", "delete_struct",
    # Undo tools
    "can_undo", "undo", "clear_undo",
    # Bulk tools
    "bulk_operations",
]
