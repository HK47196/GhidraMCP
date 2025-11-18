"""Query and information retrieval tools for GhidraMCP."""

from typing import Literal, Union
from config import conditional_tool
from http_client import safe_get
from manual import MANUAL


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
def get_function_callees(address: str, depth: int = 1) -> str:
    """Get hierarchical tree of functions called by the specified function."""
    params = {"address": address, "depth": depth}
    result = safe_get("function_callees", params)
    # safe_get returns a list of lines, join them back into a string
    return "\n".join(result) if result else ""


@conditional_tool
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """List all defined strings in the program with their addresses."""
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)
