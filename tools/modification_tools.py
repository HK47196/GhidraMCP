"""Modification tools for renaming and setting types in GhidraMCP."""

from typing import Literal
from config import conditional_tool
from http_client import safe_post


@conditional_tool
def rename(
    type: Literal["function", "function_by_address", "data", "variable", "struct"],
    new_name: str,
    old_name: str = None,
    function_address: str = None,
    address: str = None,
    function_name: str = None
) -> str:
    """Rename items by type. Supports function, function_by_address, data, variable, and struct."""
    valid_types = ["function", "function_by_address", "data", "variable", "struct"]

    if type not in valid_types:
        return f"Error: Invalid type '{type}'. Valid types: {', '.join(valid_types)}"

    # Route based on type
    if type == "function":
        if old_name is None:
            return "Error: old_name is required for type 'function'"
        return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

    elif type == "function_by_address":
        if function_address is None:
            return "Error: function_address is required for type 'function_by_address'"
        return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

    elif type == "data":
        if address is None:
            return "Error: address is required for type 'data'"
        return safe_post("renameData", {"address": address, "newName": new_name})

    elif type == "variable":
        if function_name is None or old_name is None:
            return "Error: function_name and old_name are required for type 'variable'"
        return safe_post("renameVariable", {
            "functionName": function_name,
            "oldName": old_name,
            "newName": new_name
        })

    elif type == "struct":
        if old_name is None:
            return "Error: old_name is required for type 'struct'"
        return safe_post("struct/rename", {
            "old_name": old_name,
            "new_name": new_name
        })


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
