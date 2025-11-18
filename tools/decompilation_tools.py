"""Decompilation and disassembly tools for GhidraMCP."""

from config import conditional_tool
from http_client import safe_get, safe_post


@conditional_tool
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)


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
    # Import here to avoid circular dependency
    from tools.bulk_tools import bulk_operations

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
