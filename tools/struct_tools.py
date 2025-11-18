"""Struct manipulation tools for GhidraMCP."""

from config import conditional_tool
from http_client import safe_get, safe_post


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
    return "\n".join(safe_get("struct/get_info", {"name": name}))


@conditional_tool
def list_structs(category_path: str = "", offset: int = 0, limit: int = 100) -> str:
    """List all struct types in program, optionally filtered by category."""
    params = {"offset": offset, "limit": limit}
    if category_path:
        params["category_path"] = category_path
    return safe_get("struct/list", params)


@conditional_tool
def delete_struct(name: str) -> str:
    """Delete a struct from the program."""
    return safe_post("struct/delete", {"name": name})
