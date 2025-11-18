"""BSim (Binary Similarity) tools for GhidraMCP."""

from config import conditional_tool
from http_client import safe_get, safe_post


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
