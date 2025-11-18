"""Search tools for GhidraMCP."""

from config import conditional_tool
from http_client import safe_post


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
