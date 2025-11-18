"""Configuration management for GhidraMCP."""

import os
import logging
import functools
from typing import Dict, Set, Optional

# TOML support for config files
try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # Python 3.10

logger = logging.getLogger(__name__)

# Tool categories for configuration
TOOL_CATEGORIES = {
    "query": [
        "query", "get_current_address", "get_current_function",
        "get_function_by_address", "get_data_by_address", "get_data_in_range",
        "get_function_data", "get_xrefs_to", "get_xrefs_from", "get_function_xrefs",
        "get_function_callees", "man"
    ],
    "decompile": [
        "decompile_function", "decompile_function_by_address", "disassemble_function",
        "get_address_context"
    ],
    "search": [
        "search_decompiled_text"
    ],
    "modification": [
        "rename", "set_function_prototype", "set_local_variable_type",
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
        "delete_struct"
    ],
    "undo": ["can_undo", "undo", "clear_undo"],
    "bulk": ["bulk_operations"]
}

# Global configuration
_enabled_tools: Optional[Set[str]] = None
_tool_registry: Dict[str, any] = {}  # Store tool functions before registration
_tools_registered: bool = False
_tool_tracker: Optional[any] = None  # Track tool call statistics


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


def register_tools(mcp, tool_tracker=None):
    """
    Register tools with MCP based on configuration.
    This must be called after config is loaded.

    Args:
        mcp: FastMCP instance
        tool_tracker: Optional ToolTracker instance for statistics
    """
    global _tools_registered, _tool_tracker

    if _tools_registered:
        logger.warning("Tools already registered, skipping")
        return

    _tool_tracker = tool_tracker

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


def set_enabled_tools(enabled_tools: Set[str]):
    """Set the enabled tools globally."""
    global _enabled_tools
    _enabled_tools = enabled_tools


def get_tool_registry() -> Dict[str, any]:
    """Get the tool registry."""
    return _tool_registry


def get_tool_tracker():
    """Get the tool tracker instance."""
    return _tool_tracker
