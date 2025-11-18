# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

"""GhidraMCP - MCP server for Ghidra reverse engineering."""

import sys
import argparse
import logging

from mcp.server.fastmcp import FastMCP

# Import configuration and HTTP client
from config import (
    load_config, get_enabled_tools, register_tools,
    set_enabled_tools, get_tool_registry
)
from http_client import (
    set_ghidra_server_url, set_ghidra_request_timeout,
    DEFAULT_GHIDRA_SERVER, DEFAULT_REQUEST_TIMEOUT
)

# Import all tools (this registers them via @conditional_tool decorator)
import tools

# Re-export commonly used functions and classes for backward compatibility with tests
from http_client import (
    safe_get, safe_post,
    ghidra_server_url, ghidra_request_timeout
)
from tools.bulk_tools import bulk_operations
from config import (
    TOOL_CATEGORIES,
    _tool_registry, _enabled_tools, _tools_registered, _tool_tracker,
    get_tool_tracker
)
from manual import MANUAL
from tool_tracker import ToolTracker
import requests

# Re-export all tools for backward compatibility
from tools import (
    # Query tools
    man, query, get_data_by_address, get_data_in_range,
    get_function_by_address, get_current_address, get_current_function,
    get_function_data, get_xrefs_to, get_xrefs_from, get_function_xrefs,
    get_function_callees, list_strings,
    # Decompilation tools
    decompile_function, decompile_function_by_address,
    disassemble_function, get_address_context,
    # Modification tools
    rename, set_decompiler_comment, set_disassembly_comment,
    set_plate_comment, set_function_prototype, set_local_variable_type,
    set_data_type,
    # Search tools
    search_decompiled_text,
    # BSim tools
    bsim_select_database, bsim_query_function, bsim_query_all_functions,
    bsim_disconnect, bsim_status, bsim_get_match_disassembly,
    bsim_get_match_decompile,
    # Struct tools
    create_struct, parse_c_struct, add_struct_field,
    insert_struct_field_at_offset, replace_struct_field,
    delete_struct_field, clear_struct_field, get_struct_info,
    list_structs, delete_struct,
    # Undo tools
    can_undo, undo, clear_undo,
)

# Export for test compatibility
__all__ = [
    'safe_get', 'safe_post', 'bulk_operations', 'TOOL_CATEGORIES', 'ToolTracker', 'requests',
    'MANUAL', '_tool_registry', '_enabled_tools', '_tools_registered', '_tool_tracker',
    'ghidra_server_url', 'ghidra_request_timeout', 'get_tool_tracker',
    # Query tools
    'man', 'query', 'get_data_by_address', 'get_data_in_range',
    'get_function_by_address', 'get_current_address', 'get_current_function',
    'get_function_data', 'get_xrefs_to', 'get_xrefs_from', 'get_function_xrefs',
    'get_function_callees', 'list_strings',
    # Decompilation tools
    'decompile_function', 'decompile_function_by_address',
    'disassemble_function', 'get_address_context',
    # Modification tools
    'rename', 'set_decompiler_comment', 'set_disassembly_comment',
    'set_plate_comment', 'set_function_prototype', 'set_local_variable_type',
    'set_data_type',
    # Search tools
    'search_decompiled_text',
    # BSim tools
    'bsim_select_database', 'bsim_query_function', 'bsim_query_all_functions',
    'bsim_disconnect', 'bsim_status', 'bsim_get_match_disassembly',
    'bsim_get_match_decompile',
    # Struct tools
    'create_struct', 'parse_c_struct', 'add_struct_field',
    'insert_struct_field_at_offset', 'replace_struct_field',
    'delete_struct_field', 'clear_struct_field', 'get_struct_info',
    'list_structs', 'delete_struct',
    # Undo tools
    'can_undo', 'undo', 'clear_undo',
]

logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("ghidra-mcp")


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
    config = load_config(args.config)
    if config.get("tools"):
        enabled_tools = get_enabled_tools(config)
        set_enabled_tools(enabled_tools)
    else:
        logger.info("No tool configuration found, all tools enabled")

    # Initialize tool tracker with enabled tools
    tool_tracker = None
    enabled_tools_list = list(get_tool_registry().keys()) if config.get("tools") else list(get_tool_registry().keys())
    try:
        tool_tracker = ToolTracker(enabled_tools_list)
        logger.info("Tool call tracking initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize tool tracker: {e}. Continuing without tracking.")

    # Register tools based on configuration
    register_tools(mcp, tool_tracker)

    # Configure Ghidra server URL
    if args.ghidra_server:
        set_ghidra_server_url(args.ghidra_server)
    elif "server" in config and "ghidra_server" in config["server"]:
        set_ghidra_server_url(config["server"]["ghidra_server"])

    # Configure Ghidra request timeout
    if args.ghidra_timeout:
        set_ghidra_request_timeout(args.ghidra_timeout)
    elif "server" in config and "request_timeout" in config["server"]:
        set_ghidra_request_timeout(config["server"]["request_timeout"])

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

            from http_client import get_ghidra_server_url
            logger.info(f"Connecting to Ghidra server at {get_ghidra_server_url()}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
