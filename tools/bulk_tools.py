"""Bulk operations tools for GhidraMCP."""

import json
import logging
import requests
from urllib.parse import urljoin
from config import conditional_tool, get_tool_tracker
from http_client import get_ghidra_server_url, get_ghidra_request_timeout

logger = logging.getLogger(__name__)


@conditional_tool
def bulk_operations(operations: list[dict]) -> str:
    """Execute multiple operations in a single request. Each operation: {endpoint: str, params: dict}."""
    # Mapping from endpoint paths to tool names for stats tracking
    ENDPOINT_TO_TOOL = {
        "/decompile": "decompile_function",
        "/renameFunction": "rename",
        "/renameData": "rename",
        "/renameVariable": "rename",
        "/set_decompiler_comment": "set_decompiler_comment",
        "/set_disassembly_comment": "set_disassembly_comment",
        "/set_plate_comment": "set_plate_comment",
        "/rename_function_by_address": "rename",
        "/set_function_prototype": "set_function_prototype",
        "/set_local_variable_type": "set_local_variable_type",
        "/set_data_type": "set_data_type",
        "/search_decompiled_text": "search_decompiled_text",
        "/methods": "query",
        "/classes": "query",
        "/segments": "query",
        "/imports": "query",
        "/exports": "query",
        "/namespaces": "query",
        "/data": "query",
        "/strings": "list_strings",
        "/struct/list": "list_structs",
        "/get_data_by_address": "get_data_by_address",
        "/get_function_by_address": "get_function_by_address",
        "/get_current_address": "get_current_address",
        "/get_current_function": "get_current_function",
        "/decompile_function": "decompile_function_by_address",
        "/disassemble_function": "disassemble_function",
        "/get_address_context": "get_address_context",
        "/get_function_data": "get_function_data",
        "/xrefs_to": "get_xrefs_to",
        "/xrefs_from": "get_xrefs_from",
        "/function_xrefs": "get_function_xrefs",
        "/bsim/select_database": "bsim_select_database",
        "/bsim/query_function": "bsim_query_function",
        "/bsim/query_all_functions": "bsim_query_all_functions",
        "/bsim/disconnect": "bsim_disconnect",
        "/bsim/status": "bsim_status",
        "/bsim/get_match_disassembly": "bsim_get_match_disassembly",
        "/bsim/get_match_decompile": "bsim_get_match_decompile",
        "/struct/create": "create_struct",
        "/struct/parse_c": "parse_c_struct",
        "/struct/add_field": "add_struct_field",
        "/struct/insert_field": "insert_struct_field_at_offset",
        "/struct/replace_field": "replace_struct_field",
        "/struct/delete_field": "delete_struct_field",
        "/struct/clear_field": "clear_struct_field",
        "/struct/get_info": "get_struct_info",
        "/struct/rename": "rename",
        "/struct/delete": "delete_struct",
        "/data_in_range": "get_data_in_range",
        "/searchFunctions": "query",
        "/searchData": "query",
        "/functions_by_segment": "query",
        "/data_by_segment": "query",
        "/search_instruction_pattern": "query",
    }

    # Normalize endpoints to ensure they have a leading slash
    normalized_operations = []
    for operation in operations:
        endpoint = operation.get("endpoint", "")
        # Ensure endpoint starts with /
        normalized_endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"

        normalized_operation = {
            "endpoint": normalized_endpoint,
            "params": operation.get("params", {})
        }
        normalized_operations.append(normalized_operation)

    # Track individual operations if tracker is available
    tool_tracker = get_tool_tracker()
    if tool_tracker is not None:
        for operation in normalized_operations:
            endpoint = operation.get("endpoint", "")
            # Get the corresponding tool name
            tool_name = ENDPOINT_TO_TOOL.get(endpoint)

            if tool_name:
                tool_tracker.increment(tool_name)
            else:
                # Log warning for unmapped endpoints
                logger.debug(f"Bulk operation endpoint '{endpoint}' not mapped to a tool for stats tracking")

    try:
        # Build JSON payload with normalized operations
        payload = {
            "operations": normalized_operations
        }

        url = urljoin(get_ghidra_server_url(), "bulk")
        response = requests.post(url, json=payload, timeout=get_ghidra_request_timeout())
        response.encoding = 'utf-8'

        if response.ok:
            return response.text
        else:
            return f"Error {response.status_code}: {response.text}"
    except Exception as e:
        return f"Request failed: {str(e)}"
