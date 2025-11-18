"""Undo/redo tools for GhidraMCP."""

import requests
from urllib.parse import urljoin
from config import conditional_tool
from http_client import get_ghidra_server_url, get_ghidra_request_timeout


@conditional_tool
def can_undo() -> bool:
    """Check if undo is available"""
    response = requests.get(
        urljoin(get_ghidra_server_url(), "/undo/can_undo"),
        timeout=get_ghidra_request_timeout()
    )
    response.raise_for_status()
    return response.json().get("can_undo", False)


@conditional_tool
def undo() -> str:
    """Undo the last transaction"""
    response = requests.post(
        urljoin(get_ghidra_server_url(), "/undo/undo"),
        timeout=get_ghidra_request_timeout()
    )
    response.raise_for_status()
    data = response.json()
    if data.get("success"):
        return data.get("message", "Undo successful")
    else:
        return data.get("message", "Nothing to undo")


@conditional_tool
def clear_undo() -> str:
    """Clear the undo stack"""
    response = requests.post(
        urljoin(get_ghidra_server_url(), "/undo/clear"),
        timeout=get_ghidra_request_timeout()
    )
    response.raise_for_status()
    return response.json().get("message", "Undo stack cleared")
