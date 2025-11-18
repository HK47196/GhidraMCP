"""HTTP client for communicating with Ghidra server."""

import requests
from urllib.parse import urljoin

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
DEFAULT_REQUEST_TIMEOUT = 60

# Global server configuration
ghidra_server_url = DEFAULT_GHIDRA_SERVER
ghidra_request_timeout = DEFAULT_REQUEST_TIMEOUT


def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=ghidra_request_timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]


def safe_post(endpoint: str, data: dict | str) -> str:
    """
    Perform a POST request with dict or string data.
    """
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            # BSim queries might be a bit slower, using configurable timeout
            response = requests.post(url, data=data, timeout=ghidra_request_timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=ghidra_request_timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


def set_ghidra_server_url(url: str):
    """Set the Ghidra server URL."""
    global ghidra_server_url
    ghidra_server_url = url


def set_ghidra_request_timeout(timeout: int):
    """Set the Ghidra request timeout."""
    global ghidra_request_timeout
    ghidra_request_timeout = timeout


def get_ghidra_server_url() -> str:
    """Get the current Ghidra server URL."""
    return ghidra_server_url


def get_ghidra_request_timeout() -> int:
    """Get the current Ghidra request timeout."""
    return ghidra_request_timeout
