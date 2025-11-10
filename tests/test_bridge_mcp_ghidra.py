"""
Test suite for the GhidraMCP bridge.

Tests the MCP server bridge functionality, HTTP client helpers,
and tool implementations.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path to import bridge_mcp_ghidra
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_ghidra


class TestSafeGet:
    """Test suite for the safe_get helper function."""

    @patch('bridge_mcp_ghidra.requests.get')
    def test_safe_get_success(self, mock_get):
        """Test successful GET request with text response."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = "line1\nline2\nline3"
        mock_get.return_value = mock_response

        result = bridge_mcp_ghidra.safe_get("test_endpoint")

        assert result == ["line1", "line2", "line3"]
        mock_get.assert_called_once()

    @patch('bridge_mcp_ghidra.requests.get')
    def test_safe_get_with_params(self, mock_get):
        """Test GET request with query parameters."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = "result"
        mock_get.return_value = mock_response

        params = {"offset": 10, "limit": 50}
        result = bridge_mcp_ghidra.safe_get("test_endpoint", params)

        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert call_args[1]['params'] == params

    @patch('bridge_mcp_ghidra.requests.get')
    def test_safe_get_error_response(self, mock_get):
        """Test GET request with error status code."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_get.return_value = mock_response

        result = bridge_mcp_ghidra.safe_get("test_endpoint")

        assert len(result) == 1
        assert "Error 404" in result[0]
        assert "Not Found" in result[0]

    @patch('bridge_mcp_ghidra.requests.get')
    def test_safe_get_exception(self, mock_get):
        """Test GET request that raises an exception."""
        mock_get.side_effect = Exception("Connection timeout")

        result = bridge_mcp_ghidra.safe_get("test_endpoint")

        assert len(result) == 1
        assert "Request failed" in result[0]
        assert "Connection timeout" in result[0]

    @patch('bridge_mcp_ghidra.requests.get')
    def test_safe_get_timeout(self, mock_get):
        """Test GET request with timeout."""
        mock_get.side_effect = Exception("Timeout")

        result = bridge_mcp_ghidra.safe_get("test_endpoint")

        assert len(result) == 1
        assert "Request failed" in result[0]


class TestSafePost:
    """Test suite for the safe_post helper function."""

    @patch('bridge_mcp_ghidra.requests.post')
    def test_safe_post_success_with_string(self, mock_post):
        """Test successful POST request with string data."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = "  Success result  "
        mock_post.return_value = mock_response

        result = bridge_mcp_ghidra.safe_post("test_endpoint", "test_data")

        assert result == "Success result"
        mock_post.assert_called_once()

    @patch('bridge_mcp_ghidra.requests.post')
    def test_safe_post_success_with_dict(self, mock_post):
        """Test successful POST request with dict data."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = "Success"
        mock_post.return_value = mock_response

        data = {"key": "value"}
        result = bridge_mcp_ghidra.safe_post("test_endpoint", data)

        assert result == "Success"
        call_args = mock_post.call_args
        assert call_args[1]['data'] == data

    @patch('bridge_mcp_ghidra.requests.post')
    def test_safe_post_error_response(self, mock_post):
        """Test POST request with error status code."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response

        result = bridge_mcp_ghidra.safe_post("test_endpoint", "data")

        assert "Error 500" in result
        assert "Internal Server Error" in result

    @patch('bridge_mcp_ghidra.requests.post')
    def test_safe_post_exception(self, mock_post):
        """Test POST request that raises an exception."""
        mock_post.side_effect = Exception("Network error")

        result = bridge_mcp_ghidra.safe_post("test_endpoint", "data")

        assert "Request failed" in result
        assert "Network error" in result


class TestMCPTools:
    """Test suite for MCP tool implementations."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_methods(self, mock_safe_get):
        """Test list_methods tool."""
        mock_safe_get.return_value = ["method1", "method2", "method3"]

        result = bridge_mcp_ghidra.list_methods(offset=0, limit=100)

        assert result == ["method1", "method2", "method3"]
        mock_safe_get.assert_called_once_with("methods", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_methods_with_pagination(self, mock_safe_get):
        """Test list_methods with custom pagination."""
        mock_safe_get.return_value = ["method4", "method5"]

        result = bridge_mcp_ghidra.list_methods(offset=10, limit=2)

        assert result == ["method4", "method5"]
        mock_safe_get.assert_called_once_with("methods", {"offset": 10, "limit": 2})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_classes(self, mock_safe_get):
        """Test list_classes tool."""
        mock_safe_get.return_value = ["ClassA", "ClassB"]

        result = bridge_mcp_ghidra.list_classes(offset=0, limit=100)

        assert result == ["ClassA", "ClassB"]
        mock_safe_get.assert_called_once_with("classes", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_segments(self, mock_safe_get):
        """Test list_segments tool."""
        mock_safe_get.return_value = [".text", ".data", ".bss"]

        result = bridge_mcp_ghidra.list_segments(offset=0, limit=100)

        assert result == [".text", ".data", ".bss"]
        mock_safe_get.assert_called_once_with("segments", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_decompile_function(self, mock_safe_post):
        """Test decompile_function tool."""
        mock_safe_post.return_value = "int main() { return 0; }"

        result = bridge_mcp_ghidra.decompile_function("main")

        assert result == "int main() { return 0; }"
        mock_safe_post.assert_called_once_with("decompile", "main")

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_function(self, mock_safe_post):
        """Test rename_function tool."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.rename_function("old_func", "new_func")

        assert result == "Success"
        mock_safe_post.assert_called_once_with("renameFunction",
                                                 {"oldName": "old_func", "newName": "new_func"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_data(self, mock_safe_post):
        """Test rename_data tool."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.rename_data("0x401000", "new_label")

        assert result == "Success"
        mock_safe_post.assert_called_once_with("renameData",
                                                 {"address": "0x401000", "newName": "new_label"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_data_by_address(self, mock_safe_get):
        """Test get_data_by_address tool."""
        mock_safe_get.return_value = [
            "Address: 5356:3cd8",
            "Name: g_EventQueue_ErrorCode",
            "Type: word",
            "Value: 0x1234",
            "Size: 2 bytes"
        ]

        result = bridge_mcp_ghidra.get_data_by_address("5356:3cd8")

        assert "Address: 5356:3cd8" in result
        assert "Name: g_EventQueue_ErrorCode" in result
        assert "Type: word" in result
        assert "Value: 0x1234" in result
        mock_safe_get.assert_called_once_with("get_data_by_address", {"address": "5356:3cd8"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_data_by_address_hex_format(self, mock_safe_get):
        """Test get_data_by_address with hex address format."""
        mock_safe_get.return_value = [
            "Address: 0x1400010a0",
            "Name: data_label",
            "Type: dword",
            "Value: 0xdeadbeef",
            "Size: 4 bytes"
        ]

        result = bridge_mcp_ghidra.get_data_by_address("0x1400010a0")

        assert "0x1400010a0" in result
        assert "data_label" in result
        mock_safe_get.assert_called_once_with("get_data_by_address", {"address": "0x1400010a0"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_functions_by_segment_with_segment_name(self, mock_safe_get):
        """Test list_functions_by_segment with segment_name parameter."""
        mock_safe_get.return_value = [
            "func1 @ CODE_70:001a (size: 42 bytes)",
            "func2 @ CODE_70:003c (size: 28 bytes)"
        ]

        result = bridge_mcp_ghidra.list_functions_by_segment(
            segment_name="CODE_70",
            offset=0,
            limit=100
        )

        assert len(result) == 2
        assert "func1" in result[0]
        assert "CODE_70:001a" in result[0]
        mock_safe_get.assert_called_once_with("functions_by_segment", {
            "segment_name": "CODE_70",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_functions_by_segment_with_address_range(self, mock_safe_get):
        """Test list_functions_by_segment with address range."""
        mock_safe_get.return_value = ["func1 @ 4592:000e (size: 100 bytes)"]

        result = bridge_mcp_ghidra.list_functions_by_segment(
            start_address="4592:000e",
            end_address="4592:0399",
            offset=0,
            limit=50
        )

        assert len(result) == 1
        mock_safe_get.assert_called_once_with("functions_by_segment", {
            "start_address": "4592:000e",
            "end_address": "4592:0399",
            "offset": 0,
            "limit": 50
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_functions_by_segment_missing_params(self, mock_safe_get):
        """Test list_functions_by_segment with missing required parameters."""
        result = bridge_mcp_ghidra.list_functions_by_segment()

        assert len(result) == 1
        assert "Error" in result[0]
        assert "segment_name or both start_address and end_address" in result[0]
        mock_safe_get.assert_not_called()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_functions_by_segment_with_pagination(self, mock_safe_get):
        """Test list_functions_by_segment with custom pagination."""
        mock_safe_get.return_value = ["func3 @ CODE_70:0100 (size: 64 bytes)"]

        result = bridge_mcp_ghidra.list_functions_by_segment(
            segment_name="CODE_70",
            offset=10,
            limit=20
        )

        mock_safe_get.assert_called_once_with("functions_by_segment", {
            "segment_name": "CODE_70",
            "offset": 10,
            "limit": 20
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_data_by_segment_with_segment_name(self, mock_safe_get):
        """Test list_data_by_segment with segment_name parameter."""
        mock_safe_get.return_value = [
            "label1 @ CODE_70:0020 [word] = 0x1234",
            "label2 @ CODE_70:0022 [byte] = 0x42"
        ]

        result = bridge_mcp_ghidra.list_data_by_segment(
            segment_name="CODE_70",
            offset=0,
            limit=100
        )

        assert len(result) == 2
        assert "label1" in result[0]
        assert "CODE_70:0020" in result[0]
        assert "word" in result[0]
        mock_safe_get.assert_called_once_with("data_by_segment", {
            "segment_name": "CODE_70",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_data_by_segment_with_address_range(self, mock_safe_get):
        """Test list_data_by_segment with address range."""
        mock_safe_get.return_value = ["data1 @ 4592:0010 [dword] = 0xdeadbeef"]

        result = bridge_mcp_ghidra.list_data_by_segment(
            start_address="4592:0000",
            end_address="4592:00ff",
            offset=0,
            limit=100
        )

        assert len(result) == 1
        mock_safe_get.assert_called_once_with("data_by_segment", {
            "start_address": "4592:0000",
            "end_address": "4592:00ff",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_data_by_segment_missing_params(self, mock_safe_get):
        """Test list_data_by_segment with missing required parameters."""
        result = bridge_mcp_ghidra.list_data_by_segment()

        assert len(result) == 1
        assert "Error" in result[0]
        assert "segment_name or both start_address and end_address" in result[0]
        mock_safe_get.assert_not_called()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_data_by_segment_with_pagination(self, mock_safe_get):
        """Test list_data_by_segment with custom pagination."""
        mock_safe_get.return_value = ["data2 @ CODE_70:0050 [string] = \"test\""]

        result = bridge_mcp_ghidra.list_data_by_segment(
            segment_name="CODE_70",
            offset=5,
            limit=25
        )

        mock_safe_get.assert_called_once_with("data_by_segment", {
            "segment_name": "CODE_70",
            "offset": 5,
            "limit": 25
        })


class TestGlobalConfiguration:
    """Test suite for global configuration variables."""

    def test_default_ghidra_server_url(self):
        """Test that default Ghidra server URL is set correctly."""
        assert bridge_mcp_ghidra.DEFAULT_GHIDRA_SERVER == "http://127.0.0.1:8080/"
        assert bridge_mcp_ghidra.ghidra_server_url == "http://127.0.0.1:8080/"

    def test_default_request_timeout(self):
        """Test that default request timeout is set correctly."""
        assert bridge_mcp_ghidra.DEFAULT_REQUEST_TIMEOUT == 5
        assert bridge_mcp_ghidra.ghidra_request_timeout == 5

    def test_mcp_server_name(self):
        """Test that MCP server has correct name."""
        assert bridge_mcp_ghidra.mcp.name == "ghidra-mcp"


class TestEdgeCases:
    """Test suite for edge cases and error conditions."""

    @patch('bridge_mcp_ghidra.requests.get')
    def test_safe_get_empty_response(self, mock_get):
        """Test GET request with empty response."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = ""
        mock_get.return_value = mock_response

        result = bridge_mcp_ghidra.safe_get("test_endpoint")

        assert result == []

    @patch('bridge_mcp_ghidra.requests.post')
    def test_safe_post_empty_string_data(self, mock_post):
        """Test POST request with empty string."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = "OK"
        mock_post.return_value = mock_response

        result = bridge_mcp_ghidra.safe_post("test_endpoint", "")

        assert result == "OK"

    @patch('bridge_mcp_ghidra.requests.post')
    def test_safe_post_empty_dict_data(self, mock_post):
        """Test POST request with empty dict."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = "OK"
        mock_post.return_value = mock_response

        result = bridge_mcp_ghidra.safe_post("test_endpoint", {})

        assert result == "OK"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_methods_with_zero_limit(self, mock_safe_get):
        """Test list_methods with limit of 0."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.list_methods(offset=0, limit=0)

        assert result == []
        mock_safe_get.assert_called_once_with("methods", {"offset": 0, "limit": 0})


class TestNumericSearchQueries:
    """Test suite for search functions with numeric query strings."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_string(self, mock_safe_get):
        """Test search_functions_by_name with regular string query."""
        mock_safe_get.return_value = ["function_test1", "function_test2"]

        result = bridge_mcp_ghidra.search_functions_by_name("test", offset=0, limit=100)

        assert result == ["function_test1", "function_test2"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "test", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_numeric_string(self, mock_safe_get):
        """Test search_functions_by_name with numeric string query (e.g., '4140')."""
        mock_safe_get.return_value = ["function_4140", "sub_4140"]

        result = bridge_mcp_ghidra.search_functions_by_name("4140", offset=0, limit=100)

        assert result == ["function_4140", "sub_4140"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "4140", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_integer(self, mock_safe_get):
        """Test search_functions_by_name with integer query (handles JSON parsing as int)."""
        mock_safe_get.return_value = ["FUN_00004140"]

        # Simulate MCP client sending an integer due to JSON parsing
        result = bridge_mcp_ghidra.search_functions_by_name(4140, offset=0, limit=20)

        assert result == ["FUN_00004140"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "4140", "offset": 0, "limit": 20})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_hex_string(self, mock_safe_get):
        """Test search_functions_by_name with hexadecimal string."""
        mock_safe_get.return_value = ["function_0x1234"]

        result = bridge_mcp_ghidra.search_functions_by_name("0x1234", offset=0, limit=50)

        assert result == ["function_0x1234"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "0x1234", "offset": 0, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_empty_string(self, mock_safe_get):
        """Test search_functions_by_name with empty string returns error."""
        result = bridge_mcp_ghidra.search_functions_by_name("", offset=0, limit=100)

        assert len(result) == 1
        assert "Error" in result[0]
        assert "query string is required" in result[0]
        mock_safe_get.assert_not_called()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_zero_integer(self, mock_safe_get):
        """Test search_functions_by_name with zero (edge case for falsy value)."""
        mock_safe_get.return_value = ["function_0"]

        result = bridge_mcp_ghidra.search_functions_by_name(0, offset=0, limit=100)

        assert result == ["function_0"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "0", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_data_by_name_with_string(self, mock_safe_get):
        """Test search_data_by_name with regular string query."""
        mock_safe_get.return_value = ["data_label1", "data_label2"]

        result = bridge_mcp_ghidra.search_data_by_name("label", offset=0, limit=100)

        assert result == ["data_label1", "data_label2"]
        mock_safe_get.assert_called_once_with("searchData", {"query": "label", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_data_by_name_with_numeric_string(self, mock_safe_get):
        """Test search_data_by_name with numeric string query."""
        mock_safe_get.return_value = ["DAT_00004140"]

        result = bridge_mcp_ghidra.search_data_by_name("4140", offset=0, limit=100)

        assert result == ["DAT_00004140"]
        mock_safe_get.assert_called_once_with("searchData", {"query": "4140", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_data_by_name_with_integer(self, mock_safe_get):
        """Test search_data_by_name with integer query (handles JSON parsing as int)."""
        mock_safe_get.return_value = ["data_8080"]

        # Simulate MCP client sending an integer due to JSON parsing
        result = bridge_mcp_ghidra.search_data_by_name(8080, offset=0, limit=50)

        assert result == ["data_8080"]
        mock_safe_get.assert_called_once_with("searchData", {"query": "8080", "offset": 0, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_data_by_name_with_empty_string(self, mock_safe_get):
        """Test search_data_by_name with empty string returns error."""
        result = bridge_mcp_ghidra.search_data_by_name("", offset=0, limit=100)

        assert len(result) == 1
        assert "Error" in result[0]
        assert "query string is required" in result[0]
        mock_safe_get.assert_not_called()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_data_by_name_with_negative_integer(self, mock_safe_get):
        """Test search_data_by_name with negative integer."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.search_data_by_name(-1, offset=0, limit=100)

        assert result == []
        mock_safe_get.assert_called_once_with("searchData", {"query": "-1", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_large_integer(self, mock_safe_get):
        """Test search_functions_by_name with large integer value."""
        mock_safe_get.return_value = ["FUN_deadbeef"]

        result = bridge_mcp_ghidra.search_functions_by_name(3735928559, offset=0, limit=100)  # 0xdeadbeef

        assert result == ["FUN_deadbeef"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "3735928559", "offset": 0, "limit": 100})
