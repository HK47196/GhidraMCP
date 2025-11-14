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

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_data_in_range_basic(self, mock_safe_get):
        """Test get_data_in_range with basic hex address range."""
        mock_safe_get.return_value = [
            "Data items from 0x00231fec to 0x00232100 (include_undefined=false):",
            "",
            "0x00231fec: stack_array [byte[20], 20 bytes] = [0x00, 0x01, ...]",
            "0x00232000: vm_register_1 [word, 2 bytes] = 0x1234",
            "0x00232002: vm_register_2 [word, 2 bytes] = 0x5678",
            "0x00232004: vm_register_3 [dword, 4 bytes] = 0xdeadbeef",
            "",
            "Total: 4 item(s)"
        ]

        result = bridge_mcp_ghidra.get_data_in_range("0x00231fec", "0x00232100")

        assert "Data items from 0x00231fec to 0x00232100" in result
        assert "stack_array" in result
        assert "vm_register_1" in result
        assert "Total: 4 item(s)" in result
        mock_safe_get.assert_called_once_with("data_in_range", {
            "start_address": "0x00231fec",
            "end_address": "0x00232100",
            "include_undefined": "false"
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_data_in_range_segment_offset(self, mock_safe_get):
        """Test get_data_in_range with segment:offset format."""
        mock_safe_get.return_value = [
            "Data items from 5356:3cd8 to 5356:3d00 (include_undefined=false):",
            "",
            "5356:3cd8: g_EventQueue_ErrorCode [word, 2 bytes] = 0x0000",
            "5356:3cda: g_EventQueue_Flags [byte, 1 bytes] = 0x01",
            "",
            "Total: 2 item(s)"
        ]

        result = bridge_mcp_ghidra.get_data_in_range("5356:3cd8", "5356:3d00")

        assert "5356:3cd8" in result
        assert "g_EventQueue_ErrorCode" in result
        assert "g_EventQueue_Flags" in result
        mock_safe_get.assert_called_once_with("data_in_range", {
            "start_address": "5356:3cd8",
            "end_address": "5356:3d00",
            "include_undefined": "false"
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_data_in_range_include_undefined_true(self, mock_safe_get):
        """Test get_data_in_range with include_undefined=True."""
        mock_safe_get.return_value = [
            "Data items from 0x401000 to 0x401020 (include_undefined=true):",
            "",
            "0x401000: label1 [dword, 4 bytes] = 0x12345678",
            "0x401004: (unnamed) [undefined, 1 bytes] = ??",
            "0x401005: (unnamed) [undefined, 1 bytes] = ??",
            "0x401006: label2 [word, 2 bytes] = 0xabcd",
            "",
            "Total: 4 item(s)"
        ]

        result = bridge_mcp_ghidra.get_data_in_range(
            "0x401000",
            "0x401020",
            include_undefined=True
        )

        assert "include_undefined=true" in result
        assert "undefined" in result
        assert "Total: 4 item(s)" in result
        mock_safe_get.assert_called_once_with("data_in_range", {
            "start_address": "0x401000",
            "end_address": "0x401020",
            "include_undefined": "true"
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_data_in_range_include_undefined_false(self, mock_safe_get):
        """Test get_data_in_range with include_undefined=False (default)."""
        mock_safe_get.return_value = [
            "Data items from 0x401000 to 0x401020 (include_undefined=false):",
            "",
            "0x401000: label1 [dword, 4 bytes] = 0x12345678",
            "0x401006: label2 [word, 2 bytes] = 0xabcd",
            "",
            "Total: 2 item(s)"
        ]

        result = bridge_mcp_ghidra.get_data_in_range(
            "0x401000",
            "0x401020",
            include_undefined=False
        )

        assert "include_undefined=false" in result
        assert "[undefined" not in result  # No undefined data items should be shown
        assert "Total: 2 item(s)" in result
        mock_safe_get.assert_called_once_with("data_in_range", {
            "start_address": "0x401000",
            "end_address": "0x401020",
            "include_undefined": "false"
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_data_in_range_empty_result(self, mock_safe_get):
        """Test get_data_in_range with empty range (no data found)."""
        mock_safe_get.return_value = [
            "Data items from 0x500000 to 0x500100 (include_undefined=false):",
            "",
            "No data items found in the specified range"
        ]

        result = bridge_mcp_ghidra.get_data_in_range("0x500000", "0x500100")

        assert "No data items found" in result
        mock_safe_get.assert_called_once_with("data_in_range", {
            "start_address": "0x500000",
            "end_address": "0x500100",
            "include_undefined": "false"
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_data_in_range_with_strings(self, mock_safe_get):
        """Test get_data_in_range with string data types."""
        mock_safe_get.return_value = [
            "Data items from 0x404000 to 0x404050 (include_undefined=false):",
            "",
            "0x404000: str_hello [string, 12 bytes] = \"Hello World\"",
            "0x40400c: str_test [unicode, 20 bytes] = \"Test String\"",
            "",
            "Total: 2 item(s)"
        ]

        result = bridge_mcp_ghidra.get_data_in_range("0x404000", "0x404050")

        assert "str_hello" in result
        assert "Hello World" in result
        assert "str_test" in result
        assert "unicode" in result
        mock_safe_get.assert_called_once()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_data_in_range_with_arrays(self, mock_safe_get):
        """Test get_data_in_range with array data types."""
        mock_safe_get.return_value = [
            "Data items from 0x600000 to 0x600100 (include_undefined=false):",
            "",
            "0x600000: buffer [byte[256], 256 bytes] = [0x00, 0x01, ...]",
            "0x600100: matrix [int[16], 64 bytes] = [0, 1, 2, ...]",
            "",
            "Total: 2 item(s)"
        ]

        result = bridge_mcp_ghidra.get_data_in_range("0x600000", "0x600100")

        assert "buffer" in result
        assert "byte[256]" in result
        assert "matrix" in result
        assert "int[16]" in result
        mock_safe_get.assert_called_once()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_data_in_range_large_range(self, mock_safe_get):
        """Test get_data_in_range with many items in range."""
        # Simulate a response with 10 items
        items = []
        items.append("Data items from 0x700000 to 0x700100 (include_undefined=false):")
        items.append("")
        for i in range(10):
            items.append(f"0x70000{i:x}: data_{i} [dword, 4 bytes] = 0x{i*0x1000:08x}")
        items.append("")
        items.append("Total: 10 item(s)")

        mock_safe_get.return_value = items

        result = bridge_mcp_ghidra.get_data_in_range("0x700000", "0x700100")

        assert "Total: 10 item(s)" in result
        assert "data_0" in result
        assert "data_9" in result
        mock_safe_get.assert_called_once()


class TestGlobalConfiguration:
    """Test suite for global configuration variables."""

    def test_default_ghidra_server_url(self):
        """Test that default Ghidra server URL is set correctly."""
        assert bridge_mcp_ghidra.DEFAULT_GHIDRA_SERVER == "http://127.0.0.1:8080/"
        assert bridge_mcp_ghidra.ghidra_server_url == "http://127.0.0.1:8080/"

    def test_default_request_timeout(self):
        """Test that default request timeout is set correctly."""
        assert bridge_mcp_ghidra.DEFAULT_REQUEST_TIMEOUT == 60
        assert bridge_mcp_ghidra.ghidra_request_timeout == 60

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


class TestNamespaceSearch:
    """Test suite for namespace detection in search_functions_by_name."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespace_only(self, mock_safe_get):
        """Test search with namespace only (ending with ::)."""
        mock_safe_get.return_value = ["thunk::func1", "thunk::func2", "thunk::func3"]

        result = bridge_mcp_ghidra.search_functions_by_name("thunk::", offset=0, limit=100)

        assert result == ["thunk::func1", "thunk::func2", "thunk::func3"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "thunk",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespace_with_function(self, mock_safe_get):
        """Test search with namespace and function name."""
        mock_safe_get.return_value = ["thunk::fun1", "thunk::fun2"]

        result = bridge_mcp_ghidra.search_functions_by_name("thunk::fun", offset=0, limit=100)

        assert result == ["thunk::fun1", "thunk::fun2"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "thunk",
            "function_name": "fun",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_nested_namespace_only(self, mock_safe_get):
        """Test search with nested namespace (A::B::)."""
        mock_safe_get.return_value = ["A::B::func1", "A::B::func2"]

        result = bridge_mcp_ghidra.search_functions_by_name("A::B::", offset=0, limit=100)

        assert result == ["A::B::func1", "A::B::func2"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "A::B",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_nested_namespace_with_function(self, mock_safe_get):
        """Test search with nested namespace and function name (A::B::fun)."""
        mock_safe_get.return_value = ["A::B::fun"]

        result = bridge_mcp_ghidra.search_functions_by_name("A::B::fun", offset=0, limit=100)

        assert result == ["A::B::fun"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "A::B",
            "function_name": "fun",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_deeply_nested_namespace(self, mock_safe_get):
        """Test search with deeply nested namespace (A::B::C::D::)."""
        mock_safe_get.return_value = ["A::B::C::D::func"]

        result = bridge_mcp_ghidra.search_functions_by_name("A::B::C::D::", offset=0, limit=50)

        assert result == ["A::B::C::D::func"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "A::B::C::D",
            "offset": 0,
            "limit": 50
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_deeply_nested_namespace_with_function(self, mock_safe_get):
        """Test search with deeply nested namespace and function."""
        mock_safe_get.return_value = ["std::vector::iterator::begin"]

        result = bridge_mcp_ghidra.search_functions_by_name("std::vector::iterator::begin")

        assert result == ["std::vector::iterator::begin"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "std::vector::iterator",
            "function_name": "begin",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_without_namespace_syntax(self, mock_safe_get):
        """Test search without namespace syntax (standard search)."""
        mock_safe_get.return_value = ["my_function", "another_function"]

        result = bridge_mcp_ghidra.search_functions_by_name("function", offset=0, limit=100)

        assert result == ["my_function", "another_function"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "query": "function",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_std_namespace(self, mock_safe_get):
        """Test search with std namespace (common C++ namespace)."""
        mock_safe_get.return_value = ["std::vector", "std::string", "std::map"]

        result = bridge_mcp_ghidra.search_functions_by_name("std::", offset=0, limit=100)

        assert result == ["std::vector", "std::string", "std::map"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "std",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespace_with_pagination(self, mock_safe_get):
        """Test namespace search with custom pagination."""
        mock_safe_get.return_value = ["ns::func10"]

        result = bridge_mcp_ghidra.search_functions_by_name("ns::", offset=10, limit=20)

        assert result == ["ns::func10"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "ns",
            "offset": 10,
            "limit": 20
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_single_colon_no_namespace(self, mock_safe_get):
        """Test search with single colon (not namespace syntax)."""
        mock_safe_get.return_value = ["func:label"]

        result = bridge_mcp_ghidra.search_functions_by_name("func:label", offset=0, limit=100)

        assert result == ["func:label"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "query": "func:label",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespace_numeric_query(self, mock_safe_get):
        """Test namespace search when query looks numeric but has namespace."""
        mock_safe_get.return_value = ["ns::4140"]

        result = bridge_mcp_ghidra.search_functions_by_name("ns::4140", offset=0, limit=100)

        assert result == ["ns::4140"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "ns",
            "function_name": "4140",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_underscore_namespace(self, mock_safe_get):
        """Test namespace with underscores."""
        mock_safe_get.return_value = ["my_namespace::my_func"]

        result = bridge_mcp_ghidra.search_functions_by_name("my_namespace::my_func")

        assert result == ["my_namespace::my_func"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "my_namespace",
            "function_name": "my_func",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_global_namespace_prefix(self, mock_safe_get):
        """Test search with global namespace prefix (::func)."""
        mock_safe_get.return_value = ["::global_func"]

        result = bridge_mcp_ghidra.search_functions_by_name("::global_func")

        assert result == ["::global_func"]
        # Empty namespace before ::, so only function_name is set
        call_args = mock_safe_get.call_args[0][1]
        assert "function_name" in call_args
        assert call_args["function_name"] == "global_func"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_empty_namespace_before_separator(self, mock_safe_get):
        """Test that empty namespace is handled correctly."""
        mock_safe_get.return_value = ["func"]

        result = bridge_mcp_ghidra.search_functions_by_name("::func")

        assert result == ["func"]
        # Should only have function_name, not namespace (since namespace is empty)
        call_args = mock_safe_get.call_args[0][1]
        assert "namespace" not in call_args or call_args.get("namespace") == ""
        assert call_args["function_name"] == "func"


class TestSearchDecompiledText:
    """Test suite for the search_decompiled_text MCP tool."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_basic_regex(self, mock_safe_post):
        """Test basic regex search in decompiled text."""
        mock_response = '{"matches": [{"function_name": "main", "matched_text": "malloc", "line_number": 10}], "count": 1}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text("malloc\\s*\\(")

        assert result == mock_response
        mock_safe_post.assert_called_once()
        call_args = mock_safe_post.call_args[0]
        assert call_args[0] == "search_decompiled_text"
        data = call_args[1]
        assert data["pattern"] == "malloc\\s*\\("
        assert data["is_regex"] is True
        assert data["case_sensitive"] is True
        assert data["multiline"] is False

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_literal_string(self, mock_safe_post):
        """Test literal string search."""
        mock_response = '{"matches": [], "count": 0}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text(
            "strcpy",
            is_regex=False,
            case_sensitive=False
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        assert data["pattern"] == "strcpy"
        assert data["is_regex"] is False
        assert data["case_sensitive"] is False

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_with_multiline(self, mock_safe_post):
        """Test multiline search."""
        mock_response = '{"matches": [{"function_name": "test", "is_multiline": true}], "count": 1}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text(
            "if\\s*\\([^)]*\\)\\s*\\{",
            multiline=True
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        assert data["multiline"] is True

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_with_function_names(self, mock_safe_post):
        """Test search filtered by specific function names."""
        mock_response = '{"matches": [], "count": 0}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text(
            "password",
            is_regex=False,
            function_names=["authenticate", "login", "verify_user"]
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        assert data["function_names"] == "authenticate,login,verify_user"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_with_empty_function_names(self, mock_safe_post):
        """Test search with empty function names list (search all)."""
        mock_response = '{"matches": [], "count": 0}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text(
            "test",
            function_names=[]
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        assert "function_names" not in data

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_with_max_results(self, mock_safe_post):
        """Test search with max_results parameter."""
        mock_response = '{"matches": [], "count": 0, "total_count": 50}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text(
            "malloc",
            max_results=50
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        assert data["max_results"] == 50

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_with_pagination(self, mock_safe_post):
        """Test search with pagination parameters."""
        mock_response = '{"matches": [], "count": 10, "offset": 20, "limit": 10}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text(
            "test",
            offset=20,
            limit=10
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        assert data["offset"] == 20
        assert data["limit"] == 10

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_default_parameters(self, mock_safe_post):
        """Test search with default parameters."""
        mock_response = '{"matches": [], "count": 0}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text("test_pattern")

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        # Verify defaults
        assert data["is_regex"] is True
        assert data["case_sensitive"] is True
        assert data["multiline"] is False
        assert data["max_results"] == 100
        assert data["offset"] == 0
        assert data["limit"] == 100

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_security_patterns(self, mock_safe_post):
        """Test search for security-relevant patterns."""
        mock_response = '{"matches": [{"function_name": "vulnerable", "matched_text": "gets"}], "count": 1}'
        mock_safe_post.return_value = mock_response

        # Common dangerous function pattern
        result = bridge_mcp_ghidra.search_decompiled_text(
            "(gets|strcpy|sprintf|strcat)\\s*\\("
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        assert "(gets|strcpy|sprintf|strcat)\\s*\\(" in data["pattern"]

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_case_insensitive(self, mock_safe_post):
        """Test case-insensitive search."""
        mock_response = '{"matches": [], "count": 0}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text(
            "MALLOC",
            case_sensitive=False
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        assert data["case_sensitive"] is False

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_complex_regex(self, mock_safe_post):
        """Test complex regex pattern."""
        mock_response = '{"matches": [], "count": 0}'
        mock_safe_post.return_value = mock_response

        # Pattern to find buffer allocation with size
        result = bridge_mcp_ghidra.search_decompiled_text(
            "malloc\\s*\\(\\s*[0-9]+\\s*\\)"
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        assert "malloc" in data["pattern"]

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_with_special_chars(self, mock_safe_post):
        """Test search with special regex characters."""
        mock_response = '{"matches": [], "count": 0}'
        mock_safe_post.return_value = mock_response

        # Pattern with brackets and parentheses
        result = bridge_mcp_ghidra.search_decompiled_text(
            "array\\[.*?\\]\\s*=\\s*.*?;"
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        assert call_args[0] == "search_decompiled_text"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_unlimited_results(self, mock_safe_post):
        """Test search with unlimited results (max_results=0)."""
        mock_response = '{"matches": [], "count": 0, "total_count": 1000}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text(
            "test",
            max_results=0  # Unlimited
        )

        assert result == mock_response
        call_args = mock_safe_post.call_args[0]
        data = call_args[1]
        assert data["max_results"] == 0

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_response_format(self, mock_safe_post):
        """Test that response has expected JSON format."""
        mock_response = '''{
            "matches": [
                {
                    "function_name": "main",
                    "function_address": "0x401000",
                    "line_number": 42,
                    "matched_text": "malloc",
                    "context": "ptr = [[malloc]](100);",
                    "is_multiline": false
                }
            ],
            "count": 1,
            "total_count": 1,
            "offset": 0,
            "limit": 100
        }'''
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text("malloc")

        assert result == mock_response
        assert "matches" in result
        assert "count" in result
        assert "function_name" in result
        assert "line_number" in result
        assert "context" in result

    @patch('bridge_mcp_ghidra.safe_post')
    def test_search_decompiled_text_error_response(self, mock_safe_post):
        """Test handling of error responses."""
        mock_response = '{"error": "Invalid regex pattern: Unclosed bracket"}'
        mock_safe_post.return_value = mock_response

        result = bridge_mcp_ghidra.search_decompiled_text("[invalid")

        assert result == mock_response
        assert "error" in result


class TestManualTool:
    """Test suite for the man() tool and MANUAL dictionary."""

    def test_manual_dictionary_exists(self):
        """Test that MANUAL dictionary is defined."""
        assert hasattr(bridge_mcp_ghidra, 'MANUAL')
        assert isinstance(bridge_mcp_ghidra.MANUAL, dict)

    def test_manual_dictionary_not_empty(self):
        """Test that MANUAL dictionary contains entries."""
        assert len(bridge_mcp_ghidra.MANUAL) > 0

    def test_manual_entries_are_strings(self):
        """Test that all MANUAL entries are strings."""
        for key, value in bridge_mcp_ghidra.MANUAL.items():
            assert isinstance(key, str), f"Key {key} is not a string"
            assert isinstance(value, str), f"Value for {key} is not a string"

    def test_manual_entries_contain_params_section(self):
        """Test that MANUAL entries have Params section."""
        # Most entries should have Params, except ones with no parameters
        entries_with_params = 0
        for key, value in bridge_mcp_ghidra.MANUAL.items():
            if "Params:" in value:
                entries_with_params += 1
        # At least some entries should have params
        assert entries_with_params > 0

    def test_manual_entries_contain_returns_section(self):
        """Test that MANUAL entries have Returns section."""
        entries_with_returns = 0
        for key, value in bridge_mcp_ghidra.MANUAL.items():
            if "Returns:" in value:
                entries_with_returns += 1
        # Most entries should have returns
        assert entries_with_returns > 0

    def test_man_function_exists(self):
        """Test that man() function is defined."""
        assert hasattr(bridge_mcp_ghidra, 'man')
        assert callable(bridge_mcp_ghidra.man)

    def test_man_returns_documentation_for_known_tool(self):
        """Test man() returns documentation for a tool in MANUAL."""
        result = bridge_mcp_ghidra.man("get_data_by_address")

        assert "=== Manual: get_data_by_address ===" in result
        assert "Params:" in result
        assert "address:" in result
        assert "Returns:" in result

    def test_man_returns_documentation_for_bsim_tool(self):
        """Test man() returns documentation for BSim tools."""
        result = bridge_mcp_ghidra.man("bsim_query_function")

        assert "=== Manual: bsim_query_function ===" in result
        assert "function_address:" in result
        assert "similarity_threshold:" in result
        assert "confidence_threshold:" in result

    def test_man_returns_documentation_for_struct_tool(self):
        """Test man() returns documentation for struct tools."""
        result = bridge_mcp_ghidra.man("create_struct")

        assert "=== Manual: create_struct ===" in result
        assert "name:" in result
        assert "size:" in result
        assert "category_path:" in result

    def test_man_returns_self_documentation(self):
        """Test man("man") returns documentation for itself."""
        result = bridge_mcp_ghidra.man("man")

        assert "=== Manual: man ===" in result
        assert "Params:" in result
        assert "tool_name:" in result
        assert "Available manual pages" in result

    def test_man_lists_available_tools(self):
        """Test man("man") lists all available tools."""
        result = bridge_mcp_ghidra.man("man")

        # Should list at least some known tools
        assert "get_data_by_address" in result or len(bridge_mcp_ghidra.MANUAL) > 0
        # Should show count
        assert f"({len(bridge_mcp_ghidra.MANUAL)})" in result

    def test_man_returns_error_for_unknown_tool(self):
        """Test man() returns error message for unknown tool."""
        result = bridge_mcp_ghidra.man("nonexistent_tool")

        assert "not found in manual" in result
        assert "Available manual pages" in result

    def test_man_error_includes_available_tools(self):
        """Test error message includes list of available tools."""
        result = bridge_mcp_ghidra.man("invalid_tool")

        # Should show count of available tools
        assert f"({len(bridge_mcp_ghidra.MANUAL)})" in result
        # Should suggest checking inline docstring
        assert "inline docstring" in result

    def test_manual_has_xref_tools(self):
        """Test MANUAL contains xref tool documentation."""
        assert "get_xrefs_to" in bridge_mcp_ghidra.MANUAL
        assert "get_xrefs_from" in bridge_mcp_ghidra.MANUAL
        assert "get_function_xrefs" in bridge_mcp_ghidra.MANUAL

    def test_manual_has_bsim_tools(self):
        """Test MANUAL contains BSim tool documentation."""
        assert "bsim_select_database" in bridge_mcp_ghidra.MANUAL
        assert "bsim_query_function" in bridge_mcp_ghidra.MANUAL
        assert "bsim_query_all_functions" in bridge_mcp_ghidra.MANUAL
        assert "bsim_disconnect" in bridge_mcp_ghidra.MANUAL
        assert "bsim_status" in bridge_mcp_ghidra.MANUAL

    def test_manual_has_struct_tools(self):
        """Test MANUAL contains struct tool documentation."""
        assert "create_struct" in bridge_mcp_ghidra.MANUAL
        assert "parse_c_struct" in bridge_mcp_ghidra.MANUAL
        assert "add_struct_field" in bridge_mcp_ghidra.MANUAL
        assert "get_struct_info" in bridge_mcp_ghidra.MANUAL
        assert "delete_struct" in bridge_mcp_ghidra.MANUAL

    def test_manual_entry_completeness_get_data_by_address(self):
        """Test get_data_by_address manual entry is complete."""
        entry = bridge_mcp_ghidra.MANUAL["get_data_by_address"]

        assert "address:" in entry
        assert "Memory address" in entry
        assert "hex or segment:offset" in entry
        assert "Returns:" in entry

    def test_manual_entry_completeness_bsim_query_function(self):
        """Test bsim_query_function manual entry is complete."""
        entry = bridge_mcp_ghidra.MANUAL["bsim_query_function"]

        # Check all parameters are documented
        assert "function_address:" in entry
        assert "max_matches:" in entry
        assert "similarity_threshold:" in entry
        assert "confidence_threshold:" in entry
        assert "max_similarity:" in entry
        assert "max_confidence:" in entry
        assert "Returns:" in entry

    def test_manual_entry_has_examples_for_bulk_operations(self):
        """Test bulk_operations manual entry includes examples."""
        entry = bridge_mcp_ghidra.MANUAL["bulk_operations"]

        assert "Example:" in entry
        assert "endpoint" in entry
        assert "params" in entry

    def test_manual_entry_has_notes_for_parse_c_struct(self):
        """Test parse_c_struct manual entry includes important notes."""
        entry = bridge_mcp_ghidra.MANUAL["parse_c_struct"]

        assert "Note:" in entry
        assert "preprocessed" in entry
        assert "#includes" in entry

    def test_man_preserves_original_verbose_documentation(self):
        """Test that man() returns detailed docs unlike compact tool docstrings."""
        # Get the actual function's docstring (compact)
        func_docstring = bridge_mcp_ghidra.bsim_query_function.__doc__

        # Get the manual entry (verbose)
        manual_entry = bridge_mcp_ghidra.man("bsim_query_function")

        # Manual should be more verbose
        assert len(manual_entry) > len(func_docstring)
        # Manual should have detailed parameter explanations
        assert "similarity_threshold:" in manual_entry
        assert "inclusive" in manual_entry.lower()

    def test_man_tool_is_registered(self):
        """Test that man tool is registered in tool registry."""
        assert "man" in bridge_mcp_ghidra._tool_registry

    def test_man_tool_is_in_query_category(self):
        """Test that man tool is listed in the query category."""
        assert "man" in bridge_mcp_ghidra.TOOL_CATEGORIES["query"]

    def test_all_manual_keys_are_valid_tool_names(self):
        """Test that all MANUAL keys correspond to valid functions."""
        for tool_name in bridge_mcp_ghidra.MANUAL.keys():
            # Each tool should either be in the registry or be a valid function
            assert (tool_name in bridge_mcp_ghidra._tool_registry or
                    hasattr(bridge_mcp_ghidra, tool_name)), \
                   f"Tool {tool_name} in MANUAL but not found as function"

    def test_man_output_format_consistency(self):
        """Test that man() output follows consistent format."""
        result = bridge_mcp_ghidra.man("set_data_type")

        # Should start with header
        assert result.startswith("=== Manual:")
        assert "===" in result
        # Should contain the tool name in header
        assert "set_data_type" in result.split("\n")[0]

    def test_man_handles_tools_with_complex_params(self):
        """Test man() handles tools with complex parameter documentation."""
        result = bridge_mcp_ghidra.man("bulk_operations")

        # Should handle list[dict] type documentation
        assert "operations:" in result
        assert "endpoint:" in result
        assert "params:" in result

    def test_manual_coverage_percentage(self):
        """Test that MANUAL covers a reasonable percentage of tools."""
        total_tools = len(bridge_mcp_ghidra._tool_registry)
        documented_tools = len(bridge_mcp_ghidra.MANUAL)

        # At least some tools should be documented
        assert documented_tools > 0
        # Should document the most important/complex tools
        assert documented_tools >= 20  # We have 27 documented


class TestToolTrackerIntegration:
    """Test suite for ToolTracker integration with the bridge."""

    def test_tool_tracker_import(self):
        """Test that ToolTracker can be imported."""
        from tool_tracker import ToolTracker
        assert ToolTracker is not None

    def test_global_tracker_variable_exists(self):
        """Test that the global _tool_tracker variable exists."""
        assert hasattr(bridge_mcp_ghidra, '_tool_tracker')

    def test_register_tools_without_tracker(self):
        """Test that register_tools works when tracker is None."""
        # Save original state
        original_registered = bridge_mcp_ghidra._tools_registered
        original_tracker = bridge_mcp_ghidra._tool_tracker

        try:
            # Reset state
            bridge_mcp_ghidra._tools_registered = False
            bridge_mcp_ghidra._tool_tracker = None

            # Should not raise an exception
            bridge_mcp_ghidra.register_tools()

        finally:
            # Restore state
            bridge_mcp_ghidra._tools_registered = original_registered
            bridge_mcp_ghidra._tool_tracker = original_tracker

    @patch('bridge_mcp_ghidra.ToolTracker')
    def test_tracker_initialization_in_main(self, mock_tracker_class):
        """Test that tracker is initialized with enabled tools."""
        import tempfile
        import os

        # Create a mock tracker instance
        mock_tracker = Mock()
        mock_tracker_class.return_value = mock_tracker

        # Save original state
        original_tracker = bridge_mcp_ghidra._tool_tracker
        original_enabled = bridge_mcp_ghidra._enabled_tools
        original_registered = bridge_mcp_ghidra._tools_registered

        try:
            # Reset state
            bridge_mcp_ghidra._tool_tracker = None
            bridge_mcp_ghidra._enabled_tools = None
            bridge_mcp_ghidra._tools_registered = False

            # Get all tools from registry
            all_tools = set(bridge_mcp_ghidra._tool_registry.keys())

            # Simulate tracker initialization from main()
            enabled_tools = bridge_mcp_ghidra._enabled_tools if bridge_mcp_ghidra._enabled_tools is not None else set(bridge_mcp_ghidra._tool_registry.keys())
            bridge_mcp_ghidra._tool_tracker = mock_tracker_class(list(enabled_tools))

            # Verify tracker was initialized with tool list
            mock_tracker_class.assert_called_once()
            call_args = mock_tracker_class.call_args[0]
            assert isinstance(call_args[0], list), "Should be called with a list of tools"
            assert len(call_args[0]) > 0, "Should have at least one tool"

        finally:
            # Restore state
            bridge_mcp_ghidra._tool_tracker = original_tracker
            bridge_mcp_ghidra._enabled_tools = original_enabled
            bridge_mcp_ghidra._tools_registered = original_registered

    def test_tool_wrapper_preserves_metadata(self):
        """Test that the tracking wrapper preserves function metadata."""
        # Create a mock tool function
        def sample_tool(param1: str, param2: int = 10) -> str:
            """Sample tool documentation."""
            return f"Result: {param1}, {param2}"

        # Create the wrapper using the same logic as register_tools
        mock_tracker = Mock()

        def create_tracked_wrapper(name, func):
            def tracked_tool(*args, **kwargs):
                mock_tracker.increment(name)
                return func(*args, **kwargs)
            tracked_tool.__name__ = func.__name__
            tracked_tool.__doc__ = func.__doc__
            tracked_tool.__annotations__ = func.__annotations__
            return tracked_tool

        wrapped = create_tracked_wrapper("sample_tool", sample_tool)

        # Test that metadata is preserved
        assert wrapped.__name__ == "sample_tool"
        assert wrapped.__doc__ == "Sample tool documentation."
        assert wrapped.__annotations__ == sample_tool.__annotations__

        # Test that the wrapper calls the tracker
        result = wrapped("test", 20)
        assert result == "Result: test, 20"
        mock_tracker.increment.assert_called_once_with("sample_tool")
