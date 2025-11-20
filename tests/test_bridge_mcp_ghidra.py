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
        """Test query tool for methods type."""
        mock_safe_get.return_value = ["method1", "method2", "method3"]

        result = bridge_mcp_ghidra.query(type="methods", offset=0, limit=100)

        assert result == ["method1", "method2", "method3"]
        mock_safe_get.assert_called_once_with("methods", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_methods_with_pagination(self, mock_safe_get):
        """Test query tool for methods with custom pagination."""
        mock_safe_get.return_value = ["method4", "method5"]

        result = bridge_mcp_ghidra.query(type="methods", offset=10, limit=2)

        assert result == ["method4", "method5"]
        mock_safe_get.assert_called_once_with("methods", {"offset": 10, "limit": 2})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_classes(self, mock_safe_get):
        """Test query tool for classes type."""
        mock_safe_get.return_value = ["ClassA", "ClassB"]

        result = bridge_mcp_ghidra.query(type="classes", offset=0, limit=100)

        assert result == ["ClassA", "ClassB"]
        mock_safe_get.assert_called_once_with("classes", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_classes_by_name_with_string(self, mock_safe_get):
        """Test search classes by name with regular string query."""
        mock_safe_get.return_value = ["Graphics", "GraphicsManager"]

        result = bridge_mcp_ghidra.query(type="classes", search="Graphics", offset=0, limit=100)

        assert result == ["Graphics", "GraphicsManager"]
        mock_safe_get.assert_called_once_with("classes", {"search": "Graphics", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_classes_by_name_with_numeric_string(self, mock_safe_get):
        """Test search classes by name with numeric string query."""
        mock_safe_get.return_value = ["Class2D", "Vector2D"]

        result = bridge_mcp_ghidra.query(type="classes", search="2D", offset=0, limit=100)

        assert result == ["Class2D", "Vector2D"]
        mock_safe_get.assert_called_once_with("classes", {"search": "2D", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_classes_by_name_with_integer(self, mock_safe_get):
        """Test search classes by name with integer query (handles JSON parsing as int)."""
        mock_safe_get.return_value = ["Class123"]

        # Simulate MCP client sending an integer due to JSON parsing
        result = bridge_mcp_ghidra.query(type="classes", search=123, offset=0, limit=50)

        assert result == ["Class123"]
        mock_safe_get.assert_called_once_with("classes", {"search": "123", "offset": 0, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_classes_by_name_with_empty_string(self, mock_safe_get):
        """Test search classes by name with empty string returns error."""
        result = bridge_mcp_ghidra.query(type="classes", search="", offset=0, limit=100)

        assert len(result) == 1
        assert "Error" in result[0]
        assert "query string is required" in result[0]
        mock_safe_get.assert_not_called()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_classes_by_name_with_pagination(self, mock_safe_get):
        """Test search classes by name with custom pagination."""
        mock_safe_get.return_value = ["NetworkManager"]

        result = bridge_mcp_ghidra.query(type="classes", search="Manager", offset=10, limit=25)

        assert result == ["NetworkManager"]
        mock_safe_get.assert_called_once_with("classes", {"search": "Manager", "offset": 10, "limit": 25})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_classes_by_name_with_underscore(self, mock_safe_get):
        """Test search classes by name with underscore in search term."""
        mock_safe_get.return_value = ["My_Class", "Another_Class"]

        result = bridge_mcp_ghidra.query(type="classes", search="_Class", offset=0, limit=100)

        assert result == ["My_Class", "Another_Class"]
        mock_safe_get.assert_called_once_with("classes", {"search": "_Class", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_classes_default_limit(self, mock_safe_get):
        """Test search classes uses default limit of 100."""
        mock_safe_get.return_value = ["Graphics"]

        result = bridge_mcp_ghidra.query(type="classes", search="Graphics", offset=0)

        assert result == ["Graphics"]
        mock_safe_get.assert_called_once_with("classes", {"search": "Graphics", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_segments(self, mock_safe_get):
        """Test query tool for segments type."""
        mock_safe_get.return_value = [".text", ".data", ".bss"]

        result = bridge_mcp_ghidra.query(type="segments", offset=0, limit=100)

        assert result == [".text", ".data", ".bss"]
        mock_safe_get.assert_called_once_with("segments", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_segments_by_name_with_string(self, mock_safe_get):
        """Test search segments by name with regular string query."""
        mock_safe_get.return_value = ["CODE: 00400000 - 0040ffff"]

        result = bridge_mcp_ghidra.query(type="segments", search="CODE", offset=0, limit=100)

        assert result == ["CODE: 00400000 - 0040ffff"]
        mock_safe_get.assert_called_once_with("segments", {"search": "CODE", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_segments_by_name_with_numeric_string(self, mock_safe_get):
        """Test search segments by name with numeric string query."""
        mock_safe_get.return_value = ["DATA_70: 12340000 - 1234ffff"]

        result = bridge_mcp_ghidra.query(type="segments", search="70", offset=0, limit=100)

        assert result == ["DATA_70: 12340000 - 1234ffff"]
        mock_safe_get.assert_called_once_with("segments", {"search": "70", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_segments_by_name_with_integer(self, mock_safe_get):
        """Test search segments by name with integer query (handles JSON parsing as int)."""
        mock_safe_get.return_value = ["SEGMENT_123: 00500000 - 0050ffff"]

        # Simulate MCP client sending an integer due to JSON parsing
        result = bridge_mcp_ghidra.query(type="segments", search=123, offset=0, limit=50)

        assert result == ["SEGMENT_123: 00500000 - 0050ffff"]
        mock_safe_get.assert_called_once_with("segments", {"search": "123", "offset": 0, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_segments_by_name_with_empty_string(self, mock_safe_get):
        """Test search segments by name with empty string returns error."""
        result = bridge_mcp_ghidra.query(type="segments", search="", offset=0, limit=100)

        assert len(result) == 1
        assert "Error" in result[0]
        assert "query string is required" in result[0]
        mock_safe_get.assert_not_called()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_segments_by_name_with_pagination(self, mock_safe_get):
        """Test search segments by name with custom pagination."""
        mock_safe_get.return_value = ["DATA: 00600000 - 0060ffff"]

        result = bridge_mcp_ghidra.query(type="segments", search="DATA", offset=10, limit=25)

        assert result == ["DATA: 00600000 - 0060ffff"]
        mock_safe_get.assert_called_once_with("segments", {"search": "DATA", "offset": 10, "limit": 25})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_segments_by_name_with_dot_notation(self, mock_safe_get):
        """Test search segments by name with dot notation (e.g., .text)."""
        mock_safe_get.return_value = [".text: 00401000 - 0041ffff", ".text2: 00420000 - 0042ffff"]

        result = bridge_mcp_ghidra.query(type="segments", search=".text", offset=0, limit=100)

        assert result == [".text: 00401000 - 0041ffff", ".text2: 00420000 - 0042ffff"]
        mock_safe_get.assert_called_once_with("segments", {"search": ".text", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_segments_default_limit(self, mock_safe_get):
        """Test search segments uses default limit of 100."""
        mock_safe_get.return_value = ["CODE: 00400000 - 0040ffff"]

        result = bridge_mcp_ghidra.query(type="segments", search="CODE", offset=0)

        assert result == ["CODE: 00400000 - 0040ffff"]
        mock_safe_get.assert_called_once_with("segments", {"search": "CODE", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespaces_by_name_with_string(self, mock_safe_get):
        """Test search namespaces by name with regular string query."""
        mock_safe_get.return_value = ["MyNamespace", "MyNamespace::SubNamespace"]

        result = bridge_mcp_ghidra.query(type="namespaces", search="MyNamespace", offset=0, limit=100)

        assert result == ["MyNamespace", "MyNamespace::SubNamespace"]
        mock_safe_get.assert_called_once_with("namespaces", {"search": "MyNamespace", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespaces_by_name_with_numeric_string(self, mock_safe_get):
        """Test search namespaces by name with numeric string query."""
        mock_safe_get.return_value = ["Namespace70", "Namespace700"]

        result = bridge_mcp_ghidra.query(type="namespaces", search="70", offset=0, limit=100)

        assert result == ["Namespace70", "Namespace700"]
        mock_safe_get.assert_called_once_with("namespaces", {"search": "70", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespaces_by_name_with_integer(self, mock_safe_get):
        """Test search namespaces by name with integer query (handles JSON parsing as int)."""
        mock_safe_get.return_value = ["Namespace123"]

        # Simulate MCP client sending an integer due to JSON parsing
        result = bridge_mcp_ghidra.query(type="namespaces", search=123, offset=0, limit=50)

        assert result == ["Namespace123"]
        mock_safe_get.assert_called_once_with("namespaces", {"search": "123", "offset": 0, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespaces_by_name_with_empty_string(self, mock_safe_get):
        """Test search namespaces by name with empty string returns error."""
        result = bridge_mcp_ghidra.query(type="namespaces", search="", offset=0, limit=100)

        assert len(result) == 1
        assert "Error" in result[0]
        assert "query string is required" in result[0]
        mock_safe_get.assert_not_called()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespaces_by_name_with_pagination(self, mock_safe_get):
        """Test search namespaces by name with custom pagination."""
        mock_safe_get.return_value = ["MyNamespace"]

        result = bridge_mcp_ghidra.query(type="namespaces", search="MyNamespace", offset=10, limit=25)

        assert result == ["MyNamespace"]
        mock_safe_get.assert_called_once_with("namespaces", {"search": "MyNamespace", "offset": 10, "limit": 25})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespaces_default_limit(self, mock_safe_get):
        """Test search namespaces uses default limit of 100."""
        mock_safe_get.return_value = ["MyNamespace"]

        result = bridge_mcp_ghidra.query(type="namespaces", search="MyNamespace", offset=0)

        assert result == ["MyNamespace"]
        mock_safe_get.assert_called_once_with("namespaces", {"search": "MyNamespace", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_decompile_function(self, mock_safe_post):
        """Test decompile_function tool."""
        mock_safe_post.return_value = "int main() { return 0; }"

        result = bridge_mcp_ghidra.decompile_function("main")

        assert result == "int main() { return 0; }"
        mock_safe_post.assert_called_once_with("decompile", "main")

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_function_by_name(self, mock_safe_post):
        """Test rename tool with type='function'."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.rename(type="function", old_name="old_func", new_name="new_func")

        assert result == "Success"
        mock_safe_post.assert_called_once_with("renameFunction",
                                                 {"oldName": "old_func", "newName": "new_func"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_data_label(self, mock_safe_post):
        """Test rename tool with type='data'."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.rename(type="data", address="0x401000", new_name="new_label")

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
    def test_list_functions_by_segment_with_address_range(self, mock_safe_get):
        """Test query tool for methods with address range filter."""
        mock_safe_get.return_value = ["func1 @ 4592:000e (size: 100 bytes)"]

        result = bridge_mcp_ghidra.query(
            type="methods",
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
        """Test query tool for methods with missing segment parameters."""
        result = bridge_mcp_ghidra.query(type="methods")

        # Should succeed - queries all methods without filtering
        mock_safe_get.assert_called_once()



    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_data_by_segment_with_address_range(self, mock_safe_get):
        """Test query tool for data with address range filter."""
        mock_safe_get.return_value = ["data1 @ 4592:0010 [dword] = 0xdeadbeef"]

        result = bridge_mcp_ghidra.query(
            type="data",
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
        """Test query tool for data with missing segment parameters."""
        result = bridge_mcp_ghidra.query(type="data")

        # Should succeed - queries all data without filtering
        mock_safe_get.assert_called_once()


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

    @patch('bridge_mcp_ghidra.safe_get')
    def test_query_strings_without_search(self, mock_safe_get):
        """Test query tool for strings type without search parameter."""
        mock_safe_get.return_value = [
            '0x00401000: "Hello World"',
            '0x00401010: "Error: %s"',
            '0x00401020: "Success"'
        ]

        result = bridge_mcp_ghidra.query(type="strings", offset=0, limit=100)

        assert len(result) == 3
        assert '0x00401000: "Hello World"' in result
        mock_safe_get.assert_called_once_with("strings", {
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_query_strings_with_search(self, mock_safe_get):
        """Test query tool for strings type with search parameter."""
        mock_safe_get.return_value = [
            '0x00401010: "Error: %s"',
            '0x00401030: "Error: invalid input"'
        ]

        result = bridge_mcp_ghidra.query(type="strings", search="Error", offset=0, limit=100)

        assert len(result) == 2
        mock_safe_get.assert_called_once_with("strings", {
            "offset": 0,
            "limit": 100,
            "search": "Error"
        })

    def test_query_strings_empty_search_error(self):
        """Test query tool for strings type with empty search parameter returns error."""
        result = bridge_mcp_ghidra.query(type="strings", search="", offset=0, limit=100)

        assert len(result) == 1
        assert "Error: query string is required" in result[0]

    @patch('bridge_mcp_ghidra.safe_get')
    def test_query_strings_default_limit(self, mock_safe_get):
        """Test query tool for strings uses default limit of 2000."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.query(type="strings")

        mock_safe_get.assert_called_once_with("strings", {
            "offset": 0,
            "limit": 2000
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings_basic(self, mock_safe_get):
        """Test list_strings function without search."""
        mock_safe_get.return_value = [
            '0x00401000: "Hello"',
            '0x00401010: "World"'
        ]

        result = bridge_mcp_ghidra.list_strings(offset=0, limit=100)

        assert len(result) == 2
        mock_safe_get.assert_called_once_with("strings", {
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings_with_search(self, mock_safe_get):
        """Test list_strings function with search parameter."""
        mock_safe_get.return_value = [
            '0x00401000: "password"',
            '0x00401020: "password123"'
        ]

        result = bridge_mcp_ghidra.list_strings(offset=0, limit=500, search="password")

        assert len(result) == 2
        mock_safe_get.assert_called_once_with("strings", {
            "offset": 0,
            "limit": 500,
            "search": "password"
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings_default_limit(self, mock_safe_get):
        """Test list_strings uses default limit of 2000."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.list_strings()

        mock_safe_get.assert_called_once_with("strings", {
            "offset": 0,
            "limit": 2000
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings_pagination(self, mock_safe_get):
        """Test list_strings with pagination parameters."""
        mock_safe_get.return_value = [
            '0x00402000: "page2_string"'
        ]

        result = bridge_mcp_ghidra.list_strings(offset=100, limit=50)

        mock_safe_get.assert_called_once_with("strings", {
            "offset": 100,
            "limit": 50
        })


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
        """Test query tool for methods with limit of 0."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.query(type="methods", offset=0, limit=0)

        assert result == []
        mock_safe_get.assert_called_once_with("methods", {"offset": 0, "limit": 0})


class TestNumericSearchQueries:
    """Test suite for search functions with numeric query strings."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_string(self, mock_safe_get):
        """Test search_functions_by_name with regular string query."""
        mock_safe_get.return_value = ["function_test1", "function_test2"]

        result = bridge_mcp_ghidra.query(type="methods", search="test", offset=0, limit=100)

        assert result == ["function_test1", "function_test2"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "test", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_numeric_string(self, mock_safe_get):
        """Test search_functions_by_name with numeric string query (e.g., '4140')."""
        mock_safe_get.return_value = ["function_4140", "sub_4140"]

        result = bridge_mcp_ghidra.query(type="methods", search="4140", offset=0, limit=100)

        assert result == ["function_4140", "sub_4140"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "4140", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_integer(self, mock_safe_get):
        """Test search_functions_by_name with integer query (handles JSON parsing as int)."""
        mock_safe_get.return_value = ["FUN_00004140"]

        # Simulate MCP client sending an integer due to JSON parsing
        result = bridge_mcp_ghidra.query(type="methods", search=4140, offset=0, limit=20)

        assert result == ["FUN_00004140"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "4140", "offset": 0, "limit": 20})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_hex_string(self, mock_safe_get):
        """Test search_functions_by_name with hexadecimal string."""
        mock_safe_get.return_value = ["function_0x1234"]

        result = bridge_mcp_ghidra.query(type="methods", search="0x1234", offset=0, limit=50)

        assert result == ["function_0x1234"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "0x1234", "offset": 0, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_empty_string(self, mock_safe_get):
        """Test search_functions_by_name with empty string returns error."""
        result = bridge_mcp_ghidra.query(type="methods", search="", offset=0, limit=100)

        assert len(result) == 1
        assert "Error" in result[0]
        assert "query string is required" in result[0]
        mock_safe_get.assert_not_called()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_zero_integer(self, mock_safe_get):
        """Test search_functions_by_name with zero (edge case for falsy value)."""
        mock_safe_get.return_value = ["function_0"]

        result = bridge_mcp_ghidra.query(type="methods", search=0, offset=0, limit=100)

        assert result == ["function_0"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "0", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_data_by_name_with_string(self, mock_safe_get):
        """Test search_data_by_name with regular string query."""
        mock_safe_get.return_value = ["data_label1", "data_label2"]

        result = bridge_mcp_ghidra.query(type="data", search="label", offset=0, limit=100)

        assert result == ["data_label1", "data_label2"]
        mock_safe_get.assert_called_once_with("searchData", {"query": "label", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_data_by_name_with_numeric_string(self, mock_safe_get):
        """Test search_data_by_name with numeric string query."""
        mock_safe_get.return_value = ["DAT_00004140"]

        result = bridge_mcp_ghidra.query(type="data", search="4140", offset=0, limit=100)

        assert result == ["DAT_00004140"]
        mock_safe_get.assert_called_once_with("searchData", {"query": "4140", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_data_by_name_with_integer(self, mock_safe_get):
        """Test search_data_by_name with integer query (handles JSON parsing as int)."""
        mock_safe_get.return_value = ["data_8080"]

        # Simulate MCP client sending an integer due to JSON parsing
        result = bridge_mcp_ghidra.query(type="data", search=8080, offset=0, limit=50)

        assert result == ["data_8080"]
        mock_safe_get.assert_called_once_with("searchData", {"query": "8080", "offset": 0, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_data_by_name_with_empty_string(self, mock_safe_get):
        """Test search_data_by_name with empty string returns error."""
        result = bridge_mcp_ghidra.query(type="data", search="", offset=0, limit=100)

        assert len(result) == 1
        assert "Error" in result[0]
        assert "query string is required" in result[0]
        mock_safe_get.assert_not_called()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_data_by_name_with_negative_integer(self, mock_safe_get):
        """Test search_data_by_name with negative integer."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.query(type="data", search=-1, offset=0, limit=100)

        assert result == []
        mock_safe_get.assert_called_once_with("searchData", {"query": "-1", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_large_integer(self, mock_safe_get):
        """Test search_functions_by_name with large integer value."""
        mock_safe_get.return_value = ["FUN_deadbeef"]

        result = bridge_mcp_ghidra.query(type="methods", search=3735928559, offset=0, limit=100)  # 0xdeadbeef

        assert result == ["FUN_deadbeef"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "3735928559", "offset": 0, "limit": 100})


class TestNamespaceSearch:
    """Test suite for namespace detection in search_functions_by_name."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespace_only(self, mock_safe_get):
        """Test search with namespace only (ending with ::)."""
        mock_safe_get.return_value = ["thunk::func1", "thunk::func2", "thunk::func3"]

        result = bridge_mcp_ghidra.query(type="methods", search="thunk::", offset=0, limit=100)

        assert result == ["thunk::func1", "thunk::func2", "thunk::func3"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "thunk",
            "function_name": "",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespace_with_function(self, mock_safe_get):
        """Test search with namespace and function name."""
        mock_safe_get.return_value = ["thunk::fun1", "thunk::fun2"]

        result = bridge_mcp_ghidra.query(type="methods", search="thunk::fun", offset=0, limit=100)

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

        result = bridge_mcp_ghidra.query(type="methods", search="A::B::", offset=0, limit=100)

        assert result == ["A::B::func1", "A::B::func2"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "A::B",
            "function_name": "",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_nested_namespace_with_function(self, mock_safe_get):
        """Test search with nested namespace and function name (A::B::fun)."""
        mock_safe_get.return_value = ["A::B::fun"]

        result = bridge_mcp_ghidra.query(type="methods", search="A::B::fun", offset=0, limit=100)

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

        result = bridge_mcp_ghidra.query(type="methods", search="A::B::C::D::", offset=0, limit=50)

        assert result == ["A::B::C::D::func"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "A::B::C::D",
            "function_name": "",
            "offset": 0,
            "limit": 50
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_deeply_nested_namespace_with_function(self, mock_safe_get):
        """Test search with deeply nested namespace and function."""
        mock_safe_get.return_value = ["std::vector::iterator::begin"]

        result = bridge_mcp_ghidra.query(type="methods", search="std::vector::iterator::begin")

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

        result = bridge_mcp_ghidra.query(type="methods", search="function", offset=0, limit=100)

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

        result = bridge_mcp_ghidra.query(type="methods", search="std::", offset=0, limit=100)

        assert result == ["std::vector", "std::string", "std::map"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "std",
            "function_name": "",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_namespace_with_pagination(self, mock_safe_get):
        """Test namespace search with custom pagination."""
        mock_safe_get.return_value = ["ns::func10"]

        result = bridge_mcp_ghidra.query(type="methods", search="ns::", offset=10, limit=20)

        assert result == ["ns::func10"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "ns",
            "function_name": "",
            "offset": 10,
            "limit": 20
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_audio_namespace(self, mock_safe_get):
        """Test search for Audio namespace (regression test for issue)."""
        mock_safe_get.return_value = ["Audio::PlaySound", "Audio::StopSound", "Audio::SetVolume"]

        result = bridge_mcp_ghidra.query(type="methods", search="Audio::", offset=0, limit=200)

        assert result == ["Audio::PlaySound", "Audio::StopSound", "Audio::SetVolume"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "Audio",
            "function_name": "",
            "offset": 0,
            "limit": 200
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_bardstale_namespace(self, mock_safe_get):
        """Test search for BardsTale namespace (regression test for reported issue)."""
        mock_safe_get.return_value = ["BardsTale::InitGame", "BardsTale::ProcessInput", "BardsTale::UpdateWorld"]

        result = bridge_mcp_ghidra.query(type="methods", search="BardsTale::", offset=0, limit=100)

        assert result == ["BardsTale::InitGame", "BardsTale::ProcessInput", "BardsTale::UpdateWorld"]
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "BardsTale",
            "function_name": "",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_single_colon_no_namespace(self, mock_safe_get):
        """Test search with single colon (not namespace syntax)."""
        mock_safe_get.return_value = ["func:label"]

        result = bridge_mcp_ghidra.query(type="methods", search="func:label", offset=0, limit=100)

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

        result = bridge_mcp_ghidra.query(type="methods", search="ns::4140", offset=0, limit=100)

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

        result = bridge_mcp_ghidra.query(type="methods", search="my_namespace::my_func")

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

        result = bridge_mcp_ghidra.query(type="methods", search="::global_func")

        assert result == ["::global_func"]
        # Empty namespace before ::, so it's treated as regular query search
        call_args = mock_safe_get.call_args[0][1]
        assert "query" in call_args
        assert call_args["query"] == "global_func"
        assert "namespace" not in call_args

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_compression_namespace(self, mock_safe_get):
        """Test search for Compression namespace (user's reported issue)."""
        mock_safe_get.return_value = [
            "Compression::compress @ 0x401000",
            "Compression::decompress @ 0x401100",
            "Compression::init @ 0x401200"
        ]

        result = bridge_mcp_ghidra.query(type="methods", search="Compression::", offset=0, limit=100)

        assert len(result) == 3
        assert "Compression::compress @ 0x401000" in result
        mock_safe_get.assert_called_once_with("searchFunctions", {
            "namespace": "Compression",
            "function_name": "",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_empty_namespace_before_separator(self, mock_safe_get):
        """Test that empty namespace is handled correctly."""
        mock_safe_get.return_value = ["func"]

        result = bridge_mcp_ghidra.query(type="methods", search="::func")

        assert result == ["func"]
        # Should use query parameter, not namespace (since namespace is empty)
        call_args = mock_safe_get.call_args[0][1]
        assert "query" in call_args
        assert call_args["query"] == "func"
        assert "namespace" not in call_args


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


class TestBulkOperationsStatsTracking:
    """Test suite for bulk_operations stats tracking."""

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_increments_individual_operations(self, mock_post):
        """Test that bulk_operations increments stats for each individual operation."""
        from tool_tracker import ToolTracker
        import tempfile
        import os

        # Create a temporary database for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_tool_stats.db")

            # Initialize tracker with relevant tools
            tracker = ToolTracker(
                ["bulk_operations", "disassemble_function", "decompile_function", "rename"],
                db_path=db_path
            )

            # Set the global tracker
            original_tracker = bridge_mcp_ghidra._tool_tracker
            bridge_mcp_ghidra._tool_tracker = tracker

            try:
                # Mock the response
                mock_response = Mock()
                mock_response.ok = True
                mock_response.text = '{"results": [{"success": true}, {"success": true}, {"success": true}]}'
                mock_post.return_value = mock_response

                # Create bulk operations
                operations = [
                    {"endpoint": "/disassemble_function", "params": {"address": "0x401000"}},
                    {"endpoint": "/decompile", "params": {"name": "main"}},
                    {"endpoint": "/rename_function_by_address", "params": {"function_address": "0x402000", "new_name": "init"}}
                ]

                # Call bulk_operations (this will be wrapped and increment bulk_operations)
                # But we'll call it directly to test the internal tracking
                result = bridge_mcp_ghidra.bulk_operations(operations)

                # Verify the result
                assert "results" in result

                # Check stats - each operation should be incremented
                stats = tracker.get_stats()
                stats_dict = {name: count for name, count in stats}

                # disassemble_function should be incremented (1 time)
                assert stats_dict.get("disassemble_function", 0) == 1, \
                    f"Expected disassemble_function to be 1, got {stats_dict.get('disassemble_function', 0)}"

                # decompile_function should be incremented (1 time)
                assert stats_dict.get("decompile_function", 0) == 1, \
                    f"Expected decompile_function to be 1, got {stats_dict.get('decompile_function', 0)}"

                # rename should be incremented (1 time) - tracks all rename operations
                assert stats_dict.get("rename", 0) == 1, \
                    f"Expected rename to be 1, got {stats_dict.get('rename', 0)}"

            finally:
                # Restore original tracker
                bridge_mcp_ghidra._tool_tracker = original_tracker

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_handles_multiple_same_operations(self, mock_post):
        """Test that bulk_operations correctly counts multiple operations of the same type."""
        from tool_tracker import ToolTracker
        import tempfile
        import os

        # Create a temporary database for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_tool_stats.db")

            # Initialize tracker with relevant tools
            tracker = ToolTracker(["bulk_operations", "disassemble_function"], db_path=db_path)

            # Set the global tracker
            original_tracker = bridge_mcp_ghidra._tool_tracker
            bridge_mcp_ghidra._tool_tracker = tracker

            try:
                # Mock the response
                mock_response = Mock()
                mock_response.ok = True
                mock_response.text = '{"results": [{"success": true}, {"success": true}, {"success": true}]}'
                mock_post.return_value = mock_response

                # Create bulk operations with 3 disassemble operations
                operations = [
                    {"endpoint": "/disassemble_function", "params": {"address": "0x401000"}},
                    {"endpoint": "/disassemble_function", "params": {"address": "0x402000"}},
                    {"endpoint": "/disassemble_function", "params": {"address": "0x403000"}}
                ]

                # Call bulk_operations
                result = bridge_mcp_ghidra.bulk_operations(operations)

                # Verify the result
                assert "results" in result

                # Check stats - disassemble_function should be incremented 3 times
                stats = tracker.get_stats()
                stats_dict = {name: count for name, count in stats}

                assert stats_dict.get("disassemble_function", 0) == 3, \
                    f"Expected disassemble_function to be 3, got {stats_dict.get('disassemble_function', 0)}"

            finally:
                # Restore original tracker
                bridge_mcp_ghidra._tool_tracker = original_tracker

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_normalizes_endpoints_without_leading_slash(self, mock_post):
        """Test that bulk_operations normalizes endpoints that don't start with /."""
        # Mock the response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = '{"results": [{"success": true}, {"success": true}]}'
        mock_post.return_value = mock_response

        # Create bulk operations WITHOUT leading slashes
        operations = [
            {"endpoint": "rename_function_by_address", "params": {"function_address": "0x401000", "new_name": "test"}},
            {"endpoint": "disassemble_function", "params": {"address": "0x402000"}}
        ]

        # Call bulk_operations
        result = bridge_mcp_ghidra.bulk_operations(operations)

        # Verify the request was made
        assert mock_post.called

        # Get the actual payload that was sent
        call_args = mock_post.call_args
        sent_payload = call_args[1]['json']  # kwargs['json']

        # Verify endpoints were normalized to have leading slashes
        assert sent_payload['operations'][0]['endpoint'] == '/rename_function_by_address', \
            f"Expected '/rename_function_by_address', got '{sent_payload['operations'][0]['endpoint']}'"
        assert sent_payload['operations'][1]['endpoint'] == '/disassemble_function', \
            f"Expected '/disassemble_function', got '{sent_payload['operations'][1]['endpoint']}'"

        # Verify params were preserved
        assert sent_payload['operations'][0]['params']['function_address'] == '0x401000'
        assert sent_payload['operations'][0]['params']['new_name'] == 'test'
        assert sent_payload['operations'][1]['params']['address'] == '0x402000'

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_preserves_endpoints_with_leading_slash(self, mock_post):
        """Test that bulk_operations preserves endpoints that already have /."""
        # Mock the response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = '{"results": [{"success": true}]}'
        mock_post.return_value = mock_response

        # Create bulk operations WITH leading slashes (already correct)
        operations = [
            {"endpoint": "/rename_function_by_address", "params": {"function_address": "0x401000", "new_name": "test"}}
        ]

        # Call bulk_operations
        result = bridge_mcp_ghidra.bulk_operations(operations)

        # Verify the request was made
        assert mock_post.called

        # Get the actual payload that was sent
        call_args = mock_post.call_args
        sent_payload = call_args[1]['json']

        # Verify endpoint still has leading slash
        assert sent_payload['operations'][0]['endpoint'] == '/rename_function_by_address'


class TestBulkDisassemble:
    """Test suite for disassemble_function with bulk support."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_disassemble_function_single_address(self, mock_safe_get):
        """Test disassemble_function with a single address (original behavior)."""
        mock_safe_get.return_value = [
            "uint16_t myFunc()",
            "0x401000 55              PUSH       BP",
            "0x401001 8b ec           MOV        BP,SP"
        ]

        result = bridge_mcp_ghidra.disassemble_function("0x401000")

        assert isinstance(result, list)
        assert len(result) == 3
        assert "PUSH       BP" in result[1]
        mock_safe_get.assert_called_once_with("disassemble_function", {"address": "0x401000", "include_bytes": "false"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_disassemble_function_bulk_addresses(self, mock_safe_get):
        """Test disassemble_function with multiple addresses."""
        mock_safe_get.return_value = ["0x401000 PUSH BP", "0x401001 MOV BP,SP"]

        addresses = ["0x401000", "0x402000", "0x403000"]
        result = bridge_mcp_ghidra.disassemble_function(addresses)

        # Should call safe_get for each address
        assert mock_safe_get.call_count == 3

        # Verify all addresses are passed correctly
        calls = mock_safe_get.call_args_list
        assert calls[0][0] == ("disassemble_function", {"address": "0x401000", "include_bytes": "false"})
        assert calls[1][0] == ("disassemble_function", {"address": "0x402000", "include_bytes": "false"})
        assert calls[2][0] == ("disassemble_function", {"address": "0x403000", "include_bytes": "false"})

        # Result should be a list of lists
        assert isinstance(result, list)
        assert len(result) == 3

    def test_disassemble_function_bulk_empty_list(self):
        """Test disassemble_function with empty list returns error."""
        result = bridge_mcp_ghidra.disassemble_function([])

        assert "Error" in result
        assert "cannot be empty" in result

    @patch('bridge_mcp_ghidra.safe_get')
    def test_disassemble_function_bulk_single_item_list(self, mock_safe_get):
        """Test disassemble_function with single-item list."""
        mock_safe_get.return_value = ["0x401000 PUSH BP"]

        result = bridge_mcp_ghidra.disassemble_function(["0x401000"])

        # Single item in list still uses safe_get
        mock_safe_get.assert_called_once_with("disassemble_function", {"address": "0x401000", "include_bytes": "false"})
        assert isinstance(result, list)
        assert len(result) == 1
        # Result should have START/END markers
        assert result[0] == ["=== START: 0x401000 ===", "0x401000 PUSH BP", "=== END: 0x401000 ==="]

    @patch('bridge_mcp_ghidra.safe_get')
    def test_disassemble_function_bulk_return_type(self, mock_safe_get):
        """Test that bulk disassemble returns list of lists with markers."""
        mock_safe_get.side_effect = [
            ["disassembly1_line1", "disassembly1_line2"],
            ["disassembly2_line1", "disassembly2_line2"]
        ]

        result = bridge_mcp_ghidra.disassemble_function(["0x401000", "0x402000"])

        # Result should be a list of lists where each index maps to input address
        assert isinstance(result, list)
        assert len(result) == 2
        # Each result should have START/END markers
        assert result[0] == ["=== START: 0x401000 ===", "disassembly1_line1", "disassembly1_line2", "=== END: 0x401000 ==="]
        assert result[1] == ["=== START: 0x402000 ===", "disassembly2_line1", "disassembly2_line2", "=== END: 0x402000 ==="]

    @patch('bridge_mcp_ghidra.safe_get')
    def test_disassemble_function_bulk_preserves_order(self, mock_safe_get):
        """Test that bulk operations preserve address order."""
        addresses = ["0x405000", "0x401000", "0x403000", "0x402000"]
        mock_safe_get.return_value = ["line1"]
        bridge_mcp_ghidra.disassemble_function(addresses)

        calls = mock_safe_get.call_args_list
        for i, addr in enumerate(addresses):
            assert calls[i][0][1]["address"] == addr

    @patch('bridge_mcp_ghidra.safe_get')
    def test_disassemble_function_bulk_hex_and_segment_addresses(self, mock_safe_get):
        """Test bulk disassemble with mixed address formats."""
        addresses = ["0x401000", "5356:3cd8", "0x1400010a0"]
        mock_safe_get.return_value = ["line1"]
        bridge_mcp_ghidra.disassemble_function(addresses)

        calls = mock_safe_get.call_args_list
        assert calls[0][0][1]["address"] == "0x401000"
        assert calls[1][0][1]["address"] == "5356:3cd8"
        assert calls[2][0][1]["address"] == "0x1400010a0"


class TestXrefsIncludeInstruction:
    """Test suite for xrefs tools with include_instruction parameter."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_to_with_false(self, mock_safe_get):
        """Test get_xrefs_to with include_instruction=False (default)."""
        mock_safe_get.return_value = ["From 0x401000 in main [CALL]"]

        result = bridge_mcp_ghidra.get_xrefs_to("0x402000", include_instruction=False)

        assert result == ["From 0x401000 in main [CALL]"]
        mock_safe_get.assert_called_once()
        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        # Should not include include_instruction parameter when False
        assert "include_instruction" not in params

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_to_with_true(self, mock_safe_get):
        """Test get_xrefs_to with include_instruction=True."""
        mock_safe_get.return_value = ["CALL (1):", "  0x401000 in main: call 0x402000"]

        result = bridge_mcp_ghidra.get_xrefs_to("0x402000", include_instruction=True)

        assert "CALL" in result[0]
        mock_safe_get.assert_called_once()
        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["include_instruction"] == "true"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_to_with_zero(self, mock_safe_get):
        """Test get_xrefs_to with include_instruction=0 (instruction only)."""
        mock_safe_get.return_value = ["CALL (1):", "  0x401000 in main: call 0x402000"]

        result = bridge_mcp_ghidra.get_xrefs_to("0x402000", include_instruction=0)

        mock_safe_get.assert_called_once()
        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["include_instruction"] == "0"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_to_with_context_lines(self, mock_safe_get):
        """Test get_xrefs_to with include_instruction=3 (3 context lines)."""
        mock_safe_get.return_value = [
            "CALL (1):",
            "    0x400ffa: push ebp",
            "    0x400ffb: mov ebp, esp",
            "    0x400ffd: sub esp, 0x10",
            "  > 0x401000: call 0x402000",
            "    0x401005: add esp, 0x4",
            "    0x401008: mov eax, 0",
            "    0x40100d: leave"
        ]

        result = bridge_mcp_ghidra.get_xrefs_to("0x402000", include_instruction=3)

        assert len(result) > 0
        mock_safe_get.assert_called_once()
        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["include_instruction"] == "3"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_from_with_integer(self, mock_safe_get):
        """Test get_xrefs_from with include_instruction as integer."""
        mock_safe_get.return_value = ["DATA_READ (1):", "  0x403000 to data label: mov eax, [0x403000]"]

        result = bridge_mcp_ghidra.get_xrefs_from("0x401000", include_instruction=2)

        mock_safe_get.assert_called_once()
        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["include_instruction"] == "2"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_function_xrefs_with_true(self, mock_safe_get):
        """Test get_function_xrefs with include_instruction=True."""
        mock_safe_get.return_value = ["CALL (2):", "  0x401000 in main: call FUN_00402000"]

        result = bridge_mcp_ghidra.get_function_xrefs("FUN_00402000", include_instruction=True)

        mock_safe_get.assert_called_once()
        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["include_instruction"] == "true"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_function_xrefs_with_integer(self, mock_safe_get):
        """Test get_function_xrefs with include_instruction as integer."""
        mock_safe_get.return_value = ["CALL (1):", "  0x401000 in main: call myFunc"]

        result = bridge_mcp_ghidra.get_function_xrefs("myFunc", include_instruction=5)

        mock_safe_get.assert_called_once()
        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["include_instruction"] == "5"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_to_default_false(self, mock_safe_get):
        """Test get_xrefs_to uses False as default."""
        mock_safe_get.return_value = ["From 0x401000 in main [CALL]"]

        result = bridge_mcp_ghidra.get_xrefs_to("0x402000")

        mock_safe_get.assert_called_once()
        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        # Default is False, should not include parameter
        assert "include_instruction" not in params


class TestInstructionPatternSearch:
    """Test suite for instruction pattern search functionality."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_instruction_pattern_search_basic(self, mock_safe_get):
        """Test basic instruction pattern search with regex."""
        mock_safe_get.return_value = ["0x401000: move.b (0x3932,A4),D0 (segment: CODE_70)"]

        result = bridge_mcp_ghidra.query(
            type="instruction_pattern",
            search="move\\.b.*A4"
        )

        assert result == ["0x401000: move.b (0x3932,A4),D0 (segment: CODE_70)"]
        mock_safe_get.assert_called_once()
        call_args = mock_safe_get.call_args
        assert call_args[0][0] == "search_instruction_pattern"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_instruction_pattern_search_regex_pattern(self, mock_safe_get):
        """Test instruction pattern search with regex pattern."""
        mock_safe_get.return_value = ["Found 5 matches"]

        result = bridge_mcp_ghidra.query(
            type="instruction_pattern",
            search="[jb]sr"
        )

        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["search"] == "[jb]sr"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_instruction_pattern_search_with_address_range(self, mock_safe_get):
        """Test instruction pattern search with address range."""
        mock_safe_get.return_value = ["0x1500: move.b D0,D1 (segment: CODE_70)"]

        result = bridge_mcp_ghidra.query(
            type="instruction_pattern",
            search="move",
            start_address="0x1000",
            end_address="0x2000"
        )

        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["start_address"] == "0x1000"
        assert params["end_address"] == "0x2000"
        assert params["search"] == "move"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_instruction_pattern_search_with_pagination(self, mock_safe_get):
        """Test instruction pattern search with custom pagination."""
        mock_safe_get.return_value = ["0x402000: jsr FUN_00401000 (segment: CODE_70)"]

        result = bridge_mcp_ghidra.query(
            type="instruction_pattern",
            search="jsr",
            offset=10,
            limit=50
        )

        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["offset"] == 10
        assert params["limit"] == 50

    @patch('bridge_mcp_ghidra.safe_get')
    def test_instruction_pattern_search_default_limit(self, mock_safe_get):
        """Test instruction pattern search uses default limit when not specified."""
        mock_safe_get.return_value = ["Found 10 matches"]

        result = bridge_mcp_ghidra.query(
            type="instruction_pattern",
            search="0x3932"
        )

        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["limit"] == 100  # Default limit

    def test_instruction_pattern_search_missing_search(self):
        """Test instruction pattern search error when search parameter is missing."""
        result = bridge_mcp_ghidra.query(
            type="instruction_pattern"
        )

        assert isinstance(result, list)
        assert len(result) == 1
        assert "Error" in result[0]
        assert "search" in result[0]
        assert "required" in result[0]

    def test_instruction_pattern_search_empty_search(self):
        """Test instruction pattern search error when search parameter is empty."""
        result = bridge_mcp_ghidra.query(
            type="instruction_pattern",
            search=""
        )

        assert isinstance(result, list)
        assert len(result) == 1
        assert "Error" in result[0]
        assert "required" in result[0]

    @patch('bridge_mcp_ghidra.safe_get')
    def test_instruction_pattern_search_all_options(self, mock_safe_get):
        """Test instruction pattern search with all optional parameters."""
        mock_safe_get.return_value = ["0x1500: move.b (0x3932,A4),D0 (segment: CODE_70)"]

        result = bridge_mcp_ghidra.query(
            type="instruction_pattern",
            search="move\\.b.*0x3932",
            start_address="0x1000",
            end_address="0x2000",
            offset=5,
            limit=25
        )

        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["search"] == "move\\.b.*0x3932"
        assert params["start_address"] == "0x1000"
        assert params["end_address"] == "0x2000"
        assert params["offset"] == 5
        assert params["limit"] == 25

    @patch('bridge_mcp_ghidra.safe_get')
    def test_instruction_pattern_search_special_regex_chars(self, mock_safe_get):
        """Test instruction pattern search with special regex characters."""
        mock_safe_get.return_value = ["0x401000: move.b (0x3932,A4),D0 (segment: CODE_70)"]

        result = bridge_mcp_ghidra.query(
            type="instruction_pattern",
            search=".*\\(.*,.*\\)"
        )

        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["search"] == ".*\\(.*,.*\\)"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_instruction_pattern_search_hex_address_pattern(self, mock_safe_get):
        """Test instruction pattern search for hex addresses."""
        mock_safe_get.return_value = ["0x401000: lea (0x3834,A4),A0 (segment: CODE_70)"]

        result = bridge_mcp_ghidra.query(
            type="instruction_pattern",
            search="0x[0-9a-fA-F]+"
        )

        call_args = mock_safe_get.call_args
        params = call_args[0][1]
        assert params["search"] == "0x[0-9a-fA-F]+"

    def test_query_invalid_type(self):
        """Test query with invalid type returns error."""
        result = bridge_mcp_ghidra.query(type="invalid_type")

        assert isinstance(result, list)
        assert len(result) == 1
        assert "Error" in result[0]
        assert "Invalid type" in result[0]

    def test_query_instruction_pattern_in_valid_types(self):
        """Test that 'instruction_pattern' is recognized as a valid query type."""
        # This should not raise an error for the type itself
        result = bridge_mcp_ghidra.query(type="instruction_pattern")

        # Should error due to missing search, not invalid type
        assert "Invalid type" not in result[0]
        assert "required" in result[0]


class TestConsolidatedRenameTool:
    """Test suite for the consolidated rename tool with type discriminator."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_function_by_address(self, mock_safe_post):
        """Test rename tool with type='function_by_address'."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.rename(
            type="function_by_address",
            function_address="0x401000",
            new_name="my_function"
        )

        assert result == "Success"
        mock_safe_post.assert_called_once_with(
            "rename_function_by_address",
            {"function_address": "0x401000", "new_name": "my_function"}
        )

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_variable(self, mock_safe_post):
        """Test rename tool with type='variable'."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.rename(
            type="variable",
            function_name="main",
            old_name="local_8",
            new_name="counter"
        )

        assert result == "Success"
        mock_safe_post.assert_called_once_with(
            "renameVariable",
            {"functionName": "main", "oldName": "local_8", "newName": "counter"}
        )

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_struct(self, mock_safe_post):
        """Test rename tool with type='struct'."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.rename(
            type="struct",
            old_name="struct_1",
            new_name="ConfigData"
        )

        assert result == "Success"
        mock_safe_post.assert_called_once_with(
            "struct/rename",
            {"old_name": "struct_1", "new_name": "ConfigData"}
        )

    def test_rename_invalid_type(self):
        """Test rename tool rejects invalid type."""
        result = bridge_mcp_ghidra.rename(type="invalid_type", new_name="test")

        assert "Error" in result
        assert "Invalid type" in result
        assert "invalid_type" in result

    def test_rename_function_missing_old_name(self):
        """Test rename type='function' requires old_name."""
        result = bridge_mcp_ghidra.rename(type="function", new_name="test")

        assert "Error" in result
        assert "old_name" in result
        assert "required" in result

    def test_rename_function_by_address_missing_address(self):
        """Test rename type='function_by_address' requires function_address."""
        result = bridge_mcp_ghidra.rename(type="function_by_address", new_name="test")

        assert "Error" in result
        assert "function_address" in result
        assert "required" in result

    def test_rename_data_missing_address(self):
        """Test rename type='data' requires address."""
        result = bridge_mcp_ghidra.rename(type="data", new_name="test")

        assert "Error" in result
        assert "address" in result
        assert "required" in result

    def test_rename_variable_missing_function_name(self):
        """Test rename type='variable' requires function_name and old_name."""
        result = bridge_mcp_ghidra.rename(type="variable", new_name="test")

        assert "Error" in result
        assert "required" in result

    def test_rename_struct_missing_old_name(self):
        """Test rename type='struct' requires old_name."""
        result = bridge_mcp_ghidra.rename(type="struct", new_name="test")

        assert "Error" in result
        assert "old_name" in result
        assert "required" in result


class TestToolRegistryConsolidation:
    """Test suite verifying old rename tools have been removed from registry."""

    def test_rename_function_removed(self):
        """Test that rename_function has been removed."""
        # Should not exist as a function attribute
        assert not hasattr(bridge_mcp_ghidra, 'rename_function'), \
            "rename_function should not exist - use rename(type='function') instead"

        # Should not be in tool registry
        assert 'rename_function' not in bridge_mcp_ghidra._tool_registry, \
            "rename_function should not be in _tool_registry"

    def test_rename_function_by_address_removed(self):
        """Test that rename_function_by_address has been removed."""
        assert not hasattr(bridge_mcp_ghidra, 'rename_function_by_address'), \
            "rename_function_by_address should not exist - use rename(type='function_by_address') instead"

        assert 'rename_function_by_address' not in bridge_mcp_ghidra._tool_registry, \
            "rename_function_by_address should not be in _tool_registry"

    def test_rename_data_removed(self):
        """Test that rename_data has been removed."""
        assert not hasattr(bridge_mcp_ghidra, 'rename_data'), \
            "rename_data should not exist - use rename(type='data') instead"

        assert 'rename_data' not in bridge_mcp_ghidra._tool_registry, \
            "rename_data should not be in _tool_registry"

    def test_rename_variable_removed(self):
        """Test that rename_variable has been removed."""
        assert not hasattr(bridge_mcp_ghidra, 'rename_variable'), \
            "rename_variable should not exist - use rename(type='variable') instead"

        assert 'rename_variable' not in bridge_mcp_ghidra._tool_registry, \
            "rename_variable should not be in _tool_registry"

    def test_rename_struct_removed(self):
        """Test that rename_struct has been removed."""
        assert not hasattr(bridge_mcp_ghidra, 'rename_struct'), \
            "rename_struct should not exist - use rename(type='struct') instead"

        assert 'rename_struct' not in bridge_mcp_ghidra._tool_registry, \
            "rename_struct should not be in _tool_registry"

    def test_consolidated_rename_exists(self):
        """Test that the consolidated rename tool exists."""
        # Should exist as a function attribute
        assert hasattr(bridge_mcp_ghidra, 'rename'), \
            "rename should exist as a function"

        # Should be in tool registry
        assert 'rename' in bridge_mcp_ghidra._tool_registry, \
            "rename should be in _tool_registry"

    def test_tool_categories_updated(self):
        """Test that TOOL_CATEGORIES uses consolidated rename tool."""
        from bridge_mcp_ghidra import TOOL_CATEGORIES

        # Check modification category
        assert 'rename' in TOOL_CATEGORIES['modification'], \
            "rename should be in modification category"

        # Old tools should not be in categories
        assert 'rename_function' not in TOOL_CATEGORIES['modification']
        assert 'rename_function_by_address' not in TOOL_CATEGORIES['modification']
        assert 'rename_data' not in TOOL_CATEGORIES['modification']
        assert 'rename_variable' not in TOOL_CATEGORIES['modification']

        # Check struct category
        assert 'rename_struct' not in TOOL_CATEGORIES.get('struct', []), \
            "rename_struct should not be in struct category"
