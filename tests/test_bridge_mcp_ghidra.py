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


class TestImportExportTools:
    """Test suite for import/export listing tools."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_imports_default(self, mock_safe_get):
        """Test list_imports with default parameters."""
        mock_safe_get.return_value = ["printf", "malloc", "free"]

        result = bridge_mcp_ghidra.list_imports()

        assert result == ["printf", "malloc", "free"]
        mock_safe_get.assert_called_once_with("imports", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_imports_with_pagination(self, mock_safe_get):
        """Test list_imports with custom pagination."""
        mock_safe_get.return_value = ["sprintf", "strlen"]

        result = bridge_mcp_ghidra.list_imports(offset=10, limit=50)

        assert result == ["sprintf", "strlen"]
        mock_safe_get.assert_called_once_with("imports", {"offset": 10, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_imports_empty(self, mock_safe_get):
        """Test list_imports when no imports are present."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.list_imports()

        assert result == []

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_exports_default(self, mock_safe_get):
        """Test list_exports with default parameters."""
        mock_safe_get.return_value = ["main", "init", "cleanup"]

        result = bridge_mcp_ghidra.list_exports()

        assert result == ["main", "init", "cleanup"]
        mock_safe_get.assert_called_once_with("exports", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_exports_with_pagination(self, mock_safe_get):
        """Test list_exports with custom pagination."""
        mock_safe_get.return_value = ["helper_func", "utility"]

        result = bridge_mcp_ghidra.list_exports(offset=5, limit=25)

        assert result == ["helper_func", "utility"]
        mock_safe_get.assert_called_once_with("exports", {"offset": 5, "limit": 25})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_exports_error(self, mock_safe_get):
        """Test list_exports when an error occurs."""
        mock_safe_get.return_value = ["Error 500: Internal server error"]

        result = bridge_mcp_ghidra.list_exports()

        assert len(result) == 1
        assert "Error 500" in result[0]


class TestNamespaceAndDataTools:
    """Test suite for namespace and data listing tools."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_namespaces_default(self, mock_safe_get):
        """Test list_namespaces with default parameters."""
        mock_safe_get.return_value = ["MyNamespace", "Utils", "API"]

        result = bridge_mcp_ghidra.list_namespaces()

        assert result == ["MyNamespace", "Utils", "API"]
        mock_safe_get.assert_called_once_with("namespaces", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_namespaces_with_pagination(self, mock_safe_get):
        """Test list_namespaces with custom pagination."""
        mock_safe_get.return_value = ["Internal"]

        result = bridge_mcp_ghidra.list_namespaces(offset=20, limit=10)

        assert result == ["Internal"]
        mock_safe_get.assert_called_once_with("namespaces", {"offset": 20, "limit": 10})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_data_items_default(self, mock_safe_get):
        """Test list_data_items with default parameters."""
        mock_safe_get.return_value = ["DAT_00401000", "STRING_00402000"]

        result = bridge_mcp_ghidra.list_data_items()

        assert result == ["DAT_00401000", "STRING_00402000"]
        mock_safe_get.assert_called_once_with("data", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_data_items_with_pagination(self, mock_safe_get):
        """Test list_data_items with custom pagination."""
        mock_safe_get.return_value = ["DATA_LABEL_1", "DATA_LABEL_2"]

        result = bridge_mcp_ghidra.list_data_items(offset=100, limit=200)

        assert result == ["DATA_LABEL_1", "DATA_LABEL_2"]
        mock_safe_get.assert_called_once_with("data", {"offset": 100, "limit": 200})


class TestSearchTools:
    """Test suite for search and query tools."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_basic(self, mock_safe_get):
        """Test search_functions_by_name with a basic query."""
        mock_safe_get.return_value = ["my_function", "my_function_helper"]

        result = bridge_mcp_ghidra.search_functions_by_name("my_function")

        assert result == ["my_function", "my_function_helper"]
        mock_safe_get.assert_called_once_with("searchFunctions",
                                                {"query": "my_function", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_with_pagination(self, mock_safe_get):
        """Test search_functions_by_name with pagination."""
        mock_safe_get.return_value = ["test_func"]

        result = bridge_mcp_ghidra.search_functions_by_name("test", offset=10, limit=5)

        assert result == ["test_func"]
        mock_safe_get.assert_called_once_with("searchFunctions",
                                                {"query": "test", "offset": 10, "limit": 5})

    def test_search_functions_by_name_empty_query(self):
        """Test search_functions_by_name with empty query returns error."""
        result = bridge_mcp_ghidra.search_functions_by_name("")

        assert result == ["Error: query string is required"]

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_no_results(self, mock_safe_get):
        """Test search_functions_by_name with no matching results."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.search_functions_by_name("nonexistent")

        assert result == []

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_functions(self, mock_safe_get):
        """Test list_functions returns all functions."""
        mock_safe_get.return_value = ["func1", "func2", "func3"]

        result = bridge_mcp_ghidra.list_functions()

        assert result == ["func1", "func2", "func3"]
        mock_safe_get.assert_called_once_with("list_functions")


class TestDecompilationTools:
    """Test suite for decompilation and disassembly tools."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_decompile_function_by_address(self, mock_safe_get):
        """Test decompile_function_by_address with valid address."""
        mock_safe_get.return_value = ["void main() {", "  printf(\"Hello\");", "}"]

        result = bridge_mcp_ghidra.decompile_function_by_address("0x401000")

        assert result == "void main() {\n  printf(\"Hello\");\n}"
        mock_safe_get.assert_called_once_with("decompile_function", {"address": "0x401000"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_decompile_function_by_address_error(self, mock_safe_get):
        """Test decompile_function_by_address with invalid address."""
        mock_safe_get.return_value = ["Error 404: Function not found"]

        result = bridge_mcp_ghidra.decompile_function_by_address("0xFFFFFFFF")

        assert "Error 404" in result

    @patch('bridge_mcp_ghidra.safe_get')
    def test_disassemble_function(self, mock_safe_get):
        """Test disassemble_function with valid address."""
        mock_safe_get.return_value = [
            "0x401000: PUSH RBP",
            "0x401001: MOV RBP, RSP",
            "0x401004: RET"
        ]

        result = bridge_mcp_ghidra.disassemble_function("0x401000")

        assert result == [
            "0x401000: PUSH RBP",
            "0x401001: MOV RBP, RSP",
            "0x401004: RET"
        ]
        mock_safe_get.assert_called_once_with("disassemble_function", {"address": "0x401000"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_disassemble_function_empty(self, mock_safe_get):
        """Test disassemble_function with empty result."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.disassemble_function("0x401000")

        assert result == []


class TestCurrentLocationTools:
    """Test suite for current location retrieval tools."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_current_address(self, mock_safe_get):
        """Test get_current_address returns current address."""
        mock_safe_get.return_value = ["0x401000"]

        result = bridge_mcp_ghidra.get_current_address()

        assert result == "0x401000"
        mock_safe_get.assert_called_once_with("get_current_address")

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_current_address_multiline(self, mock_safe_get):
        """Test get_current_address with multiline response."""
        mock_safe_get.return_value = ["Current address:", "0x401000"]

        result = bridge_mcp_ghidra.get_current_address()

        assert result == "Current address:\n0x401000"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_current_function(self, mock_safe_get):
        """Test get_current_function returns current function."""
        mock_safe_get.return_value = ["main"]

        result = bridge_mcp_ghidra.get_current_function()

        assert result == "main"
        mock_safe_get.assert_called_once_with("get_current_function")

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_current_function_with_details(self, mock_safe_get):
        """Test get_current_function with detailed response."""
        mock_safe_get.return_value = ["Function: main", "Address: 0x401000"]

        result = bridge_mcp_ghidra.get_current_function()

        assert result == "Function: main\nAddress: 0x401000"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_function_by_address(self, mock_safe_get):
        """Test get_function_by_address with valid address."""
        mock_safe_get.return_value = ["Function: helper", "Type: void"]

        result = bridge_mcp_ghidra.get_function_by_address("0x402000")

        assert result == "Function: helper\nType: void"
        mock_safe_get.assert_called_once_with("get_function_by_address", {"address": "0x402000"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_function_by_address_not_found(self, mock_safe_get):
        """Test get_function_by_address when function is not found."""
        mock_safe_get.return_value = ["Error: No function at address"]

        result = bridge_mcp_ghidra.get_function_by_address("0xFFFFFFFF")

        assert "Error" in result


class TestCommentTools:
    """Test suite for comment setting tools."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_decompiler_comment(self, mock_safe_post):
        """Test set_decompiler_comment with valid data."""
        mock_safe_post.return_value = "Comment set successfully"

        result = bridge_mcp_ghidra.set_decompiler_comment("0x401000", "This is a comment")

        assert result == "Comment set successfully"
        mock_safe_post.assert_called_once_with("set_decompiler_comment",
                                                 {"address": "0x401000", "comment": "This is a comment"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_decompiler_comment_empty(self, mock_safe_post):
        """Test set_decompiler_comment with empty comment (should clear comment)."""
        mock_safe_post.return_value = "Comment cleared"

        result = bridge_mcp_ghidra.set_decompiler_comment("0x401000", "")

        assert result == "Comment cleared"
        mock_safe_post.assert_called_once_with("set_decompiler_comment",
                                                 {"address": "0x401000", "comment": ""})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_disassembly_comment(self, mock_safe_post):
        """Test set_disassembly_comment with valid data."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.set_disassembly_comment("0x401000", "Loop counter")

        assert result == "Success"
        mock_safe_post.assert_called_once_with("set_disassembly_comment",
                                                 {"address": "0x401000", "comment": "Loop counter"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_disassembly_comment_multiline(self, mock_safe_post):
        """Test set_disassembly_comment with multiline comment."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.set_disassembly_comment("0x401000", "Line 1\nLine 2")

        assert result == "Success"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["comment"] == "Line 1\nLine 2"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_plate_comment(self, mock_safe_post):
        """Test set_plate_comment with valid data."""
        mock_safe_post.return_value = "Plate comment set"

        result = bridge_mcp_ghidra.set_plate_comment("0x401000", "Function header comment")

        assert result == "Plate comment set"
        mock_safe_post.assert_called_once_with("set_plate_comment",
                                                 {"address": "0x401000", "comment": "Function header comment"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_plate_comment_multiline(self, mock_safe_post):
        """Test set_plate_comment with multiline bordered comment."""
        mock_safe_post.return_value = "Success"
        multiline_comment = "This is a function\nthat does important work\nAuthor: John Doe"

        result = bridge_mcp_ghidra.set_plate_comment("0x401000", multiline_comment)

        assert result == "Success"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["comment"] == multiline_comment


class TestRenamingAndTypeTools:
    """Test suite for renaming and type setting tools."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_variable(self, mock_safe_post):
        """Test rename_variable with valid parameters."""
        mock_safe_post.return_value = "Variable renamed"

        result = bridge_mcp_ghidra.rename_variable("main", "var_1", "counter")

        assert result == "Variable renamed"
        mock_safe_post.assert_called_once_with("renameVariable",
                                                 {"functionName": "main", "oldName": "var_1", "newName": "counter"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_variable_error(self, mock_safe_post):
        """Test rename_variable when variable doesn't exist."""
        mock_safe_post.return_value = "Error: Variable not found"

        result = bridge_mcp_ghidra.rename_variable("main", "nonexistent", "newname")

        assert "Error" in result

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_function_by_address(self, mock_safe_post):
        """Test rename_function_by_address with valid parameters."""
        mock_safe_post.return_value = "Function renamed"

        result = bridge_mcp_ghidra.rename_function_by_address("0x401000", "initialize")

        assert result == "Function renamed"
        mock_safe_post.assert_called_once_with("rename_function_by_address",
                                                 {"function_address": "0x401000", "new_name": "initialize"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_function_prototype(self, mock_safe_post):
        """Test set_function_prototype with valid prototype."""
        mock_safe_post.return_value = "Prototype set"

        result = bridge_mcp_ghidra.set_function_prototype("0x401000", "int main(int argc, char** argv)")

        assert result == "Prototype set"
        mock_safe_post.assert_called_once_with("set_function_prototype",
                                                 {"function_address": "0x401000", "prototype": "int main(int argc, char** argv)"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_function_prototype_void(self, mock_safe_post):
        """Test set_function_prototype with void function."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.set_function_prototype("0x402000", "void cleanup(void)")

        assert result == "Success"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_local_variable_type(self, mock_safe_post):
        """Test set_local_variable_type with valid type."""
        mock_safe_post.return_value = "Type set"

        result = bridge_mcp_ghidra.set_local_variable_type("0x401000", "counter", "uint32_t")

        assert result == "Type set"
        mock_safe_post.assert_called_once_with("set_local_variable_type",
                                                 {"function_address": "0x401000", "variable_name": "counter", "new_type": "uint32_t"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_local_variable_type_pointer(self, mock_safe_post):
        """Test set_local_variable_type with pointer type."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.set_local_variable_type("0x401000", "buffer", "char*")

        assert result == "Success"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["new_type"] == "char*"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_data_type(self, mock_safe_post):
        """Test set_data_type with valid type."""
        mock_safe_post.return_value = "Data type set"

        result = bridge_mcp_ghidra.set_data_type("0x401000", "int")

        assert result == "Data type set"
        mock_safe_post.assert_called_once_with("set_data_type",
                                                 {"address": "0x401000", "type_name": "int"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_data_type_array(self, mock_safe_post):
        """Test set_data_type with array type."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.set_data_type("0x401000", "byte[20]")

        assert result == "Success"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["type_name"] == "byte[20]"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_data_type_pointer_type(self, mock_safe_post):
        """Test set_data_type with pointer type like PCHAR."""
        mock_safe_post.return_value = "Success"

        result = bridge_mcp_ghidra.set_data_type("0x401000", "PCHAR")

        assert result == "Success"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["type_name"] == "PCHAR"


class TestCrossReferenceTools:
    """Test suite for cross-reference tools."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_to(self, mock_safe_get):
        """Test get_xrefs_to with valid address."""
        mock_safe_get.return_value = ["0x401020 CALL", "0x401030 JMP"]

        result = bridge_mcp_ghidra.get_xrefs_to("0x401000")

        assert result == ["0x401020 CALL", "0x401030 JMP"]
        mock_safe_get.assert_called_once_with("xrefs_to", {"address": "0x401000", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_to_with_pagination(self, mock_safe_get):
        """Test get_xrefs_to with custom pagination."""
        mock_safe_get.return_value = ["0x401040 CALL"]

        result = bridge_mcp_ghidra.get_xrefs_to("0x401000", offset=10, limit=50)

        assert result == ["0x401040 CALL"]
        mock_safe_get.assert_called_once_with("xrefs_to", {"address": "0x401000", "offset": 10, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_to_none(self, mock_safe_get):
        """Test get_xrefs_to when there are no references."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.get_xrefs_to("0x401000")

        assert result == []

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_from(self, mock_safe_get):
        """Test get_xrefs_from with valid address."""
        mock_safe_get.return_value = ["0x402000 DATA", "0x403000 CALL"]

        result = bridge_mcp_ghidra.get_xrefs_from("0x401000")

        assert result == ["0x402000 DATA", "0x403000 CALL"]
        mock_safe_get.assert_called_once_with("xrefs_from", {"address": "0x401000", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_from_with_pagination(self, mock_safe_get):
        """Test get_xrefs_from with custom pagination."""
        mock_safe_get.return_value = ["0x404000 READ"]

        result = bridge_mcp_ghidra.get_xrefs_from("0x401000", offset=5, limit=25)

        assert result == ["0x404000 READ"]
        mock_safe_get.assert_called_once_with("xrefs_from", {"address": "0x401000", "offset": 5, "limit": 25})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_function_xrefs(self, mock_safe_get):
        """Test get_function_xrefs with function name."""
        mock_safe_get.return_value = ["0x401000 CALL from main", "0x402000 CALL from init"]

        result = bridge_mcp_ghidra.get_function_xrefs("helper")

        assert result == ["0x401000 CALL from main", "0x402000 CALL from init"]
        mock_safe_get.assert_called_once_with("function_xrefs", {"name": "helper", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_function_xrefs_with_pagination(self, mock_safe_get):
        """Test get_function_xrefs with custom pagination."""
        mock_safe_get.return_value = ["0x403000 CALL"]

        result = bridge_mcp_ghidra.get_function_xrefs("utility", offset=20, limit=10)

        assert result == ["0x403000 CALL"]
        mock_safe_get.assert_called_once_with("function_xrefs", {"name": "utility", "offset": 20, "limit": 10})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_function_xrefs_not_found(self, mock_safe_get):
        """Test get_function_xrefs when function has no references."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.get_function_xrefs("unused_function")

        assert result == []


class TestStringListingTools:
    """Test suite for string listing functionality."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings_default(self, mock_safe_get):
        """Test list_strings with default parameters."""
        mock_safe_get.return_value = [
            "0x401000: Hello World",
            "0x401020: Error message",
            "0x401040: Success"
        ]

        result = bridge_mcp_ghidra.list_strings()

        assert len(result) == 3
        assert "Hello World" in result[0]
        mock_safe_get.assert_called_once_with("strings", {"offset": 0, "limit": 2000})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings_with_pagination(self, mock_safe_get):
        """Test list_strings with custom pagination."""
        mock_safe_get.return_value = ["0x402000: String 1"]

        result = bridge_mcp_ghidra.list_strings(offset=100, limit=50)

        assert result == ["0x402000: String 1"]
        mock_safe_get.assert_called_once_with("strings", {"offset": 100, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings_with_filter(self, mock_safe_get):
        """Test list_strings with filter parameter."""
        mock_safe_get.return_value = ["0x401000: Error: File not found"]

        result = bridge_mcp_ghidra.list_strings(filter="Error")

        assert len(result) == 1
        assert "Error" in result[0]
        mock_safe_get.assert_called_once_with("strings", {"offset": 0, "limit": 2000, "filter": "Error"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings_with_filter_and_pagination(self, mock_safe_get):
        """Test list_strings with both filter and pagination."""
        mock_safe_get.return_value = ["0x401010: Success message"]

        result = bridge_mcp_ghidra.list_strings(offset=10, limit=100, filter="Success")

        assert result == ["0x401010: Success message"]
        mock_safe_get.assert_called_once_with("strings", {"offset": 10, "limit": 100, "filter": "Success"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings_empty(self, mock_safe_get):
        """Test list_strings when no strings match."""
        mock_safe_get.return_value = []

        result = bridge_mcp_ghidra.list_strings(filter="nonexistent")

        assert result == []


class TestBSimDatabaseOperations:
    """Test suite for BSim database operations."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_select_database(self, mock_safe_post):
        """Test bsim_select_database with file path."""
        mock_safe_post.return_value = "Connected to BSim database"

        result = bridge_mcp_ghidra.bsim_select_database("/path/to/database.bsim")

        assert result == "Connected to BSim database"
        mock_safe_post.assert_called_once_with("bsim/select_database",
                                                 {"database_path": "/path/to/database.bsim"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_select_database_postgresql(self, mock_safe_post):
        """Test bsim_select_database with PostgreSQL URL."""
        mock_safe_post.return_value = "Connected"

        result = bridge_mcp_ghidra.bsim_select_database("postgresql://localhost:5432/bsim")

        assert result == "Connected"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["database_path"] == "postgresql://localhost:5432/bsim"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_select_database_error(self, mock_safe_post):
        """Test bsim_select_database with invalid path."""
        mock_safe_post.return_value = "Error: Database not found"

        result = bridge_mcp_ghidra.bsim_select_database("/invalid/path.bsim")

        assert "Error" in result

    @patch('bridge_mcp_ghidra.safe_get')
    def test_bsim_status_connected(self, mock_safe_get):
        """Test bsim_status when connected."""
        mock_safe_get.return_value = ["Connected", "Database: /path/to/database.bsim"]

        result = bridge_mcp_ghidra.bsim_status()

        assert result == "Connected\nDatabase: /path/to/database.bsim"
        mock_safe_get.assert_called_once_with("bsim/status")

    @patch('bridge_mcp_ghidra.safe_get')
    def test_bsim_status_disconnected(self, mock_safe_get):
        """Test bsim_status when not connected."""
        mock_safe_get.return_value = ["Not connected"]

        result = bridge_mcp_ghidra.bsim_status()

        assert result == "Not connected"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_disconnect(self, mock_safe_post):
        """Test bsim_disconnect."""
        mock_safe_post.return_value = "Disconnected from BSim database"

        result = bridge_mcp_ghidra.bsim_disconnect()

        assert result == "Disconnected from BSim database"
        mock_safe_post.assert_called_once_with("bsim/disconnect", {})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_disconnect_when_not_connected(self, mock_safe_post):
        """Test bsim_disconnect when not connected."""
        mock_safe_post.return_value = "Already disconnected"

        result = bridge_mcp_ghidra.bsim_disconnect()

        assert result == "Already disconnected"


class TestBSimQueryOperations:
    """Test suite for BSim query operations."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_function_basic(self, mock_safe_post):
        """Test bsim_query_function with basic parameters."""
        mock_safe_post.return_value = "Match 1: similarity=0.85, confidence=0.9"

        result = bridge_mcp_ghidra.bsim_query_function("0x401000")

        assert "similarity=0.85" in result
        mock_safe_post.assert_called_once()
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["function_address"] == "0x401000"
        assert call_args[1]["max_matches"] == "10"
        assert call_args[1]["similarity_threshold"] == "0.7"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_function_custom_parameters(self, mock_safe_post):
        """Test bsim_query_function with custom parameters."""
        mock_safe_post.return_value = "Results"

        result = bridge_mcp_ghidra.bsim_query_function(
            "0x401000",
            max_matches=5,
            similarity_threshold=0.8,
            confidence_threshold=0.5,
            offset=10,
            limit=50
        )

        assert result == "Results"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["max_matches"] == "5"
        assert call_args[1]["similarity_threshold"] == "0.8"
        assert call_args[1]["confidence_threshold"] == "0.5"
        assert call_args[1]["offset"] == "10"
        assert call_args[1]["limit"] == "50"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_function_with_max_similarity(self, mock_safe_post):
        """Test bsim_query_function with max_similarity parameter."""
        mock_safe_post.return_value = "Results"

        result = bridge_mcp_ghidra.bsim_query_function(
            "0x401000",
            max_similarity=0.95
        )

        assert result == "Results"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["max_similarity"] == "0.95"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_function_with_max_confidence(self, mock_safe_post):
        """Test bsim_query_function with max_confidence parameter."""
        mock_safe_post.return_value = "Results"

        result = bridge_mcp_ghidra.bsim_query_function(
            "0x401000",
            max_confidence=0.85
        )

        assert result == "Results"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["max_confidence"] == "0.85"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_function_no_matches(self, mock_safe_post):
        """Test bsim_query_function when no matches are found."""
        mock_safe_post.return_value = "No matches found"

        result = bridge_mcp_ghidra.bsim_query_function("0x401000")

        assert result == "No matches found"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_all_functions_basic(self, mock_safe_post):
        """Test bsim_query_all_functions with default parameters."""
        mock_safe_post.return_value = "Summary: 10 functions matched"

        result = bridge_mcp_ghidra.bsim_query_all_functions()

        assert "10 functions matched" in result
        mock_safe_post.assert_called_once()
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["max_matches_per_function"] == "5"
        assert call_args[1]["similarity_threshold"] == "0.7"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_all_functions_custom_parameters(self, mock_safe_post):
        """Test bsim_query_all_functions with custom parameters."""
        mock_safe_post.return_value = "Results"

        result = bridge_mcp_ghidra.bsim_query_all_functions(
            max_matches_per_function=3,
            similarity_threshold=0.75,
            confidence_threshold=0.6,
            offset=20,
            limit=100
        )

        assert result == "Results"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["max_matches_per_function"] == "3"
        assert call_args[1]["similarity_threshold"] == "0.75"
        assert call_args[1]["confidence_threshold"] == "0.6"
        assert call_args[1]["offset"] == "20"
        assert call_args[1]["limit"] == "100"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_all_functions_with_bounds(self, mock_safe_post):
        """Test bsim_query_all_functions with max_similarity and max_confidence."""
        mock_safe_post.return_value = "Results"

        result = bridge_mcp_ghidra.bsim_query_all_functions(
            max_similarity=0.9,
            max_confidence=0.8
        )

        assert result == "Results"
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["max_similarity"] == "0.9"
        assert call_args[1]["max_confidence"] == "0.8"


class TestBSimMatchRetrieval:
    """Test suite for BSim match retrieval operations."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_get_match_disassembly(self, mock_safe_post):
        """Test bsim_get_match_disassembly with valid parameters."""
        mock_safe_post.return_value = "PUSH RBP\nMOV RBP, RSP\nRET"

        result = bridge_mcp_ghidra.bsim_get_match_disassembly(
            "/path/to/binary",
            "matched_function",
            "0x401000"
        )

        assert "PUSH RBP" in result
        mock_safe_post.assert_called_once_with("bsim/get_match_disassembly", {
            "executable_path": "/path/to/binary",
            "function_name": "matched_function",
            "function_address": "0x401000"
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_get_match_disassembly_not_found(self, mock_safe_post):
        """Test bsim_get_match_disassembly when program is not in project."""
        mock_safe_post.return_value = "Error: Program not found in project"

        result = bridge_mcp_ghidra.bsim_get_match_disassembly(
            "/nonexistent/binary",
            "func",
            "0x401000"
        )

        assert "Error" in result

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_get_match_decompile(self, mock_safe_post):
        """Test bsim_get_match_decompile with valid parameters."""
        mock_safe_post.return_value = "void matched_function() {\n  return;\n}"

        result = bridge_mcp_ghidra.bsim_get_match_decompile(
            "/path/to/binary",
            "matched_function",
            "0x401000"
        )

        assert "void matched_function()" in result
        mock_safe_post.assert_called_once_with("bsim/get_match_decompile", {
            "executable_path": "/path/to/binary",
            "function_name": "matched_function",
            "function_address": "0x401000"
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_get_match_decompile_not_found(self, mock_safe_post):
        """Test bsim_get_match_decompile when program is not in project."""
        mock_safe_post.return_value = "Error: Program not found in project"

        result = bridge_mcp_ghidra.bsim_get_match_decompile(
            "/nonexistent/binary",
            "func",
            "0x401000"
        )

        assert "Error" in result

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_get_match_decompile_function_not_found(self, mock_safe_post):
        """Test bsim_get_match_decompile when function doesn't exist."""
        mock_safe_post.return_value = "Error: Function not found at address"

        result = bridge_mcp_ghidra.bsim_get_match_decompile(
            "/path/to/binary",
            "invalid_func",
            "0xFFFFFFFF"
        )

        assert "Error" in result


class TestBulkOperations:
    """Test suite for bulk operations."""

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_single(self, mock_post):
        """Test bulk_operations with a single operation."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = '{"results": [{"status": "success"}]}'
        mock_post.return_value = mock_response

        operations = [
            {"endpoint": "/methods", "params": {"offset": 0, "limit": 10}}
        ]
        result = bridge_mcp_ghidra.bulk_operations(operations)

        assert "success" in result
        mock_post.assert_called_once()

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_multiple(self, mock_post):
        """Test bulk_operations with multiple operations."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = '{"results": [{"status": "ok"}, {"status": "ok"}]}'
        mock_post.return_value = mock_response

        operations = [
            {"endpoint": "/methods", "params": {"offset": 0, "limit": 10}},
            {"endpoint": "/decompile", "params": {"name": "main"}},
        ]
        result = bridge_mcp_ghidra.bulk_operations(operations)

        assert "ok" in result
        mock_post.assert_called_once()
        # Verify JSON payload
        call_args = mock_post.call_args
        assert call_args[1]['json']['operations'] == operations

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_with_rename(self, mock_post):
        """Test bulk_operations including rename operation."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = '{"results": [{"status": "renamed"}]}'
        mock_post.return_value = mock_response

        operations = [
            {"endpoint": "/rename_function_by_address",
             "params": {"function_address": "0x401000", "new_name": "initialize"}}
        ]
        result = bridge_mcp_ghidra.bulk_operations(operations)

        assert "renamed" in result

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_error(self, mock_post):
        """Test bulk_operations when request fails."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        mock_post.return_value = mock_response

        operations = [{"endpoint": "/methods", "params": {}}]
        result = bridge_mcp_ghidra.bulk_operations(operations)

        assert "Error 500" in result

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_exception(self, mock_post):
        """Test bulk_operations when exception is raised."""
        mock_post.side_effect = Exception("Connection timeout")

        operations = [{"endpoint": "/methods", "params": {}}]
        result = bridge_mcp_ghidra.bulk_operations(operations)

        assert "Request failed" in result
        assert "Connection timeout" in result


class TestStructCreationAndParsing:
    """Test suite for struct creation and C parsing."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_create_struct_basic(self, mock_safe_post):
        """Test create_struct with basic parameters."""
        mock_safe_post.return_value = '{"name": "MyStruct", "size": 0}'

        result = bridge_mcp_ghidra.create_struct("MyStruct")

        assert "MyStruct" in result
        mock_safe_post.assert_called_once_with("struct/create", {
            "name": "MyStruct",
            "size": 0,
            "category_path": ""
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_create_struct_with_size(self, mock_safe_post):
        """Test create_struct with specified size."""
        mock_safe_post.return_value = '{"name": "Buffer", "size": 256}'

        result = bridge_mcp_ghidra.create_struct("Buffer", size=256)

        assert "Buffer" in result
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["size"] == 256

    @patch('bridge_mcp_ghidra.safe_post')
    def test_create_struct_with_category(self, mock_safe_post):
        """Test create_struct with category path."""
        mock_safe_post.return_value = '{"name": "DataStruct", "category": "/MyStructs"}'

        result = bridge_mcp_ghidra.create_struct("DataStruct", category_path="/MyStructs")

        assert "DataStruct" in result
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["category_path"] == "/MyStructs"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_create_struct_error(self, mock_safe_post):
        """Test create_struct when struct already exists."""
        mock_safe_post.return_value = "Error: Struct already exists"

        result = bridge_mcp_ghidra.create_struct("ExistingStruct")

        assert "Error" in result

    @patch('bridge_mcp_ghidra.safe_post')
    def test_parse_c_struct_basic(self, mock_safe_post):
        """Test parse_c_struct with basic C struct."""
        mock_safe_post.return_value = '{"structures": [{"name": "Point", "size": 8}]}'

        c_code = "struct Point { int x; int y; };"
        result = bridge_mcp_ghidra.parse_c_struct(c_code)

        assert "Point" in result
        mock_safe_post.assert_called_once_with("struct/parse_c", {
            "c_code": c_code,
            "category_path": ""
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_parse_c_struct_with_category(self, mock_safe_post):
        """Test parse_c_struct with category path."""
        mock_safe_post.return_value = '{"structures": [{"name": "Rectangle"}]}'

        c_code = "struct Rectangle { int width; int height; };"
        result = bridge_mcp_ghidra.parse_c_struct(c_code, category_path="/Shapes")

        assert "Rectangle" in result
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["category_path"] == "/Shapes"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_parse_c_struct_complex(self, mock_safe_post):
        """Test parse_c_struct with nested/complex struct."""
        mock_safe_post.return_value = '{"structures": [{"name": "Node"}]}'

        c_code = "struct Node { int data; struct Node* next; };"
        result = bridge_mcp_ghidra.parse_c_struct(c_code)

        assert "Node" in result

    @patch('bridge_mcp_ghidra.safe_post')
    def test_parse_c_struct_error(self, mock_safe_post):
        """Test parse_c_struct with invalid C code."""
        mock_safe_post.return_value = "Error: Parse error at line 1"

        c_code = "struct Invalid { unknowntype field; };"
        result = bridge_mcp_ghidra.parse_c_struct(c_code)

        assert "Error" in result


class TestStructFieldManipulation:
    """Test suite for struct field manipulation operations."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_add_struct_field_basic(self, mock_safe_post):
        """Test add_struct_field with basic parameters."""
        mock_safe_post.return_value = '{"offset": 0, "size": 4, "type": "int", "name": "counter"}'

        result = bridge_mcp_ghidra.add_struct_field("MyStruct", "int", "counter")

        assert "counter" in result
        mock_safe_post.assert_called_once_with("struct/add_field", {
            "struct_name": "MyStruct",
            "field_type": "int",
            "field_name": "counter",
            "length": -1,
            "comment": ""
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_add_struct_field_with_length(self, mock_safe_post):
        """Test add_struct_field with specified length."""
        mock_safe_post.return_value = '{"offset": 0, "size": 20, "name": "buffer"}'

        result = bridge_mcp_ghidra.add_struct_field("MyStruct", "char", "buffer", length=20)

        assert "buffer" in result
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["length"] == 20

    @patch('bridge_mcp_ghidra.safe_post')
    def test_add_struct_field_with_comment(self, mock_safe_post):
        """Test add_struct_field with comment."""
        mock_safe_post.return_value = '{"name": "value", "comment": "The value field"}'

        result = bridge_mcp_ghidra.add_struct_field("MyStruct", "int", "value", comment="The value field")

        assert "value" in result
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["comment"] == "The value field"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_add_struct_field_pointer(self, mock_safe_post):
        """Test add_struct_field with pointer type."""
        mock_safe_post.return_value = '{"type": "void*", "name": "data"}'

        result = bridge_mcp_ghidra.add_struct_field("MyStruct", "void*", "data")

        assert "data" in result

    @patch('bridge_mcp_ghidra.safe_post')
    def test_insert_struct_field_at_offset_basic(self, mock_safe_post):
        """Test insert_struct_field_at_offset with basic parameters."""
        mock_safe_post.return_value = '{"offset": 8, "size": 4, "name": "inserted"}'

        result = bridge_mcp_ghidra.insert_struct_field_at_offset("MyStruct", 8, "int", "inserted")

        assert "inserted" in result
        mock_safe_post.assert_called_once_with("struct/insert_field", {
            "struct_name": "MyStruct",
            "offset": 8,
            "field_type": "int",
            "field_name": "inserted",
            "length": -1,
            "comment": ""
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_insert_struct_field_at_offset_zero(self, mock_safe_post):
        """Test insert_struct_field_at_offset at beginning of struct."""
        mock_safe_post.return_value = '{"offset": 0, "name": "first"}'

        result = bridge_mcp_ghidra.insert_struct_field_at_offset("MyStruct", 0, "char", "first")

        assert "first" in result
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["offset"] == 0

    @patch('bridge_mcp_ghidra.safe_post')
    def test_insert_struct_field_at_offset_with_length_and_comment(self, mock_safe_post):
        """Test insert_struct_field_at_offset with length and comment."""
        mock_safe_post.return_value = '{"offset": 4, "size": 10, "comment": "A string"}'

        result = bridge_mcp_ghidra.insert_struct_field_at_offset(
            "MyStruct", 4, "char", "str", length=10, comment="A string"
        )

        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["length"] == 10
        assert call_args[1]["comment"] == "A string"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_replace_struct_field_basic(self, mock_safe_post):
        """Test replace_struct_field with basic parameters."""
        mock_safe_post.return_value = '{"ordinal": 0, "type": "uint32_t", "name": "id"}'

        result = bridge_mcp_ghidra.replace_struct_field("MyStruct", 0, "uint32_t")

        assert "uint32_t" in result
        mock_safe_post.assert_called_once_with("struct/replace_field", {
            "struct_name": "MyStruct",
            "ordinal": 0,
            "field_type": "uint32_t",
            "field_name": "",
            "length": -1,
            "comment": ""
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_replace_struct_field_with_name(self, mock_safe_post):
        """Test replace_struct_field with new field name."""
        mock_safe_post.return_value = '{"ordinal": 1, "type": "long", "name": "timestamp"}'

        result = bridge_mcp_ghidra.replace_struct_field("MyStruct", 1, "long", field_name="timestamp")

        assert "timestamp" in result
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["field_name"] == "timestamp"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_replace_struct_field_full_parameters(self, mock_safe_post):
        """Test replace_struct_field with all parameters."""
        mock_safe_post.return_value = '{"ordinal": 2, "type": "byte", "name": "flags"}'

        result = bridge_mcp_ghidra.replace_struct_field(
            "MyStruct", 2, "byte", field_name="flags", length=1, comment="Status flags"
        )

        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["field_name"] == "flags"
        assert call_args[1]["length"] == 1
        assert call_args[1]["comment"] == "Status flags"


class TestStructFieldDeletion:
    """Test suite for struct field deletion operations."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_delete_struct_field_by_ordinal(self, mock_safe_post):
        """Test delete_struct_field using ordinal."""
        mock_safe_post.return_value = '{"status": "deleted", "ordinal": 0}'

        result = bridge_mcp_ghidra.delete_struct_field("MyStruct", ordinal=0)

        assert "deleted" in result or "status" in result
        mock_safe_post.assert_called_once_with("struct/delete_field", {
            "struct_name": "MyStruct",
            "ordinal": 0,
            "offset": -1
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_delete_struct_field_by_offset(self, mock_safe_post):
        """Test delete_struct_field using offset."""
        mock_safe_post.return_value = '{"status": "deleted", "offset": 8}'

        result = bridge_mcp_ghidra.delete_struct_field("MyStruct", offset=8)

        mock_safe_post.assert_called_once_with("struct/delete_field", {
            "struct_name": "MyStruct",
            "ordinal": -1,
            "offset": 8
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_delete_struct_field_default_params(self, mock_safe_post):
        """Test delete_struct_field with default parameters."""
        mock_safe_post.return_value = '{"status": "deleted"}'

        result = bridge_mcp_ghidra.delete_struct_field("MyStruct")

        # Should use default values of -1 for both
        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["ordinal"] == -1
        assert call_args[1]["offset"] == -1

    @patch('bridge_mcp_ghidra.safe_post')
    def test_clear_struct_field_by_ordinal(self, mock_safe_post):
        """Test clear_struct_field using ordinal."""
        mock_safe_post.return_value = '{"status": "cleared", "ordinal": 1}'

        result = bridge_mcp_ghidra.clear_struct_field("MyStruct", ordinal=1)

        assert "cleared" in result or "status" in result
        mock_safe_post.assert_called_once_with("struct/clear_field", {
            "struct_name": "MyStruct",
            "ordinal": 1,
            "offset": -1
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_clear_struct_field_by_offset(self, mock_safe_post):
        """Test clear_struct_field using offset."""
        mock_safe_post.return_value = '{"status": "cleared", "offset": 4}'

        result = bridge_mcp_ghidra.clear_struct_field("MyStruct", offset=4)

        mock_safe_post.assert_called_once_with("struct/clear_field", {
            "struct_name": "MyStruct",
            "ordinal": -1,
            "offset": 4
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_clear_struct_field_error(self, mock_safe_post):
        """Test clear_struct_field when field doesn't exist."""
        mock_safe_post.return_value = "Error: Field not found"

        result = bridge_mcp_ghidra.clear_struct_field("MyStruct", ordinal=99)

        assert "Error" in result


class TestStructInformationAndListing:
    """Test suite for struct information retrieval and listing."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_struct_info_basic(self, mock_safe_get):
        """Test get_struct_info with basic struct."""
        mock_safe_get.return_value = '{"name": "MyStruct", "size": 16, "numComponents": 2}'

        result = bridge_mcp_ghidra.get_struct_info("MyStruct")

        assert "MyStruct" in result
        mock_safe_get.assert_called_once_with("struct/get_info", {"name": "MyStruct"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_struct_info_detailed(self, mock_safe_get):
        """Test get_struct_info with detailed response."""
        mock_safe_get.return_value = '{"name": "ComplexStruct", "size": 32, "isPacked": false, "alignment": 4}'

        result = bridge_mcp_ghidra.get_struct_info("ComplexStruct")

        assert "ComplexStruct" in result
        assert "isPacked" in result or "alignment" in result

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_struct_info_not_found(self, mock_safe_get):
        """Test get_struct_info when struct doesn't exist."""
        mock_safe_get.return_value = "Error: Struct not found"

        result = bridge_mcp_ghidra.get_struct_info("NonexistentStruct")

        assert "Error" in result

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_structs_default(self, mock_safe_get):
        """Test list_structs with default parameters."""
        mock_safe_get.return_value = '{"structs": [{"name": "Struct1"}, {"name": "Struct2"}]}'

        result = bridge_mcp_ghidra.list_structs()

        assert "Struct1" in result or "structs" in result
        mock_safe_get.assert_called_once_with("struct/list", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_structs_with_pagination(self, mock_safe_get):
        """Test list_structs with custom pagination."""
        mock_safe_get.return_value = '{"structs": [{"name": "Struct3"}]}'

        result = bridge_mcp_ghidra.list_structs(offset=10, limit=50)

        mock_safe_get.assert_called_once_with("struct/list", {"offset": 10, "limit": 50})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_structs_with_category(self, mock_safe_get):
        """Test list_structs filtered by category."""
        mock_safe_get.return_value = '{"structs": [{"name": "MyStruct", "category": "/MyStructs"}]}'

        result = bridge_mcp_ghidra.list_structs(category_path="/MyStructs")

        mock_safe_get.assert_called_once()
        call_args = mock_safe_get.call_args[0]
        assert call_args[1]["category_path"] == "/MyStructs"

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_structs_with_category_and_pagination(self, mock_safe_get):
        """Test list_structs with category and pagination."""
        mock_safe_get.return_value = '{"structs": []}'

        result = bridge_mcp_ghidra.list_structs(category_path="/Custom", offset=20, limit=25)

        call_args = mock_safe_get.call_args[0]
        assert call_args[1]["category_path"] == "/Custom"
        assert call_args[1]["offset"] == 20
        assert call_args[1]["limit"] == 25

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_structs_empty(self, mock_safe_get):
        """Test list_structs when no structs exist."""
        mock_safe_get.return_value = '{"structs": []}'

        result = bridge_mcp_ghidra.list_structs()

        assert "structs" in result


class TestStructRenamingAndDeletion:
    """Test suite for struct renaming and deletion operations."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_struct_basic(self, mock_safe_post):
        """Test rename_struct with valid names."""
        mock_safe_post.return_value = '{"status": "renamed", "old_name": "OldStruct", "new_name": "NewStruct"}'

        result = bridge_mcp_ghidra.rename_struct("OldStruct", "NewStruct")

        assert "NewStruct" in result
        mock_safe_post.assert_called_once_with("struct/rename", {
            "old_name": "OldStruct",
            "new_name": "NewStruct"
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_struct_with_underscores(self, mock_safe_post):
        """Test rename_struct with underscore names."""
        mock_safe_post.return_value = '{"status": "renamed"}'

        result = bridge_mcp_ghidra.rename_struct("old_struct_name", "new_struct_name")

        call_args = mock_safe_post.call_args[0]
        assert call_args[1]["old_name"] == "old_struct_name"
        assert call_args[1]["new_name"] == "new_struct_name"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_struct_error_not_found(self, mock_safe_post):
        """Test rename_struct when struct doesn't exist."""
        mock_safe_post.return_value = "Error: Struct not found"

        result = bridge_mcp_ghidra.rename_struct("NonexistentStruct", "NewName")

        assert "Error" in result

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_struct_error_duplicate(self, mock_safe_post):
        """Test rename_struct when new name already exists."""
        mock_safe_post.return_value = "Error: Struct with new name already exists"

        result = bridge_mcp_ghidra.rename_struct("Struct1", "ExistingStruct")

        assert "Error" in result

    @patch('bridge_mcp_ghidra.safe_post')
    def test_delete_struct_basic(self, mock_safe_post):
        """Test delete_struct with valid name."""
        mock_safe_post.return_value = '{"status": "deleted", "name": "MyStruct"}'

        result = bridge_mcp_ghidra.delete_struct("MyStruct")

        assert "deleted" in result or "MyStruct" in result
        mock_safe_post.assert_called_once_with("struct/delete", {"name": "MyStruct"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_delete_struct_not_found(self, mock_safe_post):
        """Test delete_struct when struct doesn't exist."""
        mock_safe_post.return_value = "Error: Struct not found"

        result = bridge_mcp_ghidra.delete_struct("NonexistentStruct")

        assert "Error" in result

    @patch('bridge_mcp_ghidra.safe_post')
    def test_delete_struct_in_use(self, mock_safe_post):
        """Test delete_struct when struct is referenced by other types."""
        mock_safe_post.return_value = "Error: Cannot delete struct, it is referenced by other types"

        result = bridge_mcp_ghidra.delete_struct("ReferencedStruct")

        assert "Error" in result or "referenced" in result
