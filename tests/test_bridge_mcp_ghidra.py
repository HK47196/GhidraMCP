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


class TestListAndSearchTools:
    """Test suite for list and search tool implementations."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_imports(self, mock_safe_get):
        """Test list_imports tool."""
        mock_safe_get.return_value = ["printf", "malloc", "free"]

        result = bridge_mcp_ghidra.list_imports(offset=0, limit=100)

        assert result == ["printf", "malloc", "free"]
        mock_safe_get.assert_called_once_with("imports", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_imports_with_pagination(self, mock_safe_get):
        """Test list_imports with custom pagination."""
        mock_safe_get.return_value = ["puts"]

        result = bridge_mcp_ghidra.list_imports(offset=5, limit=1)

        assert result == ["puts"]
        mock_safe_get.assert_called_once_with("imports", {"offset": 5, "limit": 1})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_exports(self, mock_safe_get):
        """Test list_exports tool."""
        mock_safe_get.return_value = ["main", "init", "fini"]

        result = bridge_mcp_ghidra.list_exports(offset=0, limit=100)

        assert result == ["main", "init", "fini"]
        mock_safe_get.assert_called_once_with("exports", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_namespaces(self, mock_safe_get):
        """Test list_namespaces tool."""
        mock_safe_get.return_value = ["std", "boost", "custom"]

        result = bridge_mcp_ghidra.list_namespaces(offset=0, limit=100)

        assert result == ["std", "boost", "custom"]
        mock_safe_get.assert_called_once_with("namespaces", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_data_items(self, mock_safe_get):
        """Test list_data_items tool."""
        mock_safe_get.return_value = ["data1: 0x1000", "data2: 0x2000"]

        result = bridge_mcp_ghidra.list_data_items(offset=0, limit=100)

        assert result == ["data1: 0x1000", "data2: 0x2000"]
        mock_safe_get.assert_called_once_with("data", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name(self, mock_safe_get):
        """Test search_functions_by_name tool."""
        mock_safe_get.return_value = ["get_value", "get_status", "getter"]

        result = bridge_mcp_ghidra.search_functions_by_name("get", offset=0, limit=100)

        assert result == ["get_value", "get_status", "getter"]
        mock_safe_get.assert_called_once_with("searchFunctions", {"query": "get", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_functions_by_name_empty_query(self, mock_safe_get):
        """Test search_functions_by_name with empty query."""
        result = bridge_mcp_ghidra.search_functions_by_name("", offset=0, limit=100)

        assert result == ["Error: query string is required"]
        mock_safe_get.assert_not_called()

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_functions(self, mock_safe_get):
        """Test list_functions tool."""
        mock_safe_get.return_value = ["main", "init", "process", "cleanup"]

        result = bridge_mcp_ghidra.list_functions()

        assert result == ["main", "init", "process", "cleanup"]
        mock_safe_get.assert_called_once_with("list_functions")

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings(self, mock_safe_get):
        """Test list_strings tool without filter."""
        mock_safe_get.return_value = ["0x1000: Hello World", "0x2000: Error message"]

        result = bridge_mcp_ghidra.list_strings(offset=0, limit=2000)

        assert result == ["0x1000: Hello World", "0x2000: Error message"]
        mock_safe_get.assert_called_once_with("strings", {"offset": 0, "limit": 2000})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_strings_with_filter(self, mock_safe_get):
        """Test list_strings tool with filter."""
        mock_safe_get.return_value = ["0x1000: Error message", "0x3000: Error code"]

        result = bridge_mcp_ghidra.list_strings(offset=0, limit=2000, filter="Error")

        assert result == ["0x1000: Error message", "0x3000: Error code"]
        mock_safe_get.assert_called_once_with("strings", {"offset": 0, "limit": 2000, "filter": "Error"})


class TestFunctionAnalysisTools:
    """Test suite for function analysis tool implementations."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_function_by_address(self, mock_safe_get):
        """Test get_function_by_address tool."""
        mock_safe_get.return_value = ["Function: main at 0x401000"]

        result = bridge_mcp_ghidra.get_function_by_address("0x401000")

        assert result == "Function: main at 0x401000"
        mock_safe_get.assert_called_once_with("get_function_by_address", {"address": "0x401000"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_current_address(self, mock_safe_get):
        """Test get_current_address tool."""
        mock_safe_get.return_value = ["0x401234"]

        result = bridge_mcp_ghidra.get_current_address()

        assert result == "0x401234"
        mock_safe_get.assert_called_once_with("get_current_address")

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_current_function(self, mock_safe_get):
        """Test get_current_function tool."""
        mock_safe_get.return_value = ["main"]

        result = bridge_mcp_ghidra.get_current_function()

        assert result == "main"
        mock_safe_get.assert_called_once_with("get_current_function")

    @patch('bridge_mcp_ghidra.safe_get')
    def test_decompile_function_by_address(self, mock_safe_get):
        """Test decompile_function_by_address tool."""
        mock_safe_get.return_value = ["int main() {", "  return 0;", "}"]

        result = bridge_mcp_ghidra.decompile_function_by_address("0x401000")

        assert result == "int main() {\n  return 0;\n}"
        mock_safe_get.assert_called_once_with("decompile_function", {"address": "0x401000"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_disassemble_function(self, mock_safe_get):
        """Test disassemble_function tool."""
        mock_safe_get.return_value = ["0x401000: PUSH EBP", "0x401001: MOV EBP,ESP"]

        result = bridge_mcp_ghidra.disassemble_function("0x401000")

        assert result == ["0x401000: PUSH EBP", "0x401001: MOV EBP,ESP"]
        mock_safe_get.assert_called_once_with("disassemble_function", {"address": "0x401000"})


class TestCommentTools:
    """Test suite for comment-related tool implementations."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_decompiler_comment(self, mock_safe_post):
        """Test set_decompiler_comment tool."""
        mock_safe_post.return_value = "Comment set successfully"

        result = bridge_mcp_ghidra.set_decompiler_comment("0x401000", "This is a comment")

        assert result == "Comment set successfully"
        mock_safe_post.assert_called_once_with("set_decompiler_comment",
                                                 {"address": "0x401000", "comment": "This is a comment"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_disassembly_comment(self, mock_safe_post):
        """Test set_disassembly_comment tool."""
        mock_safe_post.return_value = "Comment set successfully"

        result = bridge_mcp_ghidra.set_disassembly_comment("0x401000", "Assembly comment")

        assert result == "Comment set successfully"
        mock_safe_post.assert_called_once_with("set_disassembly_comment",
                                                 {"address": "0x401000", "comment": "Assembly comment"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_plate_comment(self, mock_safe_post):
        """Test set_plate_comment tool."""
        mock_safe_post.return_value = "Plate comment set successfully"

        result = bridge_mcp_ghidra.set_plate_comment("0x401000", "Function header\nMultiline comment")

        assert result == "Plate comment set successfully"
        mock_safe_post.assert_called_once_with("set_plate_comment",
                                                 {"address": "0x401000", "comment": "Function header\nMultiline comment"})


class TestModificationTools:
    """Test suite for modification tool implementations."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_function_by_address(self, mock_safe_post):
        """Test rename_function_by_address tool."""
        mock_safe_post.return_value = "Function renamed successfully"

        result = bridge_mcp_ghidra.rename_function_by_address("0x401000", "initialize")

        assert result == "Function renamed successfully"
        mock_safe_post.assert_called_once_with("rename_function_by_address",
                                                 {"function_address": "0x401000", "new_name": "initialize"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_variable(self, mock_safe_post):
        """Test rename_variable tool."""
        mock_safe_post.return_value = "Variable renamed successfully"

        result = bridge_mcp_ghidra.rename_variable("main", "var_8", "counter")

        assert result == "Variable renamed successfully"
        mock_safe_post.assert_called_once_with("renameVariable",
                                                 {"functionName": "main", "oldName": "var_8", "newName": "counter"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_function_prototype(self, mock_safe_post):
        """Test set_function_prototype tool."""
        mock_safe_post.return_value = "Prototype set successfully"

        result = bridge_mcp_ghidra.set_function_prototype("0x401000", "int main(int argc, char **argv)")

        assert result == "Prototype set successfully"
        mock_safe_post.assert_called_once_with("set_function_prototype",
                                                 {"function_address": "0x401000", "prototype": "int main(int argc, char **argv)"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_local_variable_type(self, mock_safe_post):
        """Test set_local_variable_type tool."""
        mock_safe_post.return_value = "Variable type set successfully"

        result = bridge_mcp_ghidra.set_local_variable_type("0x401000", "var_8", "int")

        assert result == "Variable type set successfully"
        mock_safe_post.assert_called_once_with("set_local_variable_type",
                                                 {"function_address": "0x401000", "variable_name": "var_8", "new_type": "int"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_set_data_type(self, mock_safe_post):
        """Test set_data_type tool."""
        mock_safe_post.return_value = "Data type set successfully"

        result = bridge_mcp_ghidra.set_data_type("0x1400010a0", "dword")

        assert result == "Data type set successfully"
        mock_safe_post.assert_called_once_with("set_data_type",
                                                 {"address": "0x1400010a0", "type_name": "dword"})


class TestXrefTools:
    """Test suite for cross-reference tool implementations."""

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_to(self, mock_safe_get):
        """Test get_xrefs_to tool."""
        mock_safe_get.return_value = ["0x401050 -> 0x401000", "0x401100 -> 0x401000"]

        result = bridge_mcp_ghidra.get_xrefs_to("0x401000", offset=0, limit=100)

        assert result == ["0x401050 -> 0x401000", "0x401100 -> 0x401000"]
        mock_safe_get.assert_called_once_with("xrefs_to", {"address": "0x401000", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_xrefs_from(self, mock_safe_get):
        """Test get_xrefs_from tool."""
        mock_safe_get.return_value = ["0x401000 -> 0x402000", "0x401000 -> 0x403000"]

        result = bridge_mcp_ghidra.get_xrefs_from("0x401000", offset=0, limit=100)

        assert result == ["0x401000 -> 0x402000", "0x401000 -> 0x403000"]
        mock_safe_get.assert_called_once_with("xrefs_from", {"address": "0x401000", "offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_function_xrefs(self, mock_safe_get):
        """Test get_function_xrefs tool."""
        mock_safe_get.return_value = ["main -> printf", "process -> printf"]

        result = bridge_mcp_ghidra.get_function_xrefs("printf", offset=0, limit=100)

        assert result == ["main -> printf", "process -> printf"]
        mock_safe_get.assert_called_once_with("function_xrefs", {"name": "printf", "offset": 0, "limit": 100})


class TestBSimTools:
    """Test suite for BSim tool implementations."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_select_database(self, mock_safe_post):
        """Test bsim_select_database tool."""
        mock_safe_post.return_value = "Connected to database"

        result = bridge_mcp_ghidra.bsim_select_database("/path/to/database.bsim")

        assert result == "Connected to database"
        mock_safe_post.assert_called_once_with("bsim/select_database", {"database_path": "/path/to/database.bsim"})

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_function(self, mock_safe_post):
        """Test bsim_query_function tool with default parameters."""
        mock_safe_post.return_value = "Match results"

        result = bridge_mcp_ghidra.bsim_query_function("0x401000")

        assert result == "Match results"
        call_args = mock_safe_post.call_args
        assert call_args[0][0] == "bsim/query_function"
        assert call_args[0][1]["function_address"] == "0x401000"
        assert call_args[0][1]["max_matches"] == "10"
        assert call_args[0][1]["similarity_threshold"] == "0.7"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_function_with_thresholds(self, mock_safe_post):
        """Test bsim_query_function tool with custom thresholds."""
        mock_safe_post.return_value = "Match results"

        result = bridge_mcp_ghidra.bsim_query_function(
            "0x401000",
            max_matches=5,
            similarity_threshold=0.8,
            confidence_threshold=0.5,
            max_similarity=0.95,
            max_confidence=0.9
        )

        assert result == "Match results"
        call_args = mock_safe_post.call_args
        data = call_args[0][1]
        assert data["max_matches"] == "5"
        assert data["similarity_threshold"] == "0.8"
        assert data["confidence_threshold"] == "0.5"
        assert data["max_similarity"] == "0.95"
        assert data["max_confidence"] == "0.9"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_query_all_functions(self, mock_safe_post):
        """Test bsim_query_all_functions tool."""
        mock_safe_post.return_value = "All functions match results"

        result = bridge_mcp_ghidra.bsim_query_all_functions(
            max_matches_per_function=5,
            similarity_threshold=0.7
        )

        assert result == "All functions match results"
        call_args = mock_safe_post.call_args
        assert call_args[0][0] == "bsim/query_all_functions"
        assert call_args[0][1]["max_matches_per_function"] == "5"
        assert call_args[0][1]["similarity_threshold"] == "0.7"

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_disconnect(self, mock_safe_post):
        """Test bsim_disconnect tool."""
        mock_safe_post.return_value = "Disconnected successfully"

        result = bridge_mcp_ghidra.bsim_disconnect()

        assert result == "Disconnected successfully"
        mock_safe_post.assert_called_once_with("bsim/disconnect", {})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_bsim_status(self, mock_safe_get):
        """Test bsim_status tool."""
        mock_safe_get.return_value = ["Connected to /path/to/database.bsim"]

        result = bridge_mcp_ghidra.bsim_status()

        assert result == "Connected to /path/to/database.bsim"
        mock_safe_get.assert_called_once_with("bsim/status")

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_get_match_disassembly(self, mock_safe_post):
        """Test bsim_get_match_disassembly tool."""
        mock_safe_post.return_value = "Assembly code"

        result = bridge_mcp_ghidra.bsim_get_match_disassembly(
            "/path/to/executable",
            "function_name",
            "0x401000"
        )

        assert result == "Assembly code"
        mock_safe_post.assert_called_once_with("bsim/get_match_disassembly", {
            "executable_path": "/path/to/executable",
            "function_name": "function_name",
            "function_address": "0x401000"
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_bsim_get_match_decompile(self, mock_safe_post):
        """Test bsim_get_match_decompile tool."""
        mock_safe_post.return_value = "Decompiled code"

        result = bridge_mcp_ghidra.bsim_get_match_decompile(
            "/path/to/executable",
            "function_name",
            "0x401000"
        )

        assert result == "Decompiled code"
        mock_safe_post.assert_called_once_with("bsim/get_match_decompile", {
            "executable_path": "/path/to/executable",
            "function_name": "function_name",
            "function_address": "0x401000"
        })


class TestStructTools:
    """Test suite for struct manipulation tool implementations."""

    @patch('bridge_mcp_ghidra.safe_post')
    def test_create_struct(self, mock_safe_post):
        """Test create_struct tool."""
        mock_safe_post.return_value = '{"name": "MyStruct", "size": 0}'

        result = bridge_mcp_ghidra.create_struct("MyStruct", size=0, category_path="/MyStructs")

        assert result == '{"name": "MyStruct", "size": 0}'
        mock_safe_post.assert_called_once_with("struct/create", {
            "name": "MyStruct",
            "size": 0,
            "category_path": "/MyStructs"
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_parse_c_struct(self, mock_safe_post):
        """Test parse_c_struct tool."""
        c_code = "struct MyStruct { int field1; char field2; };"
        mock_safe_post.return_value = '{"structs": ["MyStruct"]}'

        result = bridge_mcp_ghidra.parse_c_struct(c_code, category_path="/")

        assert result == '{"structs": ["MyStruct"]}'
        mock_safe_post.assert_called_once_with("struct/parse_c", {
            "c_code": c_code,
            "category_path": "/"
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_add_struct_field(self, mock_safe_post):
        """Test add_struct_field tool."""
        mock_safe_post.return_value = '{"field": "my_field", "offset": 0}'

        result = bridge_mcp_ghidra.add_struct_field(
            "MyStruct",
            "int",
            "my_field",
            length=-1,
            comment="My field comment"
        )

        assert result == '{"field": "my_field", "offset": 0}'
        mock_safe_post.assert_called_once_with("struct/add_field", {
            "struct_name": "MyStruct",
            "field_type": "int",
            "field_name": "my_field",
            "length": -1,
            "comment": "My field comment"
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_insert_struct_field_at_offset(self, mock_safe_post):
        """Test insert_struct_field_at_offset tool."""
        mock_safe_post.return_value = '{"success": true}'

        result = bridge_mcp_ghidra.insert_struct_field_at_offset(
            "MyStruct",
            4,
            "char",
            "inserted_field"
        )

        assert result == '{"success": true}'
        mock_safe_post.assert_called_once_with("struct/insert_field", {
            "struct_name": "MyStruct",
            "offset": 4,
            "field_type": "char",
            "field_name": "inserted_field",
            "length": -1,
            "comment": ""
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_replace_struct_field(self, mock_safe_post):
        """Test replace_struct_field tool."""
        mock_safe_post.return_value = '{"success": true}'

        result = bridge_mcp_ghidra.replace_struct_field(
            "MyStruct",
            0,
            "long",
            "new_field"
        )

        assert result == '{"success": true}'
        mock_safe_post.assert_called_once_with("struct/replace_field", {
            "struct_name": "MyStruct",
            "ordinal": 0,
            "field_type": "long",
            "field_name": "new_field",
            "length": -1,
            "comment": ""
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_delete_struct_field_by_ordinal(self, mock_safe_post):
        """Test delete_struct_field tool using ordinal."""
        mock_safe_post.return_value = '{"success": true}'

        result = bridge_mcp_ghidra.delete_struct_field("MyStruct", ordinal=1)

        assert result == '{"success": true}'
        mock_safe_post.assert_called_once_with("struct/delete_field", {
            "struct_name": "MyStruct",
            "ordinal": 1,
            "offset": -1
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_delete_struct_field_by_offset(self, mock_safe_post):
        """Test delete_struct_field tool using offset."""
        mock_safe_post.return_value = '{"success": true}'

        result = bridge_mcp_ghidra.delete_struct_field("MyStruct", offset=4)

        assert result == '{"success": true}'
        mock_safe_post.assert_called_once_with("struct/delete_field", {
            "struct_name": "MyStruct",
            "ordinal": -1,
            "offset": 4
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_clear_struct_field(self, mock_safe_post):
        """Test clear_struct_field tool."""
        mock_safe_post.return_value = '{"success": true}'

        result = bridge_mcp_ghidra.clear_struct_field("MyStruct", ordinal=0)

        assert result == '{"success": true}'
        mock_safe_post.assert_called_once_with("struct/clear_field", {
            "struct_name": "MyStruct",
            "ordinal": 0,
            "offset": -1
        })

    @patch('bridge_mcp_ghidra.safe_get')
    def test_get_struct_info(self, mock_safe_get):
        """Test get_struct_info tool."""
        mock_safe_get.return_value = '{"name": "MyStruct", "size": 8}'

        result = bridge_mcp_ghidra.get_struct_info("MyStruct")

        assert result == '{"name": "MyStruct", "size": 8}'
        mock_safe_get.assert_called_once_with("struct/get_info", {"name": "MyStruct"})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_structs(self, mock_safe_get):
        """Test list_structs tool."""
        mock_safe_get.return_value = '{"structs": ["Struct1", "Struct2"]}'

        result = bridge_mcp_ghidra.list_structs(category_path="", offset=0, limit=100)

        assert result == '{"structs": ["Struct1", "Struct2"]}'
        mock_safe_get.assert_called_once_with("struct/list", {"offset": 0, "limit": 100})

    @patch('bridge_mcp_ghidra.safe_get')
    def test_list_structs_with_category(self, mock_safe_get):
        """Test list_structs tool with category filter."""
        mock_safe_get.return_value = '{"structs": ["Struct1"]}'

        result = bridge_mcp_ghidra.list_structs(category_path="/MyStructs", offset=0, limit=100)

        assert result == '{"structs": ["Struct1"]}'
        mock_safe_get.assert_called_once_with("struct/list", {
            "category_path": "/MyStructs",
            "offset": 0,
            "limit": 100
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_rename_struct(self, mock_safe_post):
        """Test rename_struct tool."""
        mock_safe_post.return_value = '{"success": true}'

        result = bridge_mcp_ghidra.rename_struct("OldName", "NewName")

        assert result == '{"success": true}'
        mock_safe_post.assert_called_once_with("struct/rename", {
            "old_name": "OldName",
            "new_name": "NewName"
        })

    @patch('bridge_mcp_ghidra.safe_post')
    def test_delete_struct(self, mock_safe_post):
        """Test delete_struct tool."""
        mock_safe_post.return_value = '{"success": true}'

        result = bridge_mcp_ghidra.delete_struct("MyStruct")

        assert result == '{"success": true}'
        mock_safe_post.assert_called_once_with("struct/delete", {"name": "MyStruct"})


class TestBulkOperations:
    """Test suite for bulk operations tool implementation."""

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_success(self, mock_post):
        """Test bulk_operations tool with successful request."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.text = '{"results": [{"status": "ok"}, {"status": "ok"}]}'
        mock_post.return_value = mock_response

        operations = [
            {"endpoint": "/methods", "params": {"offset": 0, "limit": 10}},
            {"endpoint": "/decompile", "params": {"name": "main"}}
        ]

        result = bridge_mcp_ghidra.bulk_operations(operations)

        assert result == '{"results": [{"status": "ok"}, {"status": "ok"}]}'
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[1]['json'] == {"operations": operations}

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_error(self, mock_post):
        """Test bulk_operations tool with error response."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_post.return_value = mock_response

        operations = [{"endpoint": "/invalid", "params": {}}]

        result = bridge_mcp_ghidra.bulk_operations(operations)

        assert "Error 400" in result
        assert "Bad Request" in result

    @patch('bridge_mcp_ghidra.requests.post')
    def test_bulk_operations_exception(self, mock_post):
        """Test bulk_operations tool with exception."""
        mock_post.side_effect = Exception("Connection error")

        operations = [{"endpoint": "/methods", "params": {}}]

        result = bridge_mcp_ghidra.bulk_operations(operations)

        assert "Request failed" in result
        assert "Connection error" in result
