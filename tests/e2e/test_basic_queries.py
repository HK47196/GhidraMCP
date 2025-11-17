"""End-to-end tests for basic query operations"""

import pytest
from bridge_mcp_ghidra import query, get_current_function, man


class TestBasicQueries:
    """Test basic query operations"""

    def test_query_list_functions(self, ghidra_server):
        """Test listing all functions"""
        result = query(type="methods", limit=100)

        # Result is a list of lines
        assert isinstance(result, list)
        assert len(result) > 0

        # Join to check content
        text = "\n".join(result)
        assert len(text) > 5

    def test_get_current_function(self, ghidra_server):
        """Test getting current function"""
        result = get_current_function()

        # Result should be a string
        assert isinstance(result, str)
        assert len(result) > 0

    def test_man_command(self, ghidra_server):
        """Test the manual/help command"""
        result = man(tool_name="disassemble_function")

        # Result is a string
        assert isinstance(result, str)
        assert "disassemble" in result.lower() or "function" in result.lower()
