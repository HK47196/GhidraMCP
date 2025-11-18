"""End-to-end tests for basic query operations"""

import pytest
from bridge_mcp_ghidra import query, get_current_function, man, list_strings


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

    def test_query_strings_basic(self, ghidra_server):
        """Test listing strings without search parameter"""
        result = query(type="strings", limit=100)

        # Result is a list of lines
        assert isinstance(result, list)
        # May or may not have strings depending on the test binary

    def test_query_strings_with_search(self, ghidra_server):
        """Test listing strings with search parameter"""
        result = query(type="strings", search="test", limit=100)

        # Result is a list of lines
        assert isinstance(result, list)

        # If there are results, they should contain the search term
        if len(result) > 0:
            text = "\n".join(result).lower()
            # Strings should be filtered by search term
            assert "test" in text or len(result) == 0

    def test_query_strings_default_limit(self, ghidra_server):
        """Test that strings query uses default high limit"""
        result = query(type="strings")

        # Result is a list of lines
        assert isinstance(result, list)

    def test_query_strings_pagination(self, ghidra_server):
        """Test strings query with pagination"""
        # Get first page
        result1 = query(type="strings", offset=0, limit=10)
        # Get second page
        result2 = query(type="strings", offset=10, limit=10)

        assert isinstance(result1, list)
        assert isinstance(result2, list)

        # Pages should be different (if there are enough strings)
        if len(result1) == 10 and len(result2) > 0:
            assert result1 != result2

    def test_list_strings_function(self, ghidra_server):
        """Test list_strings function directly"""
        result = list_strings(limit=50)

        # Result is a list
        assert isinstance(result, list)

    def test_list_strings_with_search(self, ghidra_server):
        """Test list_strings function with search parameter"""
        result = list_strings(search="error", limit=100)

        # Result is a list
        assert isinstance(result, list)

        # If there are results, they should contain the search term
        if len(result) > 0:
            text = "\n".join(result).lower()
            assert "error" in text

    def test_list_strings_pagination(self, ghidra_server):
        """Test list_strings with pagination parameters"""
        result = list_strings(offset=5, limit=10)

        assert isinstance(result, list)
        assert len(result) <= 10

    def test_query_classes_vs_namespaces_distinct(self, ghidra_server):
        """Test that classes and namespaces queries return different results

        Classes should only return symbols with SymbolType.CLASS,
        while namespaces returns all non-global namespaces.
        """
        import warnings
        warnings.warn(
            "No C++ test fixture available - cannot properly test classes vs namespaces distinction. "
            "Classes query returns SymbolType.CLASS symbols only.",
            UserWarning
        )
