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


class TestNamespacesSearch:
    """Test namespaces search operations

    NOTE: The current test binary (test_simple) does not contain user-defined
    namespaces. These tests verify the search functionality works correctly
    but may not exercise the search filtering with actual namespace data.
    Consider adding a C++ test binary with namespaces to fully test this feature.
    """

    def test_query_namespaces_basic(self, ghidra_server):
        """Test listing namespaces without search parameter"""
        result = query(type="namespaces", limit=100)

        # Result is a list of lines
        assert isinstance(result, list)

        # Warn if no namespaces found - test binary may need C++ code with namespaces
        if len(result) == 0:
            import warnings
            warnings.warn(
                "No namespaces found in test binary. "
                "Consider adding a C++ binary with namespaces to test-infrastructure/fixtures "
                "to fully exercise namespace search functionality.",
                UserWarning
            )

    def test_query_namespaces_with_search(self, ghidra_server):
        """Test listing namespaces with search parameter"""
        import warnings

        # First get all namespaces to find a search term
        all_namespaces = query(type="namespaces", limit=100)
        assert isinstance(all_namespaces, list)

        if len(all_namespaces) > 0:
            # Get a substring from the first namespace to search for
            first_namespace = all_namespaces[0]
            # Use first few characters as search term
            search_term = first_namespace[:3] if len(first_namespace) >= 3 else first_namespace

            result = query(type="namespaces", search=search_term, limit=100)

            # Result is a list of lines
            assert isinstance(result, list)
            # Should have at least one result since we searched for existing namespace
            assert len(result) > 0

            # All results should contain the search term (case-insensitive)
            for ns in result:
                assert search_term.lower() in ns.lower(), f"Expected '{search_term}' in '{ns}'"
        else:
            warnings.warn(
                "No namespaces found - search filtering not tested. "
                "Add C++ binary with namespaces to fixtures.",
                UserWarning
            )

    def test_query_namespaces_search_no_match(self, ghidra_server):
        """Test namespaces search with term that doesn't match"""
        result = query(type="namespaces", search="ZZZZNONEXISTENT12345", limit=100)

        # Result is a list
        assert isinstance(result, list)
        # Should be empty since the search term shouldn't match anything
        assert len(result) == 0, f"Expected no results but got: {result}"

    def test_query_namespaces_pagination(self, ghidra_server):
        """Test namespaces query with pagination"""
        import warnings

        # Get first page
        result1 = query(type="namespaces", offset=0, limit=10)
        # Get second page
        result2 = query(type="namespaces", offset=10, limit=10)

        assert isinstance(result1, list)
        assert isinstance(result2, list)

        # Pages should be different (if there are enough namespaces)
        if len(result1) == 10 and len(result2) > 0:
            assert result1 != result2
        else:
            warnings.warn(
                "Not enough namespaces to test pagination (need >10). "
                "Add C++ binary with namespaces to fixtures.",
                UserWarning
            )

    def test_query_namespaces_search_with_pagination(self, ghidra_server):
        """Test namespaces search with custom pagination"""
        import warnings

        # First get all namespaces to find a search term
        all_namespaces = query(type="namespaces", limit=100)

        if len(all_namespaces) > 0:
            # Use a common substring that might match multiple namespaces
            search_term = all_namespaces[0][:2] if len(all_namespaces[0]) >= 2 else all_namespaces[0]

            result = query(type="namespaces", search=search_term, offset=0, limit=5)

            assert isinstance(result, list)
            assert len(result) <= 5
        else:
            warnings.warn(
                "No namespaces found - search with pagination not tested. "
                "Add C++ binary with namespaces to fixtures.",
                UserWarning
            )

    def test_query_namespaces_default_limit(self, ghidra_server):
        """Test that namespaces query uses default limit"""
        result = query(type="namespaces")

        # Result is a list of lines
        assert isinstance(result, list)
