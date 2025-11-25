"""Tests for the binary marker functionality.

This module tests the @pytest.mark.binary decorator that allows tests
to specify which binary they require.
"""

import pytest
from bridge_mcp_ghidra import query


class TestBinaryMarker:
    """Test the binary marker functionality."""

    def test_default_binary_without_marker(self, program, ghidra_server):
        """Test that tests without a marker use the default binary."""
        # The default binary is 'test_simple'
        assert program == "test_simple"

        # Verify we can actually query the program
        result = query(type="methods", limit=10)
        assert isinstance(result, list)

    @pytest.mark.binary("test_simple")
    def test_explicit_default_binary(self, program, ghidra_server):
        """Test that explicitly marking test_simple works."""
        assert program == "test_simple"

        # Verify we can query the program
        result = query(type="methods", limit=10)
        assert isinstance(result, list)

    def test_program_fixture_provides_binary_name(self, program, ghidra_server):
        """Test that the program fixture provides the binary name."""
        # Without a marker, should use the default
        assert program == "test_simple"
        assert isinstance(program, str)


class TestBinaryMarkerOnClass:
    """Test that binary marker works on classes."""

    # Note: Class-level markers would need pytestmark = pytest.mark.binary("...")
    # For now we test method-level markers

    @pytest.mark.binary("test_simple")
    def test_method_level_marker(self, program, ghidra_server):
        """Test that method-level binary marker works."""
        assert program == "test_simple"


@pytest.mark.binary("test_cpp")
class TestCppBinarySwitching:
    """Tests that require the C++ binary - demonstrates binary switching.

    These tests will automatically switch to the test_cpp binary when run.
    The binary is imported on first use and cached for subsequent tests.
    """

    def test_cpp_binary_loads(self, program, ghidra_server):
        """Test that the C++ binary is automatically loaded when requested."""
        assert program == "test_cpp"

    def test_cpp_classes_query(self, program, ghidra_server):
        """Test that we can query the C++ binary after switching."""
        assert program == "test_cpp"
        # Query classes from the C++ binary
        classes = query(type="classes", limit=50)
        assert isinstance(classes, list)


class TestQueryWithBinaryMarker:
    """Integration tests showing binary marker with actual queries."""

    @pytest.mark.binary("test_simple")
    def test_functions_in_test_simple(self, program, ghidra_server):
        """Test that we can query functions from test_simple binary."""
        assert program == "test_simple"

        result = query(type="methods", limit=100)
        assert isinstance(result, list)
        assert len(result) > 0

        # test_simple should have known functions
        text = "\n".join(result)
        # The binary has functions like add, multiply, main, etc.
        assert any(name in text for name in ["add", "main", "multiply", "helper"])

    @pytest.mark.binary("test_simple")
    def test_segments_in_test_simple(self, program, ghidra_server):
        """Test that we can query segments from test_simple binary."""
        assert program == "test_simple"

        result = query(type="segments", limit=10)
        assert isinstance(result, list)
        assert len(result) > 0
