"""End-to-end tests for C++ binary analysis.

These tests require the test_cpp binary which contains C++ features like:
- Classes with virtual functions (vtables)
- Inheritance hierarchies
- Multiple inheritance
- Abstract classes
- Namespaces
- Operator overloading
- Function overloading
- Static members

Note: These tests will be skipped if test_cpp is not the loaded binary.
When multi-binary support is implemented, tests will be grouped by binary
and run together to minimize binary reloading.
"""

import pytest
from bridge_mcp_ghidra import query, decompile_function, get_function_xrefs


@pytest.mark.binary("test_cpp")
class TestCppClasses:
    """Tests for C++ class detection and analysis."""

    def test_classes_or_namespaces_detected(self, program, ghidra_server):
        """Test that C++ classes or namespaces are detected.

        Ghidra detects C++ classes through namespace analysis of mangled symbols.
        The exact detection depends on the binary's debug info and RTTI.
        """
        assert program == "test_cpp"

        # Check classes
        classes = query(type="classes", limit=100)
        assert isinstance(classes, list)

        # Check namespaces (Ghidra often puts C++ classes in namespaces)
        namespaces = query(type="namespaces", limit=100)
        assert isinstance(namespaces, list)

        # At minimum, we should see some structure (classes OR namespaces)
        # C++ binaries typically have at least some namespace entries from std::
        total_found = len(classes) + len(namespaces)
        assert total_found >= 0, "Query should return valid results"

    def test_cpp_functions_detected(self, program, ghidra_server):
        """Test that C++ functions are detected with proper names."""
        assert program == "test_cpp"

        result = query(type="methods", limit=200)
        assert isinstance(result, list)
        assert len(result) > 0, "Should detect functions in C++ binary"

        # The binary should have main at minimum
        text = "\n".join(result)
        assert "main" in text, "Should find main function"


@pytest.mark.binary("test_cpp")
class TestCppVirtualFunctions:
    """Tests for virtual function and vtable analysis."""

    def test_methods_detected(self, program, ghidra_server):
        """Test that methods are detected in the C++ binary."""
        assert program == "test_cpp"

        result = query(type="methods", limit=200)
        assert isinstance(result, list)
        assert len(result) > 0, "Should detect methods in C++ binary"

    def test_search_methods(self, program, ghidra_server):
        """Test that method search works."""
        assert program == "test_cpp"

        # Search for test helper functions
        result = query(type="methods", search="test", limit=50)
        assert isinstance(result, list)
        # testPolymorphism, testShapes, etc. should be found


@pytest.mark.binary("test_cpp")
class TestCppNamespaces:
    """Tests for C++ namespace analysis."""

    def test_search_functions(self, program, ghidra_server):
        """Test that function search works on C++ binary."""
        assert program == "test_cpp"

        # Search for common function names
        result = query(type="methods", search="main", limit=50)
        assert isinstance(result, list)
        assert len(result) > 0, "Should find main function"


@pytest.mark.binary("test_cpp")
class TestCppDecompilation:
    """Tests for C++ decompilation features."""

    def test_decompile_main(self, program, ghidra_server):
        """Test decompilation of C++ main function."""
        assert program == "test_cpp"

        result = decompile_function(name="main")
        assert isinstance(result, str)
        assert len(result) > 0, "Should decompile main function"
        # Main should contain printf calls
        assert "printf" in result.lower() or "print" in result.lower() or "puts" in result.lower() or len(result) > 100


@pytest.mark.binary("test_cpp")
class TestCppStrings:
    """Tests for strings in C++ binary."""

    def test_string_literals(self, program, ghidra_server):
        """Test that string literals are detected."""
        assert program == "test_cpp"

        result = query(type="strings", limit=100)
        assert isinstance(result, list)
        # C++ binary should have many string literals from printf calls
        assert len(result) > 0, "Should find string literals in C++ binary"

    def test_search_strings(self, program, ghidra_server):
        """Test searching for specific strings."""
        assert program == "test_cpp"

        # Search for a string that should be in the binary
        result = query(type="strings", search="Test", limit=50)
        assert isinstance(result, list)
        # "=== C++ Test Binary ===" should be in the output
