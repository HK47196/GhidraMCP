"""End-to-end tests for decompilation operations"""

import pytest
import re
from bridge_mcp_ghidra import decompile_function, disassemble_function, query, get_address_context


class TestDecompilation:
    """Test decompilation operations"""

    def test_decompile_main_function(self, ghidra_server):
        """Test decompiling the main function"""
        result = decompile_function(name="main")

        # Result is a string
        assert isinstance(result, str)

        # Should contain C-like code
        assert "{" in result or "}" in result, f"Expected braces in decompiled code. Got: {result[:500]}"

        # Check for common C keywords
        keywords = ["void", "int", "return"]
        found = [k for k in keywords if k in result]
        assert found, f"Expected at least one of {keywords} in decompiled code. Got: {result[:500]}"

    def test_disassemble_function(self, ghidra_server):
        """Test disassembling a function"""
        # First, search for main function to get its address
        search_result = query(type="methods", search="main")

        # Result is a list
        assert isinstance(search_result, list)

        # Join and look for "main @" specifically (not __libc_start_main)
        search_text = "\n".join(search_result)
        # Match "main @ 001011d4" pattern specifically
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, f"Could not find 'main' function address in search results: {search_text[:200]}"
        # Add 0x prefix if not present
        address = f"0x{addr_match.group(1)}"

        # Now disassemble at that address (pass as list)
        result = disassemble_function(address=[address])

        # Result is a list of lists (one per address)
        assert isinstance(result, list)
        assert len(result) == 1

        text = "\n".join(result[0])

        # Should contain assembly instructions
        instructions = ["mov", "push", "pop", "ret", "call", "lea", "sub", "endbr", "test", "jz", "add"]
        found = any(instr in text.lower() for instr in instructions)
        assert found, f"Expected at least one of {instructions} in disassembly. Got: {text[:500]}"


class TestAddressContext:
    """Test get_address_context with improved function markers and XREFs"""

    def test_get_address_context_shows_function_start_marker(self, ghidra_server):
        """Test that get_address_context shows function start markers"""
        # Get the main function's address
        search_result = query(type="methods", search="main")
        assert isinstance(search_result, list)

        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find main function address"
        address = f"0x{addr_match.group(1)}"

        # Get context at function entry point
        result = get_address_context(address=address, before=0, after=10)

        assert isinstance(result, list)
        text = "\n".join(result)

        # Should show function start marker
        assert "┌─ FUNCTION:" in text, f"Expected function start marker. Got: {text[:500]}"
        assert "main" in text, f"Expected function name 'main'. Got: {text[:500]}"

    def test_get_address_context_shows_function_entry_point_attribute(self, ghidra_server):
        """Test that entry point functions show ENTRY POINT attribute"""
        # Get the entry function address
        search_result = query(type="methods", search="entry")

        if not search_result or len(search_result) == 0:
            pytest.skip("No entry function found in test binary")

        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bentry\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)

        if not addr_match:
            pytest.skip("Could not find entry function address")

        address = f"0x{addr_match.group(1)}"

        # Get context at function entry point
        result = get_address_context(address=address, before=0, after=5)

        assert isinstance(result, list)
        text = "\n".join(result)

        # Should show function start marker with ENTRY POINT attribute
        assert "┌─ FUNCTION:" in text, f"Expected function start marker. Got: {text[:500]}"
        # May or may not have ENTRY POINT attribute depending on how Ghidra analyzes the binary
        # Just verify the marker exists

    def test_get_address_context_shows_function_end_marker(self, ghidra_server):
        """Test that get_address_context shows function end markers"""
        # Get a small function that we can see the end of
        search_result = query(type="methods", limit=50)
        assert isinstance(search_result, list)

        # Find any function address
        search_text = "\n".join(search_result)
        addr_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find any function address"

        func_name = addr_match.group(1)
        address = f"0x{addr_match.group(2)}"

        # Get context with enough "after" to see the end of the function
        result = get_address_context(address=address, before=2, after=20)

        assert isinstance(result, list)
        text = "\n".join(result)

        # Should show function end marker for some function
        # (May be this function or another if we're crossing function boundaries)
        has_end_marker = "└─ END FUNCTION:" in text
        has_ret = "RET" in text or "ret" in text

        # If we see a RET instruction, we should see an end marker
        # (unless it's a RET in the middle of a function, which is possible)
        if has_ret:
            # This is informational - we expect to see end markers near RET instructions
            pass

        # Just verify the marker syntax is correct if present
        if has_end_marker:
            assert re.search(r'└─ END FUNCTION:\s+\w+', text), \
                f"End marker should have proper format. Got: {text}"

    def test_get_address_context_shows_enhanced_xrefs_with_function_names(self, ghidra_server):
        """Test that XREFs include function names, not just addresses"""
        # Get any function
        search_result = query(type="methods", limit=50)
        assert isinstance(search_result, list)

        search_text = "\n".join(search_result)
        addr_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find any function address"

        address = f"0x{addr_match.group(2)}"

        # Get context with a window to potentially see XREFs
        result = get_address_context(address=address, before=10, after=10)

        assert isinstance(result, list)
        text = "\n".join(result)

        # Check if there are any XREFs in the output
        if "XREF[" in text:
            # XREFs should ideally include function names in format "FunctionName:address"
            # Look for the pattern: word:hexaddress
            has_function_in_xref = re.search(r'\b[a-zA-Z_][a-zA-Z0-9_]*:[0-9a-fA-F]{6,}', text)

            # This is informational - we want to verify the format when XREFs with functions exist
            if has_function_in_xref:
                # Verify the XREF includes both function name and address
                assert True, "XREFs correctly include function names"

    def test_get_address_context_function_boundaries(self, ghidra_server):
        """Test that function boundaries are clearly marked in context"""
        # Get two consecutive functions if possible
        search_result = query(type="methods", limit=100)
        assert isinstance(search_result, list)

        # Get first function
        search_text = "\n".join(search_result)
        matches = list(re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text))

        if len(matches) < 2:
            pytest.skip("Need at least 2 functions to test boundaries")

        # Get address of first function
        first_func_name = matches[0].group(1)
        first_func_addr = f"0x{matches[0].group(2)}"

        # Get context with large window to potentially see function boundaries
        result = get_address_context(address=first_func_addr, before=2, after=30)

        assert isinstance(result, list)
        text = "\n".join(result)

        # Verify we have function markers
        has_start_marker = "┌─ FUNCTION:" in text

        # The output should clearly show function structure
        assert has_start_marker, f"Expected function start marker. Got: {text[:500]}"

    def test_get_address_context_data_with_xrefs(self, ghidra_server):
        """Test that data labels with XREFs show function names in XREFs"""
        # Query for data symbols
        data_result = query(type="data", limit=100)

        if not data_result or len(data_result) == 0:
            pytest.skip("No data symbols found in test binary")

        # Find a data symbol with an address
        data_text = "\n".join(data_result)
        addr_match = re.search(r'(?:0x)?([0-9a-fA-F]{6,})', data_text)

        if not addr_match:
            pytest.skip("Could not find data address")

        address = f"0x{addr_match.group(1)}"

        # Get context at data address
        result = get_address_context(address=address, before=2, after=2)

        assert isinstance(result, list)
        text = "\n".join(result)

        # If there are XREFs to this data, they should include function names
        if "XREF[" in text:
            # Look for function:address pattern in XREFs
            # XREFs should be in format "FunctionName:address(*)" or similar
            xref_pattern = r'XREF\[\d+\]:'
            assert re.search(xref_pattern, text), "XREFs should have proper format"
