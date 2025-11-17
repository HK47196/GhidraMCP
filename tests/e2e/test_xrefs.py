"""End-to-end tests for cross-reference (XRef) operations"""

import pytest
import re
from bridge_mcp_ghidra import (
    get_xrefs_to,
    get_xrefs_from,
    get_function_xrefs,
    get_function_callees,
    query
)


class TestXRefOperations:
    """Test cross-reference (XRef) operations"""

    def test_get_xrefs_to_basic(self, ghidra_server):
        """Test getting references to an address (basic mode)"""
        # First, find the main function to get a valid address
        search_result = query(type="methods", search="main")
        assert isinstance(search_result, list)

        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, f"Could not find 'main' function address in: {search_text[:200]}"

        address = f"0x{addr_match.group(1)}"

        # Get xrefs to main (basic - no instruction text)
        result = get_xrefs_to(address=address, limit=10)

        # Result should be a list
        assert isinstance(result, list)

        # Should have at least one reference (e.g., from _start or __libc_start_main)
        assert len(result) > 0, f"Expected at least one xref to main, got: {result}"

        # Join and verify it contains XRef information
        # XRef results may include descriptive text like "From Entry Point [EXTERNAL]"
        # or address information with "0x" or "XREF"
        text = "\n".join(result)
        # Just verify we got non-empty meaningful result (not an error)
        assert len(text) > 0 and not text.startswith("Error"), f"Expected valid xref result, got: {text[:200]}"

    def test_get_xrefs_to_with_instruction(self, ghidra_server):
        """Test getting references with instruction display"""
        # Find main function address
        search_result = query(type="methods", search="main")
        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find 'main' function address"

        address = f"0x{addr_match.group(1)}"

        # Get xrefs with instruction display enabled (True means show instruction only)
        result = get_xrefs_to(address=address, limit=10, include_instruction=True)

        assert isinstance(result, list)
        assert len(result) > 0, "Expected at least one xref to main"

        text = "\n".join(result)

        # Should contain instruction mnemonics like call, jmp, mov, etc.
        common_instructions = ["call", "jmp", "mov", "lea", "push", "pop"]
        has_instruction = any(instr in text.lower() for instr in common_instructions)
        assert has_instruction, f"Expected instruction text in xrefs. Got: {text[:300]}"

    def test_get_xrefs_to_with_context(self, ghidra_server):
        """Test getting references with instruction context (before/after lines)"""
        # Find main function address
        search_result = query(type="methods", search="main")
        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find 'main' function address"

        address = f"0x{addr_match.group(1)}"

        # Get xrefs with 2 lines of context (before and after)
        result = get_xrefs_to(address=address, limit=10, include_instruction=2)

        assert isinstance(result, list)
        assert len(result) > 0, "Expected at least one xref to main"

        text = "\n".join(result)

        # With context, should have multiple lines (context before + instruction + context after)
        # Should contain instruction mnemonics
        common_instructions = ["call", "jmp", "mov", "lea", "push", "pop", "sub", "add", "xor"]
        has_instruction = any(instr in text.lower() for instr in common_instructions)
        assert has_instruction, f"Expected instruction text with context. Got: {text[:500]}"

    def test_get_xrefs_from_basic(self, ghidra_server):
        """Test getting references from an address"""
        # Find main function address
        search_result = query(type="methods", search="main")
        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find 'main' function address"

        address = f"0x{addr_match.group(1)}"

        # Get xrefs from main (functions/data that main references)
        result = get_xrefs_from(address=address, limit=20)

        assert isinstance(result, list)
        # Main function likely calls other functions or references data
        # So we should have some xrefs from it (though this may vary by binary)
        # Let's just verify the call succeeds and returns valid data
        text = "\n".join(result) if result else ""
        # Even if empty, it should be a valid response (not an error)
        if text:
            assert not text.startswith("Error"), f"Got error: {text}"

    def test_get_xrefs_from_with_instruction(self, ghidra_server):
        """Test getting references from an address with instruction display"""
        # Find main function address
        search_result = query(type="methods", search="main")
        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find 'main' function address"

        address = f"0x{addr_match.group(1)}"

        # Get xrefs from main with instruction display
        result = get_xrefs_from(address=address, limit=20, include_instruction=True)

        assert isinstance(result, list)
        # Verify it's a valid response
        text = "\n".join(result) if result else ""
        if text:
            assert not text.startswith("Error"), f"Got error: {text}"

    def test_get_function_xrefs_basic(self, ghidra_server):
        """Test getting references to a function by name"""
        # Use a common function that should exist and be called
        # In most C programs, 'main' is called from _start or similar
        result = get_function_xrefs(name="main", limit=10)

        assert isinstance(result, list)
        # Should have at least one reference to main
        assert len(result) > 0, f"Expected at least one xref to 'main', got: {result}"

        text = "\n".join(result)
        # XRef results may include descriptive text or address information
        # Just verify we got non-empty meaningful result (not an error)
        assert len(text) > 0 and not text.startswith("Error"), f"Expected valid xref result, got: {text[:200]}"

    def test_get_function_xrefs_with_instruction(self, ghidra_server):
        """Test getting function references with instruction display"""
        # Get xrefs to main with instruction text
        result = get_function_xrefs(name="main", limit=10, include_instruction=True)

        assert isinstance(result, list)
        assert len(result) > 0, "Expected at least one xref to 'main'"

        text = "\n".join(result)

        # Should contain instruction mnemonics (likely 'call' for function references)
        common_call_instructions = ["call", "jmp", "bl", "b"]  # Different architectures
        has_call = any(instr in text.lower() for instr in common_call_instructions)
        assert has_call, f"Expected call instruction in function xrefs. Got: {text[:300]}"

    def test_get_function_xrefs_with_context(self, ghidra_server):
        """Test getting function references with context lines"""
        # Get xrefs to main with 1 line of context
        result = get_function_xrefs(name="main", limit=10, include_instruction=1)

        assert isinstance(result, list)
        assert len(result) > 0, "Expected at least one xref to 'main'"

        text = "\n".join(result)

        # With context, should have more information
        assert len(text) > 0, "Expected non-empty result with context"
        # Should not be an error
        assert not text.startswith("Error"), f"Got error: {text}"

    def test_xrefs_pagination(self, ghidra_server):
        """Test pagination of XRef results"""
        # Find main function address
        search_result = query(type="methods", search="main")
        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find 'main' function address"

        address = f"0x{addr_match.group(1)}"

        # Get first page
        result_page1 = get_xrefs_to(address=address, offset=0, limit=1)
        assert isinstance(result_page1, list)

        # Get second page
        result_page2 = get_xrefs_to(address=address, offset=1, limit=1)
        assert isinstance(result_page2, list)

        # Both pages should be valid responses (even if one is empty)
        # This tests that pagination parameters work correctly
        text1 = "\n".join(result_page1) if result_page1 else ""
        text2 = "\n".join(result_page2) if result_page2 else ""

        if text1:
            assert not text1.startswith("Error"), f"Page 1 error: {text1}"
        if text2:
            assert not text2.startswith("Error"), f"Page 2 error: {text2}"

    def test_xrefs_nonexistent_function(self, ghidra_server):
        """Test getting XRefs for a non-existent function"""
        # Try to get xrefs for a function that doesn't exist
        result = get_function_xrefs(name="nonexistent_function_12345", limit=10)

        assert isinstance(result, list)
        # Should return empty list or error message
        text = "\n".join(result) if result else ""
        # Either empty or contains an error/not found message
        if text:
            # Should indicate function not found or no xrefs
            # API may return messages like "No references found" or "not found"
            assert (
                "not found" in text.lower() or
                "no references" in text.lower() or
                "error" in text.lower() or
                len(result) == 0
            ), f"Expected 'not found' or 'no references' message, got: {text[:200]}"

    def test_get_function_callees_basic(self, ghidra_server):
        """Test getting function call graph with depth 1"""
        # Find main function address
        search_result = query(type="methods", search="main")
        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find 'main' function address"

        address = f"0x{addr_match.group(1)}"

        # Get callees with depth 1 (immediate calls only)
        result = get_function_callees(address=address, depth=1)

        assert isinstance(result, str)
        # Should contain the function name and address
        assert "main" in result or address.replace("0x", "") in result

        # Should not be an error
        assert not result.startswith("Error"), f"Got error: {result}"

        # If main calls any functions, the result should contain call indicators
        # like tree characters (├, └, │) or function addresses
        if len(result) > 100:  # If there are callees
            # Should contain tree formatting
            has_tree_chars = any(char in result for char in ["├", "└", "│"])
            # Or at least multiple lines indicating a call tree
            has_multiple_lines = "\n" in result or len(result.split()) > 5
            assert has_tree_chars or has_multiple_lines, f"Expected tree structure in result: {result[:200]}"

    def test_get_function_callees_depth_2(self, ghidra_server):
        """Test getting function call graph with depth 2"""
        # Find main function address
        search_result = query(type="methods", search="main")
        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find 'main' function address"

        address = f"0x{addr_match.group(1)}"

        # Get callees with depth 2 (show calls and their calls)
        result = get_function_callees(address=address, depth=2)

        assert isinstance(result, str)
        # Should not be an error
        assert not result.startswith("Error"), f"Got error: {result}"

        # Result should be valid (contains function name or address)
        assert "main" in result or address.replace("0x", "") in result

    def test_get_function_callees_invalid_address(self, ghidra_server):
        """Test getting callees for an invalid address"""
        # Try with an address that doesn't contain a function
        result = get_function_callees(address="0x99999999", depth=1)

        assert isinstance(result, str)
        # Should return an error or "No function found" message
        assert (
            "error" in result.lower() or
            "no function" in result.lower()
        ), f"Expected error message, got: {result[:200]}"

    def test_get_function_callees_multi_level(self, ghidra_server):
        """Test multi-level call graph (depth 3)"""
        # Find level1_complex_calc which has a 3-level call hierarchy
        search_result = query(type="methods", search="level1_complex_calc")

        if not search_result or "not found" in "\n".join(search_result).lower():
            pytest.skip("level1_complex_calc function not found in binary")

        search_text = "\n".join(search_result)
        addr_match = re.search(r'level1_complex_calc\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find level1_complex_calc address"

        address = f"0x{addr_match.group(1)}"

        # Get callees with depth 3 (should show full hierarchy)
        result = get_function_callees(address=address, depth=3)

        assert isinstance(result, str)
        assert not result.startswith("Error"), f"Got error: {result}"

        # Should contain the root function
        assert "level1_complex_calc" in result or address.replace("0x", "") in result

        # Should contain tree formatting for multi-level hierarchy
        has_tree_chars = any(char in result for char in ["├", "└", "│"])
        assert has_tree_chars, f"Expected tree structure in multi-level result: {result[:300]}"

        # Should contain level 2 functions
        assert "level2_compute_a" in result or "level2_compute_b" in result, \
            f"Expected level 2 functions in result: {result[:300]}"

    def test_get_function_callees_thunk(self, ghidra_server):
        """Test call graph with thunk functions"""
        # Find thunk_add which wraps the add function
        search_result = query(type="methods", search="thunk_add")

        if not search_result or "not found" in "\n".join(search_result).lower():
            pytest.skip("thunk_add function not found in binary")

        search_text = "\n".join(search_result)
        addr_match = re.search(r'thunk_add\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find thunk_add address"

        address = f"0x{addr_match.group(1)}"

        # Get callees with depth 2 (should show thunk -> actual function)
        result = get_function_callees(address=address, depth=2)

        assert isinstance(result, str)
        assert not result.startswith("Error"), f"Got error: {result}"

        # Should contain the thunk function
        assert "thunk_add" in result or address.replace("0x", "") in result

        # Should show the call through the thunk to add
        assert "add" in result.lower(), f"Expected to see 'add' function in thunk call tree: {result[:300]}"

    def test_get_function_callees_multiple_callees(self, ghidra_server):
        """Test function with multiple direct callees"""
        # Find multi_call_function which calls add, multiply, and helper_function
        search_result = query(type="methods", search="multi_call_function")

        if not search_result or "not found" in "\n".join(search_result).lower():
            pytest.skip("multi_call_function not found in binary")

        search_text = "\n".join(search_result)
        addr_match = re.search(r'multi_call_function\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find multi_call_function address"

        address = f"0x{addr_match.group(1)}"

        # Get callees with depth 1
        result = get_function_callees(address=address, depth=1)

        assert isinstance(result, str)
        assert not result.startswith("Error"), f"Got error: {result}"

        # Should contain the root function
        assert "multi_call_function" in result or address.replace("0x", "") in result

        # Should contain tree formatting for multiple callees
        has_tree_chars = any(char in result for char in ["├", "└", "│"])
        assert has_tree_chars, f"Expected tree structure with multiple callees: {result[:300]}"

        # Count tree branch characters - should have at least 2 (for multiple callees)
        branch_count = result.count("├") + result.count("└")
        assert branch_count >= 2, f"Expected at least 2 callees, found {branch_count}: {result[:300]}"

    def test_get_function_callees_depth_comparison(self, ghidra_server):
        """Test that increasing depth shows more callees"""
        # Find level1_complex_calc for multi-level testing
        search_result = query(type="methods", search="level1_complex_calc")

        if not search_result or "not found" in "\n".join(search_result).lower():
            pytest.skip("level1_complex_calc function not found in binary")

        search_text = "\n".join(search_result)
        addr_match = re.search(r'level1_complex_calc\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)
        assert addr_match, "Could not find level1_complex_calc address"

        address = f"0x{addr_match.group(1)}"

        # Get callees with depth 1
        result_depth1 = get_function_callees(address=address, depth=1)
        # Get callees with depth 2
        result_depth2 = get_function_callees(address=address, depth=2)
        # Get callees with depth 3
        result_depth3 = get_function_callees(address=address, depth=3)

        # All should succeed
        assert not result_depth1.startswith("Error")
        assert not result_depth2.startswith("Error")
        assert not result_depth3.startswith("Error")

        # Depth 2 should have more content than depth 1 (or equal if only 1 level deep)
        # Depth 3 should have more content than depth 2 (or equal if only 2 levels deep)
        # Use line count as a proxy for tree depth
        lines_depth1 = len(result_depth1.split('\n'))
        lines_depth2 = len(result_depth2.split('\n'))
        lines_depth3 = len(result_depth3.split('\n'))

        assert lines_depth2 >= lines_depth1, \
            f"Depth 2 should have >= lines than depth 1. Depth1={lines_depth1}, Depth2={lines_depth2}"
        assert lines_depth3 >= lines_depth2, \
            f"Depth 3 should have >= lines than depth 2. Depth2={lines_depth2}, Depth3={lines_depth3}"
