"""End-to-end tests for cross-reference (XRef) operations"""

import pytest
import re
from bridge_mcp_ghidra import (
    get_xrefs_to,
    get_xrefs_from,
    get_function_xrefs,
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

        # Join and verify it contains address information
        text = "\n".join(result)
        assert "0x" in text or "XREF" in text, f"Expected address/xref info in: {text[:200]}"

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
        # Should contain address information
        assert "0x" in text or "XREF" in text, f"Expected xref info in: {text[:200]}"

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
            assert (
                "not found" in text.lower() or
                "error" in text.lower() or
                len(result) == 0
            ), f"Expected 'not found' or empty result, got: {text[:200]}"
