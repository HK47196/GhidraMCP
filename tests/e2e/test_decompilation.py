"""End-to-end tests for decompilation operations"""

import pytest
import re
from bridge_mcp_ghidra import decompile_function, disassemble_function, query


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
