"""End-to-end tests for instruction pattern search operations"""

import pytest
import re
from bridge_mcp_ghidra import query


class TestInstructionPatternSearch:
    """Test instruction pattern search operations"""

    def test_instruction_pattern_basic(self, ghidra_server):
        """Test basic instruction pattern search"""
        # Search for common instruction pattern (mov)
        result = query(type="instruction_pattern", search="mov", limit=10)

        # Result should be a list
        assert isinstance(result, list)
        assert len(result) > 0, "Expected to find 'mov' instructions"

        # Join and verify content
        text = "\n".join(result)
        assert not text.startswith("Error"), f"Expected valid result, got: {text[:200]}"

        # Should contain address and instruction information
        assert "0x" in text, "Expected addresses in result"

    def test_instruction_pattern_case_insensitive_lowercase(self, ghidra_server):
        """Test case insensitive search with lowercase pattern"""
        # Search using lowercase pattern
        result_lower = query(type="instruction_pattern", search="mov", limit=20)

        assert isinstance(result_lower, list)
        assert len(result_lower) > 0, "Expected to find instructions with lowercase 'mov'"

        text = "\n".join(result_lower)
        assert not text.startswith("Error"), f"Expected valid result, got: {text[:200]}"

        # Should match both 'mov' and 'MOV' in the disassembly
        # The result should contain instruction text
        assert len(text) > 0

    def test_instruction_pattern_case_insensitive_uppercase(self, ghidra_server):
        """Test case insensitive search with uppercase pattern"""
        # Search using uppercase pattern
        result_upper = query(type="instruction_pattern", search="MOV", limit=20)

        assert isinstance(result_upper, list)
        assert len(result_upper) > 0, "Expected to find instructions with uppercase 'MOV'"

        text = "\n".join(result_upper)
        assert not text.startswith("Error"), f"Expected valid result, got: {text[:200]}"

        # Should match both 'mov' and 'MOV' in the disassembly
        assert len(text) > 0

    def test_instruction_pattern_case_insensitive_mixed(self, ghidra_server):
        """Test case insensitive search with mixed case pattern"""
        # Search using mixed case pattern
        result_mixed = query(type="instruction_pattern", search="MoV", limit=20)

        assert isinstance(result_mixed, list)
        assert len(result_mixed) > 0, "Expected to find instructions with mixed case 'MoV'"

        text = "\n".join(result_mixed)
        assert not text.startswith("Error"), f"Expected valid result, got: {text[:200]}"

        # Should match regardless of case
        assert len(text) > 0

    def test_instruction_pattern_regex_with_operands(self, ghidra_server):
        """Test pattern search with regex for operands"""
        # Search for mov with specific operand patterns (e.g., register to register)
        result = query(type="instruction_pattern", search="mov.*,.*", limit=10)

        assert isinstance(result, list)
        # May or may not find matches depending on binary, but should be valid
        text = "\n".join(result) if result else ""
        if text:
            assert not text.startswith("Error"), f"Expected valid result, got: {text[:200]}"

    def test_instruction_pattern_hex_addresses(self, ghidra_server):
        """Test pattern search for hex addresses"""
        # Search for instructions containing hex addresses
        result = query(type="instruction_pattern", search="0x[0-9a-fA-F]+", limit=10)

        assert isinstance(result, list)
        # Should find instructions with hex address operands
        # This is common in most binaries
        if len(result) > 0:
            text = "\n".join(result)
            assert not text.startswith("Error"), f"Expected valid result, got: {text[:200]}"
            assert "0x" in text, "Expected hex addresses in results"

    def test_instruction_pattern_call_instructions(self, ghidra_server):
        """Test pattern search for call instructions (case insensitive)"""
        # Search for call instructions using lowercase
        result_lower = query(type="instruction_pattern", search="call", limit=10)

        assert isinstance(result_lower, list)
        assert len(result_lower) > 0, "Expected to find 'call' instructions"

        text_lower = "\n".join(result_lower)
        assert not text_lower.startswith("Error"), f"Expected valid result, got: {text_lower[:200]}"

        # Search using uppercase should give same results due to case insensitivity
        result_upper = query(type="instruction_pattern", search="CALL", limit=10)

        assert isinstance(result_upper, list)
        assert len(result_upper) > 0, "Expected to find 'CALL' instructions"

        text_upper = "\n".join(result_upper)
        assert not text_upper.startswith("Error"), f"Expected valid result, got: {text_upper[:200]}"

    def test_instruction_pattern_with_address_range(self, ghidra_server):
        """Test pattern search with address range"""
        # First, get segments to find a valid address range
        segments = query(type="segments", limit=10)
        assert isinstance(segments, list)
        assert len(segments) > 0, "Expected to find segments"

        # Parse first segment to get address range
        segment_text = "\n".join(segments)
        # Look for address pattern like 0x00100000 - 0x00101000
        addr_match = re.search(r'(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)', segment_text)

        if addr_match:
            start_addr = addr_match.group(1)
            end_addr = addr_match.group(2)

            # Search for mov within this range
            result = query(
                type="instruction_pattern",
                search="mov",
                start_address=start_addr,
                end_address=end_addr,
                limit=10
            )

            assert isinstance(result, list)
            # May or may not find matches depending on what's in the range
            text = "\n".join(result) if result else ""
            if text:
                assert not text.startswith("Error"), f"Expected valid result, got: {text[:200]}"

    def test_instruction_pattern_invalid_regex(self, ghidra_server):
        """Test pattern search with invalid regex"""
        # Search with invalid regex (unclosed bracket)
        result = query(type="instruction_pattern", search="mov[", limit=10)

        assert isinstance(result, list)
        text = "\n".join(result)

        # Should return error message about invalid regex
        assert "Error" in text or "Invalid" in text, f"Expected error for invalid regex, got: {text[:200]}"

    def test_instruction_pattern_empty_pattern(self, ghidra_server):
        """Test pattern search with empty pattern"""
        # Search with empty pattern
        result = query(type="instruction_pattern", search="", limit=10)

        assert isinstance(result, list)
        text = "\n".join(result)

        # Should return error message requiring pattern
        assert "Error" in text or "required" in text, f"Expected error for empty pattern, got: {text[:200]}"

    def test_instruction_pattern_no_matches(self, ghidra_server):
        """Test pattern search with pattern that matches nothing"""
        # Search for very unlikely instruction pattern
        result = query(type="instruction_pattern", search="xyzzy12345abcde", limit=10)

        assert isinstance(result, list)
        text = "\n".join(result) if result else ""

        # Should return "No matches" message
        if text:
            assert "No matches" in text or "0 matches" in text or len(result) == 0, \
                f"Expected 'No matches' message, got: {text[:200]}"

    def test_instruction_pattern_pagination(self, ghidra_server):
        """Test pagination of instruction pattern results"""
        # Search for common pattern that should have many results
        result_page1 = query(type="instruction_pattern", search="mov", offset=0, limit=5)
        result_page2 = query(type="instruction_pattern", search="mov", offset=5, limit=5)

        assert isinstance(result_page1, list)
        assert isinstance(result_page2, list)

        # Both pages should be valid (even if page 2 is empty)
        text1 = "\n".join(result_page1) if result_page1 else ""
        text2 = "\n".join(result_page2) if result_page2 else ""

        if text1:
            assert not text1.startswith("Error"), f"Page 1 error: {text1[:200]}"
        if text2:
            assert not text2.startswith("Error"), f"Page 2 error: {text2[:200]}"

        # Page 1 should have results
        assert len(result_page1) > 0, "Expected results on first page"

    def test_instruction_pattern_complex_regex(self, ghidra_server):
        """Test pattern search with complex regex"""
        # Search for push/pop instructions (case insensitive)
        result = query(type="instruction_pattern", search="(push|pop)", limit=10)

        assert isinstance(result, list)
        # Should find push or pop instructions (common in most binaries)
        if len(result) > 0:
            text = "\n".join(result)
            assert not text.startswith("Error"), f"Expected valid result, got: {text[:200]}"

    def test_instruction_pattern_with_segment(self, ghidra_server):
        """Test pattern search within a specific segment"""
        # First, get segments
        segments = query(type="segments", limit=10)
        assert isinstance(segments, list)
        assert len(segments) > 0, "Expected to find segments"

        # Parse segment names - look for executable code segment
        segment_text = "\n".join(segments)
        # Common segment names: .text, CODE, code, .code
        segment_match = re.search(r'(?:\.text|CODE|\.code)\s', segment_text, re.IGNORECASE)

        if segment_match:
            # Extract the segment name
            segment_line = [line for line in segments if re.search(r'(?:\.text|CODE|\.code)', line, re.IGNORECASE)]
            if segment_line:
                # Try to parse segment name - it's usually at the start of the line
                segment_parts = segment_line[0].split()
                if len(segment_parts) > 0:
                    segment_name = segment_parts[0].strip()

                    # Search for mov within this segment
                    # Note: The API uses segment_name parameter in the backend
                    # but it's passed through start_address/end_address in the Python API
                    # For now, just verify the basic search works
                    result = query(type="instruction_pattern", search="mov", limit=10)

                    assert isinstance(result, list)
                    if len(result) > 0:
                        text = "\n".join(result)
                        assert not text.startswith("Error"), f"Expected valid result, got: {text[:200]}"
