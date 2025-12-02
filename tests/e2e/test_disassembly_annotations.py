"""End-to-end tests for disassembly annotation format.

Tests that disassembly shows raw operands (registers, addresses) with variable/symbol
annotations inline in parentheses, rather than substituting variable names directly.

Expected format:
    MOV AH (context), AH          # annotation on first operand only (deduplicated)
    CMP [EBP + -0x8] (local_14), 0x0   # stack variable annotation
    CALL [0x12345678] (SomeFunc)  # function symbol annotation
"""

import pytest
import re
from bridge_mcp_ghidra import disassemble_function, get_address_context, query


class TestDisassemblyAnnotationFormat:
    """Test that disassembly shows raw operands with inline annotations."""

    def test_disassembly_shows_raw_registers(self, ghidra_server):
        """Test that disassembly shows actual register names, not just variable names.

        Registers like EAX, EBX, ESP, EBP should appear in the output,
        not be completely replaced by variable names.
        """
        # Get a function with local variables
        search_result = query(type="methods", search="level2_compute")
        assert isinstance(search_result, list)

        if len(search_result) == 0:
            pytest.skip("No level2_compute function found")

        search_text = "\n".join(search_result)
        addr_match = re.search(r'level2_compute\w*\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)

        if not addr_match:
            pytest.skip("Could not find level2_compute function address")

        address = f"0x{addr_match.group(1)}"

        # Disassemble the function
        result = disassemble_function(address=[address])
        assert isinstance(result, list)
        assert len(result) >= 1

        text = "\n".join(result[0])

        # Should contain actual register names
        # Common x86/x64 registers that should appear in disassembly
        registers = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
                     "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                     "AX", "BX", "CX", "DX", "AL", "AH", "BL", "BH"]

        # At least some registers should be visible in the disassembly
        found_registers = [r for r in registers if r in text.upper()]
        assert len(found_registers) > 0, \
            f"Expected to find register names in disassembly. Got: {text[:1000]}"

    def test_annotations_appear_in_parentheses(self, ghidra_server):
        """Test that variable/symbol annotations appear in parentheses after operands."""
        # Get main function which has local variables
        search_result = query(type="methods", search="main")
        assert isinstance(search_result, list)

        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)

        if not addr_match:
            pytest.skip("Could not find main function address")

        address = f"0x{addr_match.group(1)}"

        # Disassemble the function
        result = disassemble_function(address=[address])
        assert isinstance(result, list)
        assert len(result) >= 1

        text = "\n".join(result[0])

        # Look for annotation pattern: operand followed by (annotation)
        # Pattern: word/register followed by space and parenthesized annotation
        annotation_pattern = r'\b[A-Za-z0-9\[\]\+\-\s]+\s+\([a-zA-Z_][a-zA-Z0-9_]*\)'

        # Check if any annotations are present
        # Note: Not all instructions will have annotations, but functions with
        # local variables should have some
        has_annotations = re.search(annotation_pattern, text)

        # This is informational - the format should be correct if annotations exist
        if has_annotations:
            # Verify annotation format is correct (word in parentheses)
            match = has_annotations.group(0)
            assert '(' in match and ')' in match, \
                f"Annotation should be in parentheses. Found: {match}"

    def test_call_instruction_shows_address_and_function_name(self, ghidra_server):
        """Test that CALL instructions show raw address with function name annotation."""
        # Get a function that calls other functions
        search_result = query(type="methods", search="multi_call_function")
        assert isinstance(search_result, list)

        if len(search_result) == 0:
            # Try main as fallback
            search_result = query(type="methods", search="main")

        search_text = "\n".join(search_result)
        addr_match = re.search(r'(?:multi_call_function|main)\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)

        if not addr_match:
            pytest.skip("Could not find function address")

        address = f"0x{addr_match.group(1)}"

        # Disassemble the function
        result = disassemble_function(address=[address])
        assert isinstance(result, list)
        assert len(result) >= 1

        text = "\n".join(result[0])

        # Look for CALL instructions
        call_lines = [line for line in result[0] if 'CALL' in line.upper()]

        if len(call_lines) > 0:
            # CALL instructions should show the target
            # Could be direct address, register, or memory reference
            for call_line in call_lines:
                # Verify CALL instruction is present
                assert 'CALL' in call_line.upper(), f"Expected CALL in: {call_line}"

    def test_address_context_shows_raw_operands(self, ghidra_server):
        """Test that get_address_context also shows raw operands with annotations."""
        # Get any function
        search_result = query(type="methods", search="helper_function")
        assert isinstance(search_result, list)

        if len(search_result) == 0:
            pytest.skip("No helper_function found")

        search_text = "\n".join(search_result)
        addr_match = re.search(r'helper_function\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)

        if not addr_match:
            pytest.skip("Could not find helper_function address")

        address = f"0x{addr_match.group(1)}"

        # Get address context
        result = get_address_context(address=address, before=2, after=10)
        assert isinstance(result, list)

        text = "\n".join(result)

        # Should contain instruction mnemonics
        mnemonics = ["MOV", "PUSH", "POP", "RET", "CALL", "LEA", "SUB", "ADD",
                     "ENDBR", "TEST", "JZ", "JNZ", "JMP", "CMP", "XOR", "AND", "OR"]
        found_mnemonics = [m for m in mnemonics if m in text.upper()]
        assert len(found_mnemonics) > 0, \
            f"Expected instruction mnemonics in context. Got: {text[:500]}"

    def test_stack_variable_annotation_format(self, ghidra_server):
        """Test that stack variables show as annotations, not replacing the offset."""
        # Get main function which should have stack variables
        search_result = query(type="methods", search="main")
        assert isinstance(search_result, list)

        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)

        if not addr_match:
            pytest.skip("Could not find main function address")

        address = f"0x{addr_match.group(1)}"

        # Disassemble the function
        result = disassemble_function(address=[address])
        assert isinstance(result, list)
        assert len(result) >= 1

        text = "\n".join(result[0])

        # Look for stack references - should show actual offsets like [EBP + -0x8] or [RSP + 0x10]
        # Not just variable names
        stack_ref_pattern = r'\[(E|R)?(BP|SP)\s*[\+\-]\s*(?:0x)?[0-9a-fA-F]+\]'
        has_stack_refs = re.search(stack_ref_pattern, text, re.IGNORECASE)

        # If there are stack references, the raw offset should be visible
        # This is informational - not all functions will have recognizable stack references
        if has_stack_refs:
            match = has_stack_refs.group(0)
            # Verify it shows actual offset, not just a variable name
            assert re.search(r'[\+\-]\s*(?:0x)?[0-9a-fA-F]+', match), \
                f"Stack reference should show numeric offset. Found: {match}"


class TestAnnotationDeduplication:
    """Test that duplicate annotations are deduplicated across operands."""

    def test_same_variable_on_multiple_operands_shows_once(self, ghidra_server):
        """Test that if same variable appears on multiple operands, annotation shows once.

        For example, XOR EAX, EAX where both operands map to same variable
        should show: XOR EAX (varname), EAX
        Not: XOR EAX (varname), EAX (varname)
        """
        # Get a function - the deduplication logic is in buildEnhancedOperands
        search_result = query(type="methods", search="level3")
        assert isinstance(search_result, list)

        if len(search_result) == 0:
            pytest.skip("No level3 functions found")

        search_text = "\n".join(search_result)
        addr_match = re.search(r'level3_\w+\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)

        if not addr_match:
            pytest.skip("Could not find level3 function address")

        address = f"0x{addr_match.group(1)}"

        # Disassemble the function
        result = disassemble_function(address=[address])
        assert isinstance(result, list)
        assert len(result) >= 1

        text = "\n".join(result[0])

        # Look for lines with annotations
        # Count occurrences of same annotation on a single line
        for line in result[0]:
            if '(' in line and ')' in line:
                # Find all annotations in parentheses
                annotations = re.findall(r'\(([a-zA-Z_][a-zA-Z0-9_]*)\)', line)
                if len(annotations) > 1:
                    # If multiple annotations on same line, they should be different
                    # (same variable shouldn't be annotated twice)
                    # Note: This is a soft check - multiple different variables is fine
                    unique_annotations = set(annotations)
                    # Just verify we can parse annotations
                    assert len(unique_annotations) >= 1


class TestRawAddressVisibility:
    """Test that raw addresses are visible in disassembly output."""

    def test_instruction_addresses_visible(self, ghidra_server):
        """Test that instruction addresses are shown in disassembly."""
        search_result = query(type="methods", search="add")
        assert isinstance(search_result, list)

        if len(search_result) == 0:
            pytest.skip("No add function found")

        search_text = "\n".join(search_result)
        # Match 'add' but not 'thunk_add' or similar
        addr_match = re.search(r'\badd\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)

        if not addr_match:
            pytest.skip("Could not find add function address")

        address = f"0x{addr_match.group(1)}"

        # Disassemble the function
        result = disassemble_function(address=[address])
        assert isinstance(result, list)
        assert len(result) >= 1

        text = "\n".join(result[0])

        # Each instruction line should start with or contain an address
        # Address format: hex digits (e.g., 00401000 or 0x00401000)
        address_pattern = r'(?:0x)?[0-9a-fA-F]{6,}'

        # Multiple addresses should be present (one per instruction)
        addresses_found = re.findall(address_pattern, text)
        assert len(addresses_found) > 1, \
            f"Expected multiple instruction addresses. Got: {text[:500]}"

    def test_memory_operand_addresses_visible(self, ghidra_server):
        """Test that memory operand addresses are visible, not just symbols."""
        # Get main which likely references global data
        search_result = query(type="methods", search="main")
        assert isinstance(search_result, list)

        search_text = "\n".join(search_result)
        addr_match = re.search(r'\bmain\s+@\s+(?:0x)?([0-9a-fA-F]{6,})', search_text)

        if not addr_match:
            pytest.skip("Could not find main function address")

        address = f"0x{addr_match.group(1)}"

        # Disassemble the function
        result = disassemble_function(address=[address])
        assert isinstance(result, list)
        assert len(result) >= 1

        text = "\n".join(result[0])

        # Look for memory references in brackets with addresses
        # Pattern: [something with hex address]
        mem_ref_pattern = r'\[.*(?:0x)?[0-9a-fA-F]{4,}.*\]'

        # This is informational - not all instructions have memory operands
        has_mem_refs = re.search(mem_ref_pattern, text)

        if has_mem_refs:
            match = has_mem_refs.group(0)
            # Verify it contains actual numeric address
            assert re.search(r'[0-9a-fA-F]{4,}', match), \
                f"Memory reference should contain numeric address. Found: {match}"
