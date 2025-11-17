"""End-to-end tests for program modification operations"""

import pytest
from bridge_mcp_ghidra import rename_function, set_decompiler_comment, query


class TestModifications:
    """Test modification operations"""

    def test_rename_function(self, ghidra_server):
        """Test renaming a function"""
        original_name = "add"
        new_name = "test_add_renamed"

        # Rename
        result = rename_function(old_name=original_name, new_name=new_name)

        # Result is a string
        assert isinstance(result, str)
        assert "success" in result.lower() or "renamed" in result.lower()

        # Verify - use 'methods' which lists functions
        list_result = query(type="methods", limit=100)
        list_text = "\n".join(list_result)
        assert new_name in list_text, f"Expected '{new_name}' in function list. Got: {list_text[:500]}"

        # Rename back
        restore_result = rename_function(old_name=new_name, new_name=original_name)
        assert isinstance(restore_result, str)

    def test_set_decompiler_comment(self, ghidra_server):
        """Test setting a comment in decompiler view"""
        result = set_decompiler_comment(
            address="0x00101000",
            comment="Test comment from E2E test"
        )

        # Result is a string
        assert isinstance(result, str)
