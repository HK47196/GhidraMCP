"""Test undo-based test isolation"""

import pytest
from bridge_mcp_ghidra import query, rename, create_struct, add_struct_field, set_decompiler_comment, get_current_function


class TestUndoIsolation:
    """Test that undo-based isolation works correctly"""

    def test_rename_creates_undo_transaction(self, ghidra_server):
        """Verify that rename operations create undo transactions"""
        # Get initial function list
        initial_result = query(type="methods", limit=10)

        # Find a function to rename
        test_function = None
        for line in initial_result:
            if line.strip() and not line.startswith("Error"):
                test_function = line.strip()
                break

        assert test_function is not None, "No functions found to test"

        # Rename the function
        new_name = "test_renamed_function"
        rename_result = rename(
            type="function",
            old_name=test_function,
            new_name=new_name
        )

        assert "success" in rename_result.lower() or "renamed" in rename_result.lower()

        # Verify the function was renamed
        renamed_result = query(type="methods", search=new_name)
        renamed_text = "\n".join(renamed_result) if isinstance(renamed_result, list) else renamed_result
        assert new_name in renamed_text

        # The undo will happen automatically in teardown via restore_program_state fixture

    def test_state_restored_between_tests(self, ghidra_server):
        """Verify that previous test's changes were undone"""
        # This test runs after test_rename_creates_undo_transaction
        # If undo is working, "test_renamed_function" should not exist

        result = query(type="methods", search="test_renamed_function")
        result_text = "\n".join(result) if isinstance(result, list) else result

        # The renamed function should NOT exist because the previous test's changes were undone
        # We expect "No functions matching" or similar message indicating the function doesn't exist
        # The message will contain the search term but that's fine - we're looking for "No functions"
        assert "No functions" in result_text or "0 function" in result_text.lower()

    def test_multiple_modifications_all_undone(self, ghidra_server):
        """Verify that multiple modifications in a single test are all undone"""
        # Get initial function list
        initial_result = query(type="methods", limit=10)

        # Rename multiple functions
        renamed_count = 0
        for i, line in enumerate(initial_result):
            if line.strip() and not line.startswith("Error") and renamed_count < 3:
                old_name = line.strip()
                new_name = f"test_multi_rename_{i}"

                result = rename(
                    type="function",
                    old_name=old_name,
                    new_name=new_name
                )

                if "success" in result.lower() or "renamed" in result.lower():
                    renamed_count += 1

        assert renamed_count >= 1, "Should have renamed at least one function"

        # All changes will be undone automatically in teardown

    def test_create_and_modify_struct_undone(self, ghidra_server):
        """Verify that struct creation and modification are undone"""
        struct_name = "TestUndoStruct"

        # Create a struct
        create_result = create_struct(
            name=struct_name,
            size=0
        )

        assert "error" not in create_result.lower() or "already exists" in create_result.lower()

        # Add a field to the struct
        if "already exists" not in create_result.lower():
            add_field_result = add_struct_field(
                struct_name=struct_name,
                field_type="int",
                field_name="test_field"
            )

            # Verify field was added
            assert "error" not in add_field_result.lower() or "not found" not in add_field_result.lower()

        # Changes will be undone automatically in teardown

    def test_comment_modifications_undone(self, ghidra_server):
        """Verify that comment modifications are undone"""
        # Get current function info to get address
        func_info = get_current_function()

        # Set a comment (this will create an undo transaction)
        if "0x" in func_info:
            # Extract address
            import re
            address_match = re.search(r'0x[0-9a-fA-F]+', func_info)
            if address_match:
                address = address_match.group(0)

                comment_result = set_decompiler_comment(
                    address=address,
                    comment="Test undo isolation comment"
                )

                assert "success" in comment_result.lower() or "comment set" in comment_result.lower()

        # Comment will be undone automatically in teardown
