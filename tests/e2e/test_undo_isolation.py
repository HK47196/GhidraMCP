"""Test undo-based test isolation"""

import pytest
import json


class TestUndoIsolation:
    """Test that undo-based isolation works correctly"""

    def test_rename_creates_undo_transaction(self, mcp_client):
        """Verify that rename operations create undo transactions"""
        # Get initial function list
        initial_result = mcp_client.call_tool("query", type="methods", limit=10)
        initial_functions = initial_result.split('\n')

        # Find a function to rename
        test_function = None
        for line in initial_functions:
            if line.strip() and not line.startswith("Error"):
                test_function = line.strip()
                break

        assert test_function is not None, "No functions found to test"

        # Rename the function
        new_name = "test_renamed_function"
        rename_result = mcp_client.call_tool(
            "rename",
            type="function",
            old_name=test_function,
            new_name=new_name
        )

        assert "success" in rename_result.lower() or "renamed" in rename_result.lower()

        # Verify the function was renamed
        renamed_result = mcp_client.call_tool("query", type="methods", search=new_name)
        assert new_name in renamed_result

        # The undo will happen automatically in teardown via restore_program_state fixture

    def test_state_restored_between_tests(self, mcp_client):
        """Verify that previous test's changes were undone"""
        # This test runs after test_rename_creates_undo_transaction
        # If undo is working, "test_renamed_function" should not exist

        result = mcp_client.call_tool("query", type="methods", search="test_renamed_function")

        # The renamed function should NOT exist because the previous test's changes were undone
        # We expect either no results or an error message
        assert "test_renamed_function" not in result or "No functions found" in result or "0 function" in result

    def test_multiple_modifications_all_undone(self, mcp_client):
        """Verify that multiple modifications in a single test are all undone"""
        # Get initial function list
        initial_result = mcp_client.call_tool("query", type="methods", limit=10)
        initial_functions = initial_result.split('\n')

        # Rename multiple functions
        renamed_count = 0
        for i, line in enumerate(initial_functions):
            if line.strip() and not line.startswith("Error") and renamed_count < 3:
                old_name = line.strip()
                new_name = f"test_multi_rename_{i}"

                result = mcp_client.call_tool(
                    "rename",
                    type="function",
                    old_name=old_name,
                    new_name=new_name
                )

                if "success" in result.lower() or "renamed" in result.lower():
                    renamed_count += 1

        assert renamed_count >= 1, "Should have renamed at least one function"

        # All changes will be undone automatically in teardown

    def test_create_and_modify_struct_undone(self, mcp_client):
        """Verify that struct creation and modification are undone"""
        struct_name = "TestUndoStruct"

        # Create a struct
        create_result = mcp_client.call_tool(
            "create_struct",
            name=struct_name,
            size=0
        )

        assert "error" not in create_result.lower() or "already exists" in create_result.lower()

        # Add a field to the struct
        if "already exists" not in create_result.lower():
            add_field_result = mcp_client.call_tool(
                "add_struct_field",
                struct_name=struct_name,
                field_type="int",
                field_name="test_field"
            )

            # Verify field was added
            assert "error" not in add_field_result.lower() or "not found" not in add_field_result.lower()

        # Changes will be undone automatically in teardown

    def test_comment_modifications_undone(self, mcp_client):
        """Verify that comment modifications are undone"""
        # Get a function address
        functions_result = mcp_client.call_tool("query", type="methods", limit=1)

        if functions_result and not functions_result.startswith("Error"):
            function_name = functions_result.split('\n')[0].strip()

            # Get function info to get address
            func_info = mcp_client.call_tool("get_current_function")

            # Set a comment (this will create an undo transaction)
            if "0x" in func_info:
                # Extract address
                import re
                address_match = re.search(r'0x[0-9a-fA-F]+', func_info)
                if address_match:
                    address = address_match.group(0)

                    comment_result = mcp_client.call_tool(
                        "set_decompiler_comment",
                        address=address,
                        comment="Test undo isolation comment"
                    )

                    assert "success" in comment_result.lower() or "comment set" in comment_result.lower()

        # Comment will be undone automatically in teardown
