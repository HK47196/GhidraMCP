"""End-to-end MCP tests for program modifications"""

import pytest


class TestMCPModifications:
    """Test modification operations through MCP"""

    def test_rename_function(self, mcp_client):
        """Test renaming a function"""
        original_name = "add"
        new_name = "test_add_renamed"

        # Rename
        response = mcp_client.call_tool("rename_function", {
            "old_name": original_name,
            "new_name": new_name
        })

        assert "result" in response
        text = response["result"]["content"][0]["text"]
        assert "success" in text.lower() or "renamed" in text.lower()

        # Verify
        list_response = mcp_client.call_tool("query", {
            "endpoint": "list_functions"
        })
        list_text = list_response["result"]["content"][0]["text"]
        assert new_name in list_text

        # Rename back
        restore_response = mcp_client.call_tool("rename_function", {
            "old_name": new_name,
            "new_name": original_name
        })
        assert "result" in restore_response

    def test_set_decompiler_comment(self, mcp_client):
        """Test setting a comment in decompiler view"""
        response = mcp_client.call_tool("set_decompiler_comment", {
            "address": "0x00401000",
            "comment": "Test comment from MCP integration test"
        })

        assert "result" in response
