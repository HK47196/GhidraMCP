"""End-to-end MCP tests for struct operations"""

import pytest


class TestMCPStructOperations:
    """Test struct manipulation through MCP"""

    def test_create_struct(self, mcp_client):
        """Test creating a new struct"""
        response = mcp_client.call_tool("create_struct", {
            "name": "MCPTestStruct",
            "size": 16
        })

        assert "result" in response
        text = response["result"]["content"][0]["text"]
        assert "success" in text.lower() or "created" in text.lower()

    def test_add_struct_field(self, mcp_client):
        """Test adding field to struct"""
        # Create struct first
        mcp_client.call_tool("create_struct", {
            "name": "MCPTestStruct2",
            "size": 0
        })

        # Add field
        response = mcp_client.call_tool("add_struct_field", {
            "struct_name": "MCPTestStruct2",
            "field_type": "int",
            "field_name": "test_field",
            "comment": "Test field comment"
        })

        assert "result" in response

    def test_get_struct_info(self, mcp_client):
        """Test getting struct information"""
        # Create struct with field
        mcp_client.call_tool("create_struct", {
            "name": "MCPTestStruct3",
            "size": 0
        })

        mcp_client.call_tool("add_struct_field", {
            "struct_name": "MCPTestStruct3",
            "field_type": "int",
            "field_name": "field1"
        })

        # Get info
        response = mcp_client.call_tool("get_struct_info", {
            "name": "MCPTestStruct3"
        })

        assert "result" in response
        text = response["result"]["content"][0]["text"]
        assert "field1" in text
