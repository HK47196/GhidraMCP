"""End-to-end MCP tests for basic queries"""

import pytest


class TestMCPBasicQueries:
    """Test basic query operations through MCP"""

    def test_tools_are_available(self, mcp_tools):
        """Verify MCP tools are registered"""
        assert len(mcp_tools) > 0

        essential_tools = ["query", "get_current_function", "decompile_function"]

        for tool in essential_tools:
            assert tool in mcp_tools, f"Tool '{tool}' not found"

    def test_query_list_functions(self, mcp_client):
        """Test listing all functions via MCP"""
        response = mcp_client.call_tool("query", {
            "endpoint": "list_functions"
        })

        assert "result" in response
        result = response["result"]

        assert "content" in result
        assert len(result["content"]) > 0

        content = result["content"][0]
        assert content["type"] == "text"
        assert len(content["text"]) > 0

        text = content["text"]
        assert "main" in text.lower() or "function" in text.lower()

    def test_get_current_function(self, mcp_client):
        """Test getting current function"""
        response = mcp_client.call_tool("get_current_function", {})

        assert "result" in response

    def test_man_command(self, mcp_client):
        """Test the manual/help command"""
        response = mcp_client.call_tool("man", {})

        assert "result" in response
        text = response["result"]["content"][0]["text"]

        assert "endpoint" in text.lower() or "manual" in text.lower()
