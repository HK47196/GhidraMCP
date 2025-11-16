"""End-to-end MCP tests for decompilation"""

import pytest


class TestMCPDecompilation:
    """Test decompilation operations through MCP"""

    def test_decompile_main_function(self, mcp_client):
        """Test decompiling the main function"""
        response = mcp_client.call_tool("decompile_function", {
            "function_name": "main"
        })

        assert "result" in response
        text = response["result"]["content"][0]["text"]

        # Should contain C-like code
        assert "{" in text or "}" in text
        assert any(keyword in text for keyword in ["void", "int", "return"])

    def test_disassemble_function(self, mcp_client):
        """Test disassembling a function"""
        response = mcp_client.call_tool("disassemble_function", {
            "function_name": "main"
        })

        assert "result" in response
        text = response["result"]["content"][0]["text"]

        # Should contain assembly instructions
        assert any(instr in text.lower() for instr in
                   ["mov", "push", "pop", "ret", "call"])
