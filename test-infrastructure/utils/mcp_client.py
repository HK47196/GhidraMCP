"""
MCP Test Client
Communicates with MCP bridge server using the official MCP SDK
"""

import sys
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import asyncio
from contextlib import AsyncExitStack

from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

logger = logging.getLogger(__name__)


class MCPClient:
    """Test client for MCP protocol communication using official SDK"""

    def __init__(
        self,
        mcp_script_path: str,
        ghidra_server: str = "http://127.0.0.1:8080/",
        timeout: int = 60,
        verbose: bool = False
    ):
        self.mcp_script_path = Path(mcp_script_path)
        self.ghidra_server = ghidra_server
        self.timeout = timeout
        self.verbose = verbose

        # MCP SDK components
        self.session: Optional[ClientSession] = None
        self._exit_stack: Optional[AsyncExitStack] = None
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None

        if not self.mcp_script_path.exists():
            raise FileNotFoundError(f"MCP script not found: {self.mcp_script_path}")

    def start(self):
        """Start MCP bridge server and initialize session"""
        logger.info("Starting MCP bridge server")

        # Create new event loop for this session
        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)

        # Run async initialization
        self._event_loop.run_until_complete(self._start_async())

        logger.info("MCP bridge server started")

    async def _start_async(self):
        """Async initialization of MCP client"""
        # Use AsyncExitStack to manage nested async context managers
        self._exit_stack = AsyncExitStack()

        # Ensure the bridge script can import tool_tracker and other modules
        # by setting working directory to the script's parent directory
        import os
        env = os.environ.copy()

        server_params = StdioServerParameters(
            command=sys.executable,
            args=[
                str(self.mcp_script_path),
                "--ghidra-server", self.ghidra_server,
                "--transport", "stdio"
            ],
            env=env,
            cwd=str(self.mcp_script_path.parent)  # Set working directory
        )

        try:
            # Enter stdio client context
            read, write = await self._exit_stack.enter_async_context(
                stdio_client(server_params)
            )

            # Create and enter session context
            session = ClientSession(read, write)
            self.session = await self._exit_stack.enter_async_context(session)

            # Initialize the session (required before using it)
            await self.session.initialize()

        except Exception as e:
            # If initialization fails, clean up the exit stack
            await self._exit_stack.aclose()
            self._exit_stack = None
            raise RuntimeError(f"Failed to start MCP client: {e}") from e

    def stop(self):
        """Stop MCP server and cleanup"""
        if self._exit_stack:
            logger.info("Stopping MCP bridge server")
            if self._event_loop and not self._event_loop.is_closed():
                try:
                    # Close all async contexts in reverse order
                    self._event_loop.run_until_complete(self._exit_stack.aclose())
                except Exception as e:
                    logger.error(f"Error during cleanup: {e}")
                finally:
                    self._event_loop.close()

            self.session = None
            self._exit_stack = None

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call an MCP tool"""
        logger.info(f"Calling tool: {tool_name}")

        if not self.session:
            raise RuntimeError("MCP client not started")

        # Run async call in event loop
        result = self._event_loop.run_until_complete(
            self._call_tool_async(tool_name, arguments)
        )

        return result

    async def _call_tool_async(self, tool_name: str, arguments: Dict[str, Any]):
        """Async tool call"""
        result = await self.session.call_tool(tool_name, arguments)

        # Convert CallToolResult to dict format expected by tests
        # The result object has attributes like .content, .isError
        return {
            "result": {
                "content": [
                    {
                        "type": item.type,
                        "text": item.text if hasattr(item, "text") else None
                    }
                    for item in result.content
                ],
                "isError": result.isError if hasattr(result, "isError") else False
            }
        }

    def list_tools(self) -> List[str]:
        """List available tools"""
        logger.info("Listing available tools")

        if not self.session:
            raise RuntimeError("MCP client not started")

        # Run async list in event loop
        tools = self._event_loop.run_until_complete(self._list_tools_async())

        return [tool.name for tool in tools]

    async def _list_tools_async(self):
        """Async list tools"""
        result = await self.session.list_tools()
        return result.tools

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
