"""
MCP Test Client
Communicates with MCP bridge server via stdio protocol
"""

import subprocess
import json
import time
import logging
from typing import Dict, List, Any
from pathlib import Path
import threading
import queue

logger = logging.getLogger(__name__)


class MCPClient:
    """Test client for MCP protocol communication"""

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
        self.process = None
        self.request_id = 0

        self.stdout_queue = queue.Queue()
        self.stderr_queue = queue.Queue()
        self.reader_thread = None
        self.stderr_thread = None

        if not self.mcp_script_path.exists():
            raise FileNotFoundError(f"MCP script not found: {self.mcp_script_path}")

    def _read_stdout(self):
        """Background thread to read stdout"""
        while self.process and self.process.poll() is None:
            try:
                line = self.process.stdout.readline()
                if line:
                    self.stdout_queue.put(line)
            except Exception as e:
                logger.error(f"Error reading stdout: {e}")
                break

    def _read_stderr(self):
        """Background thread to read stderr"""
        while self.process and self.process.poll() is None:
            try:
                line = self.process.stderr.readline()
                if line:
                    self.stderr_queue.put(line)
                    if self.verbose:
                        logger.debug(f"MCP stderr: {line.strip()}")
            except Exception as e:
                logger.error(f"Error reading stderr: {e}")
                break

    def start(self):
        """Start MCP bridge server"""
        logger.info("Starting MCP bridge server")

        cmd = [
            "python",
            str(self.mcp_script_path),
            "--ghidra-server", self.ghidra_server,
            "--transport", "stdio"
        ]

        if self.verbose:
            logger.info(f"Running: {' '.join(cmd)}")

        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        self.reader_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self.reader_thread.start()
        self.stderr_thread.start()

        time.sleep(2)

        if self.process.poll() is not None:
            stderr = self.process.stderr.read()
            raise RuntimeError(f"MCP server failed to start: {stderr}")

        logger.info("MCP bridge server started")

    def stop(self):
        """Stop MCP server"""
        if self.process:
            logger.info("Stopping MCP bridge server")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("MCP server did not terminate, killing")
                self.process.kill()
                self.process.wait()
            self.process = None

    def _get_next_id(self) -> int:
        """Get next request ID"""
        self.request_id += 1
        return self.request_id

    def _send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send MCP request and wait for response"""
        if not self.process:
            raise RuntimeError("MCP server not started")

        request_id = self._get_next_id()
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }

        if self.verbose:
            logger.debug(f"Sending request: {json.dumps(request, indent=2)}")

        request_json = json.dumps(request) + "\n"
        self.process.stdin.write(request_json)
        self.process.stdin.flush()

        start_time = time.time()
        while time.time() - start_time < self.timeout:
            try:
                response_line = self.stdout_queue.get(timeout=1)

                if self.verbose:
                    logger.debug(f"Received response: {response_line.strip()}")

                try:
                    response = json.loads(response_line)

                    if response.get("id") == request_id:
                        return response
                    else:
                        logger.warning(f"Received response for different request: {response.get('id')}")

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse response: {response_line}")
                    logger.error(f"JSON error: {e}")
                    continue

            except queue.Empty:
                continue

        raise TimeoutError(f"No response received within {self.timeout} seconds")

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call an MCP tool"""
        logger.info(f"Calling tool: {tool_name}")

        response = self._send_request(
            method="tools/call",
            params={
                "name": tool_name,
                "arguments": arguments
            }
        )

        if "error" in response:
            error = response["error"]
            raise RuntimeError(
                f"MCP tool call failed: {error.get('message', 'Unknown error')}"
            )

        return response

    def list_tools(self) -> List[str]:
        """List available tools"""
        logger.info("Listing available tools")

        response = self._send_request(
            method="tools/list",
            params={}
        )

        if "error" in response:
            raise RuntimeError(f"Failed to list tools: {response['error']}")

        tools = response.get("result", {}).get("tools", [])
        return [tool["name"] for tool in tools]

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
