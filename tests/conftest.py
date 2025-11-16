"""pytest configuration and shared fixtures"""

import pytest
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.utils.ghidra_runner import GhidraRunner
from tests.utils.mcp_client import MCPClient

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def pytest_addoption(parser):
    """Add custom command line options"""
    parser.addoption(
        "--ghidra-dir",
        action="store",
        default="/opt/ghidra",
        help="Path to Ghidra installation directory"
    )
    parser.addoption(
        "--no-xvfb",
        action="store_true",
        default=False,
        help="Don't use Xvfb (for local testing with display)"
    )
    parser.addoption(
        "--keep-project",
        action="store_true",
        default=False,
        help="Don't delete test project after tests"
    )
    parser.addoption(
        "--verbose-ghidra",
        action="store_true",
        default=False,
        help="Enable verbose Ghidra output"
    )


@pytest.fixture(scope="session")
def ghidra_dir(request):
    """Get Ghidra installation directory"""
    return request.config.getoption("--ghidra-dir")


@pytest.fixture(scope="session")
def use_xvfb(request):
    """Whether to use Xvfb"""
    return not request.config.getoption("--no-xvfb")


@pytest.fixture(scope="session")
def keep_project(request):
    """Whether to keep test project"""
    return request.config.getoption("--keep-project")


@pytest.fixture(scope="session")
def verbose_ghidra(request):
    """Whether to enable verbose Ghidra output"""
    return request.config.getoption("--verbose-ghidra")


@pytest.fixture(scope="session")
def test_binary():
    """Path to test binary"""
    binary_path = Path(__file__).parent / "fixtures" / "binaries" / "test_simple"
    if not binary_path.exists():
        pytest.skip(f"Test binary not found: {binary_path}. Run: tests/fixtures/build_test_binary.sh")
    return str(binary_path)


@pytest.fixture(scope="session")
def plugin_path():
    """Path to plugin"""
    # Try multiple locations
    search_paths = [
        Path(__file__).parent / "fixtures" / "plugin",
        Path(__file__).parent.parent / "target",  # Maven output directory
        Path(__file__).parent.parent / "dist",
        Path(__file__).parent.parent / "build",
    ]

    for search_dir in search_paths:
        if search_dir.exists():
            # Look for ZIP files
            for plugin_file in search_dir.glob("*.zip"):
                if "GhidraMCP" in plugin_file.name or "ghidra" in plugin_file.name.lower():
                    return str(plugin_file)

    pytest.skip("Plugin not found. Please build the plugin first with: mvn clean package")


@pytest.fixture(scope="session")
def ghidra_server(ghidra_dir, test_binary, plugin_path, use_xvfb,
                   keep_project, verbose_ghidra):
    """Start Ghidra server for entire test session"""
    import tempfile

    project_dir = tempfile.mkdtemp(prefix="ghidra_test_")

    runner = GhidraRunner(
        ghidra_install_dir=ghidra_dir,
        test_project_dir=project_dir,
        test_binary=test_binary,
        plugin_path=plugin_path,
        http_port=8080,
        use_xvfb=use_xvfb,
        verbose=verbose_ghidra
    )

    runner.start(timeout=120)

    yield runner

    runner.stop()
    if not keep_project:
        runner.cleanup_project()


@pytest.fixture(scope="session")
def mcp_client(ghidra_server):
    """Start MCP bridge server for entire test session"""
    mcp_script = Path(__file__).parent.parent / "bridge_mcp_ghidra.py"

    if not mcp_script.exists():
        pytest.skip(f"MCP script not found: {mcp_script}")

    client = MCPClient(
        mcp_script_path=str(mcp_script),
        ghidra_server="http://127.0.0.1:8080/",
        timeout=60,
        verbose=False
    )

    client.start()

    yield client

    client.stop()


@pytest.fixture
def mcp_tools(mcp_client):
    """List of available MCP tools"""
    return mcp_client.list_tools()
