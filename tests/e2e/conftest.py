"""pytest configuration and shared fixtures"""

import pytest
import logging
import sys
from pathlib import Path

# Add parent directory and test-infrastructure to path
# From tests/e2e/conftest.py, go up to project root, then add test-infrastructure
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "test-infrastructure"))

# Import from local utils (in test-infrastructure/utils/)
from utils.ghidra_runner import GhidraRunner
from utils.mcp_client import MCPClient

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def pytest_addoption(parser):
    """Add custom command line options"""
    # Use try-except to handle duplicate option registration when multiple conftest.py files exist
    options = [
        ("--ghidra-dir", {"action": "store", "default": "/opt/ghidra", "help": "Path to Ghidra installation directory"}),
        ("--no-xvfb", {"action": "store_true", "default": False, "help": "Don't use Xvfb (for local testing with display)"}),
        ("--keep-project", {"action": "store_true", "default": False, "help": "Don't delete test project after tests"}),
        ("--verbose-ghidra", {"action": "store_true", "default": False, "help": "Enable verbose Ghidra output"}),
        ("--isolated", {"action": "store_true", "default": True, "help": "Use isolated Ghidra user directory (default: True, prevents interference with desktop Ghidra)"}),
        ("--no-isolated", {"action": "store_true", "default": False, "help": "Don't use isolated directory (use your actual ~/.ghidra)"}),
    ]

    for opt_name, opt_kwargs in options:
        try:
            parser.addoption(opt_name, **opt_kwargs)
        except ValueError:
            # Option already added by another conftest.py
            pass


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
def use_isolated(request):
    """Whether to use isolated Ghidra user directory"""
    if request.config.getoption("--no-isolated"):
        return False
    return True  # Default to isolated mode


@pytest.fixture(scope="session")
def test_binary():
    """Path to test binary"""
    project_root = Path(__file__).parent.parent.parent
    binary_path = project_root / "test-infrastructure" / "fixtures" / "binaries" / "test_simple"
    if not binary_path.exists():
        pytest.skip(f"Test binary not found: {binary_path}. Run: test-infrastructure/fixtures/build_test_binary.sh")
    return str(binary_path)


@pytest.fixture(scope="session")
def plugin_path():
    """Path to plugin"""
    project_root = Path(__file__).parent.parent.parent
    # Try multiple locations
    search_paths = [
        project_root / "test-infrastructure" / "fixtures" / "plugin",
        project_root / "target",  # Maven output directory
        project_root / "dist",
        project_root / "build",
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
                   keep_project, verbose_ghidra, use_isolated):
    """Start Ghidra server for entire test session"""
    import tempfile
    import shutil

    project_dir = tempfile.mkdtemp(prefix="ghidra_test_project_")

    # Create isolated user directory if requested (default)
    isolated_dir = None
    if use_isolated:
        isolated_dir = tempfile.mkdtemp(prefix="ghidra_test_home_")
        logging.info(f"Using isolated Ghidra user directory: {isolated_dir}")
    else:
        logging.warning("NOT using isolated mode - tests will use your real ~/.ghidra directory!")

    runner = GhidraRunner(
        ghidra_install_dir=ghidra_dir,
        test_project_dir=project_dir,
        test_binary=test_binary,
        plugin_path=plugin_path,
        http_port=8080,  # Use plugin's default port (configured in plugin options)
        use_xvfb=use_xvfb,
        verbose=verbose_ghidra,
        isolated_user_dir=isolated_dir
    )

    runner.start(timeout=30)

    yield runner

    runner.stop()
    if not keep_project:
        runner.cleanup_project()

    # Clean up isolated directory
    if use_isolated and isolated_dir and Path(isolated_dir).exists():
        if keep_project:
            logging.info(f"Keeping isolated directory: {isolated_dir}")
        else:
            logging.info(f"Cleaning up isolated directory: {isolated_dir}")
            shutil.rmtree(isolated_dir)


@pytest.fixture(scope="session")
def mcp_client(ghidra_server):
    """Start MCP bridge server for entire test session"""
    project_root = Path(__file__).parent.parent.parent
    mcp_script = project_root / "bridge_mcp_ghidra.py"

    if not mcp_script.exists():
        pytest.skip(f"MCP script not found: {mcp_script}")

    # Use the dynamically allocated port from ghidra_server
    ghidra_url = f"http://127.0.0.1:{ghidra_server.http_port}/"
    logging.info(f"MCP client connecting to Ghidra at {ghidra_url}")

    client = MCPClient(
        mcp_script_path=str(mcp_script),
        ghidra_server=ghidra_url,
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
