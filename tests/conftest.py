"""pytest configuration and shared fixtures"""

import pytest
import logging
import sys
from pathlib import Path

# Add parent directory and test-infrastructure to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "test-infrastructure"))

# Import from utils (in test-infrastructure/utils/)
from utils.ghidra_runner import GhidraRunner

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
    parser.addoption(
        "--isolated",
        action="store_true",
        default=True,
        help="Use isolated Ghidra user directory (default: True, prevents interference with desktop Ghidra)"
    )
    parser.addoption(
        "--no-isolated",
        action="store_true",
        default=False,
        help="Don't use isolated directory (use your actual ~/.ghidra)"
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
def use_isolated(request):
    """Whether to use isolated Ghidra user directory"""
    if request.config.getoption("--no-isolated"):
        return False
    return True  # Default to isolated mode


@pytest.fixture(scope="session")
def test_binary():
    """Path to test binary"""
    binary_path = Path(__file__).parent.parent / "test-infrastructure" / "fixtures" / "binaries" / "test_simple"
    if not binary_path.exists():
        pytest.skip(f"Test binary not found: {binary_path}. Run: test-infrastructure/fixtures/build_test_binary.sh")
    return str(binary_path)


@pytest.fixture(scope="session")
def plugin_path():
    """Path to plugin"""
    # Try multiple locations
    search_paths = [
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

    runner.start(timeout=90)

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


@pytest.fixture(scope="session", autouse=True)
def configure_bridge(ghidra_server):
    """Configure the bridge module to connect to the test Ghidra server"""
    import time
    import requests

    # Import here, after ghidra_server is running
    import bridge_mcp_ghidra

    # Set the Ghidra server URL for all bridge functions
    ghidra_url = f"http://127.0.0.1:{ghidra_server.http_port}/"
    logging.info(f"Configuring bridge to connect to Ghidra at {ghidra_url}")

    bridge_mcp_ghidra.ghidra_server_url = ghidra_url

    # Verify connection and wait for program to be loaded
    logging.info(f"Bridge configured: bridge_mcp_ghidra.ghidra_server_url = {bridge_mcp_ghidra.ghidra_server_url}")

    # Health check: Wait for Ghidra to have a program loaded
    logging.info("Waiting for Ghidra to finish loading and analyzing program...")
    max_retries = 30
    for i in range(max_retries):
        try:
            response = requests.get(f"{ghidra_url}methods", params={"limit": 1}, timeout=5)
            if response.ok and "No program loaded" not in response.text:
                logging.info(f"✓ Ghidra program loaded successfully (attempt {i+1}/{max_retries})")
                break
        except Exception as e:
            logging.debug(f"Health check attempt {i+1}/{max_retries} failed: {e}")

        if i == max_retries - 1:
            logging.error("Ghidra failed to load program after 30 attempts!")
            logging.error("Last response: %s", response.text if 'response' in locals() else "No response")
            raise RuntimeError("Ghidra did not load program successfully")

        time.sleep(1)

    # Test the bridge functions are using the right URL
    test_result = bridge_mcp_ghidra.query(type="methods", limit=1)
    logging.info(f"Bridge connection test result: {test_result[:100] if test_result else 'Empty'}")

    yield

    # No cleanup needed - bridge functions are stateless
