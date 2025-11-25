"""pytest configuration and shared fixtures"""

import pytest
import logging
import sys
import json
import requests
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

# Default binary name used when no marker is specified
DEFAULT_BINARY = "test_simple"

# Global reference to ghidra server URL (set by ghidra_server fixture)
_ghidra_url = None


# ==================== Program Management Helpers ====================

def _get_ghidra_url():
    """Get the Ghidra server URL."""
    global _ghidra_url
    if _ghidra_url is None:
        _ghidra_url = "http://127.0.0.1:8080"
    return _ghidra_url


def list_programs():
    """List all programs in the current Ghidra project.

    Returns:
        dict with 'programs' list and 'current' program name
    """
    url = f"{_get_ghidra_url()}/program/list"
    response = requests.get(url, timeout=30)
    return response.json()


def get_current_program():
    """Get the currently active program.

    Returns:
        dict with 'program_name' and 'loaded' status
    """
    url = f"{_get_ghidra_url()}/program/current"
    response = requests.get(url, timeout=30)
    return response.json()


def switch_program(program_name: str):
    """Switch to a different program.

    Args:
        program_name: Name of the program to switch to

    Returns:
        dict with 'success' status and 'message'
    """
    url = f"{_get_ghidra_url()}/program/switch"
    response = requests.post(url, data={"program_name": program_name}, timeout=60)
    return response.json()


def import_binary(file_path: str):
    """Import a binary file into the Ghidra project.

    Args:
        file_path: Absolute path to the binary file

    Returns:
        dict with 'success' status, 'program_name', and 'message'
    """
    url = f"{_get_ghidra_url()}/program/import"
    response = requests.post(url, data={"file_path": file_path}, timeout=120)
    return response.json()


def ensure_binary_loaded(binary_name: str) -> str:
    """Ensure a binary is switched to as the current program.

    All binaries are pre-imported at Ghidra startup, so this function
    just switches to the requested binary if it's not already current.

    Args:
        binary_name: Name of the binary (e.g., 'test_simple', 'test_cpp')

    Returns:
        The program name after loading

    Raises:
        RuntimeError: If the binary cannot be switched to
    """
    # Check current program
    current = get_current_program()
    if current.get("program_name") == binary_name:
        logging.info(f"Binary '{binary_name}' is already the current program")
        return binary_name

    # Check if the binary is available in the project
    programs = list_programs()
    program_names = [p["name"] for p in programs.get("programs", [])]

    if binary_name not in program_names:
        available = ", ".join(program_names) if program_names else "none"
        raise RuntimeError(
            f"Binary '{binary_name}' not found in project. "
            f"Available programs: {available}. "
            f"Make sure the binary exists in test-infrastructure/fixtures/binaries/"
        )

    # Switch to the binary
    logging.info(f"Switching to binary '{binary_name}'")
    result = switch_program(binary_name)
    if not result.get("success"):
        raise RuntimeError(f"Failed to switch to program: {result.get('error', 'Unknown error')}")

    return binary_name


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "binary(name): mark test to run with specific binary (e.g., @pytest.mark.binary('test_simple'))"
    )


def pytest_collection_modifyitems(config, items):
    """Sort tests by their binary marker to minimize binary reloading.

    Tests are grouped by their binary marker value, with unmarked tests
    (using default binary) sorted together.
    """
    def get_binary_name(item):
        marker = item.get_closest_marker("binary")
        if marker and marker.args:
            return marker.args[0]
        return DEFAULT_BINARY

    # Sort items by binary name to group tests using the same binary together
    items.sort(key=lambda item: get_binary_name(item))


def get_binary_path(binary_name: str) -> Path:
    """Get the full path to a binary in the test fixtures directory.

    Args:
        binary_name: Name of the binary (e.g., 'test_simple', 'test_cpp')

    Returns:
        Path to the binary file

    Raises:
        FileNotFoundError: If the binary doesn't exist
    """
    binaries_dir = project_root / "test-infrastructure" / "fixtures" / "binaries"
    binary_path = binaries_dir / binary_name

    if not binary_path.exists():
        available = [f.name for f in binaries_dir.iterdir() if f.is_file()] if binaries_dir.exists() else []
        raise FileNotFoundError(
            f"Binary '{binary_name}' not found at {binary_path}. "
            f"Available binaries: {available}"
        )

    return binary_path


def get_test_binary_name(request) -> str:
    """Get the binary name for a test from its marker or default.

    Args:
        request: pytest request fixture

    Returns:
        Name of the binary to use for the test
    """
    marker = request.node.get_closest_marker("binary")
    if marker and marker.args:
        return marker.args[0]
    return DEFAULT_BINARY


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
    """Path to default test binary (test_simple).

    For tests that require a specific binary, use the @pytest.mark.binary('binary_name')
    marker and the `program` fixture instead.
    """
    try:
        return str(get_binary_path(DEFAULT_BINARY))
    except FileNotFoundError as e:
        pytest.skip(f"Default test binary not found: {e}. Run: test-infrastructure/fixtures/build_test_binary.sh")


@pytest.fixture(scope="session")
def all_test_binaries():
    """Get paths to all test binaries in the fixtures directory.

    Returns a list of paths to all binaries that should be imported at startup.
    """
    binaries_dir = project_root / "test-infrastructure" / "fixtures" / "binaries"
    if not binaries_dir.exists():
        return []

    binaries = []
    for f in binaries_dir.iterdir():
        if f.is_file() and not f.name.startswith('.'):
            binaries.append(str(f))

    logging.info(f"Found {len(binaries)} test binaries: {[Path(b).name for b in binaries]}")
    return binaries


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
def ghidra_server(ghidra_dir, test_binary, all_test_binaries, plugin_path, use_xvfb,
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

    # Get additional binaries (all binaries except the primary one)
    additional_binaries = [b for b in all_test_binaries if b != test_binary]
    if additional_binaries:
        logging.info(f"Will import {len(additional_binaries)} additional binaries: {[Path(b).name for b in additional_binaries]}")

    runner = GhidraRunner(
        ghidra_install_dir=ghidra_dir,
        test_project_dir=project_dir,
        test_binary=test_binary,
        plugin_path=plugin_path,
        http_port=8080,  # Use plugin's default port (configured in plugin options)
        use_xvfb=use_xvfb,
        verbose=verbose_ghidra,
        isolated_user_dir=isolated_dir,
        additional_binaries=additional_binaries
    )

    runner.start(timeout=30)

    # Set the global Ghidra URL for program management helpers
    global _ghidra_url
    _ghidra_url = f"http://127.0.0.1:{runner.http_port}"

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


# Track the currently loaded binary for the session
_current_binary = None


def _switch_to_binary(request, binary_name: str) -> str:
    """Internal helper to switch to a binary.

    Returns the loaded binary name or raises an exception.
    """
    global _current_binary

    if _current_binary == binary_name:
        return _current_binary

    logging.info(f"Switching to binary '{binary_name}' (current: '{_current_binary}')")
    try:
        loaded_name = ensure_binary_loaded(binary_name)
        _current_binary = loaded_name
        logging.info(f"Successfully switched to binary '{loaded_name}'")
        return _current_binary
    except Exception as e:
        pytest.fail(f"Failed to switch to binary '{binary_name}': {e}")


@pytest.fixture(autouse=True)
def auto_switch_binary(request, ghidra_server):
    """Automatically switch to the correct binary for each test.

    This autouse fixture ensures that the correct binary is loaded
    based on the @pytest.mark.binary marker (or default binary if no marker).

    Tests are sorted by binary marker to minimize switching.
    """
    requested_binary = get_test_binary_name(request)
    _switch_to_binary(request, requested_binary)
    yield


@pytest.fixture
def program(request, ghidra_server):
    """Get the program name for the current test.

    Reads the @pytest.mark.binary('name') marker to determine which binary
    the test expects. If no marker is present, uses the default binary.

    Note: Binary switching is handled automatically by auto_switch_binary.
    This fixture just returns the current binary name.

    Usage:
        @pytest.mark.binary("test_simple")
        def test_something(program):
            # program == "test_simple"
            pass

        @pytest.mark.binary("test_cpp")
        def test_cpp_feature(program):
            # program == "test_cpp"
            pass

        def test_default(program):
            # program == DEFAULT_BINARY (test_simple)
            pass

    Returns:
        The binary name that is loaded for this test.
    """
    global _current_binary
    return _current_binary


@pytest.fixture(scope="session")
def clean_undo_stack(ghidra_server):
    """Ensure undo stack is clear at test session start"""
    from bridge_mcp_ghidra import clear_undo
    clear_undo()
    yield


@pytest.fixture(autouse=True)
def restore_program_state(clean_undo_stack):
    """Automatically restore program state after each test by undoing all changes"""
    from bridge_mcp_ghidra import can_undo, undo

    yield  # Run the test

    # After test: undo all changes
    undo_count = 0
    max_undos = 100  # Safety limit to prevent infinite loops

    while can_undo() and undo_count < max_undos:
        undo()
        undo_count += 1

    if undo_count > 0:
        logging.info(f"Restored program state by undoing {undo_count} transaction(s)")

    if undo_count >= max_undos:
        logging.warning(f"Hit max undo limit ({max_undos}), program state may not be fully restored")
