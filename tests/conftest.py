"""pytest configuration for unit tests"""

import pytest


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
