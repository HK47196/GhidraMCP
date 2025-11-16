"""
Ghidra GUI Runner for Testing
Manages Ghidra instances with Xvfb for automated testing
"""

import subprocess
import time
import os
import signal
import requests
import shutil
import socket
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class GhidraRunner:
    """Manages a Ghidra GUI instance with plugin for testing"""

    def __init__(
        self,
        ghidra_install_dir: str,
        test_project_dir: str,
        test_binary: str,
        plugin_path: Optional[str] = None,
        http_port: Optional[int] = None,
        use_xvfb: bool = True,
        verbose: bool = False,
        isolated_user_dir: Optional[str] = None
    ):
        self.ghidra_dir = Path(ghidra_install_dir)
        self.project_dir = Path(test_project_dir)
        self.binary_path = Path(test_binary)
        self.plugin_path = Path(plugin_path) if plugin_path else None
        self.use_xvfb = use_xvfb
        self.verbose = verbose
        self.isolated_user_dir = Path(isolated_user_dir) if isolated_user_dir else None

        self.ghidra_process = None
        self.xvfb_process = None
        self.display_num = None
        self.original_user_home = None

        # Find a free port if not specified
        if http_port is None:
            self.http_port = self._find_free_port()
            logger.info(f"Using auto-selected port: {self.http_port}")
        else:
            self.http_port = http_port
            logger.info(f"Using specified port: {self.http_port}")

        # Validate paths
        if not self.ghidra_dir.exists():
            raise FileNotFoundError(f"Ghidra directory not found: {self.ghidra_dir}")
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Test binary not found: {self.binary_path}")

    def _find_free_display(self):
        """Find a free X display number"""
        for i in range(99, 999):
            if not Path(f"/tmp/.X{i}-lock").exists():
                return i
        raise RuntimeError("Could not find free X display")

    def _find_free_port(self):
        """Find a free port for HTTP server"""
        # Use OS to find a free port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def _start_xvfb(self):
        """Start virtual X server"""
        if not self.use_xvfb:
            return

        self.display_num = self._find_free_display()

        logger.info(f"Starting Xvfb on display :{self.display_num}")

        self.xvfb_process = subprocess.Popen(
            [
                'Xvfb',
                f':{self.display_num}',
                '-screen', '0', '1920x1080x24',
                '-ac',
                '+extension', 'GLX',
                '+render',
                '-noreset'
            ],
            stdout=subprocess.DEVNULL if not self.verbose else None,
            stderr=subprocess.DEVNULL if not self.verbose else None
        )

        os.environ['DISPLAY'] = f':{self.display_num}'
        time.sleep(2)

        logger.info(f"Xvfb started on display :{self.display_num}")

    def _stop_xvfb(self):
        """Stop virtual X server"""
        if self.xvfb_process:
            logger.info("Stopping Xvfb")
            self.xvfb_process.terminate()
            try:
                self.xvfb_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.xvfb_process.kill()
                self.xvfb_process.wait()
            self.xvfb_process = None

    def _detect_ghidra_version(self):
        """Detect Ghidra version from application.properties"""
        # Try to read version from application.properties
        app_props = self.ghidra_dir / "Ghidra" / "application.properties"
        if app_props.exists():
            with open(app_props, 'r') as f:
                for line in f:
                    if line.startswith('application.version='):
                        version = line.split('=')[1].strip()
                        logger.info(f"Detected Ghidra version from application.properties: {version}")
                        return version

        # Fallback: use directory name
        dir_name = self.ghidra_dir.name
        if "_" in dir_name:
            version = dir_name.replace("ghidra_", "").replace("_PUBLIC", "")
            logger.info(f"Detected Ghidra version from directory name: {version}")
            return version

        # Last resort: use a default
        logger.warning(f"Could not detect Ghidra version, using default")
        return "11.4.2_PUBLIC"

    def _install_plugin(self):
        """Install plugin to user Extensions directory"""
        if not self.plugin_path:
            logger.info("No plugin path provided, skipping plugin installation")
            return

        # Detect Ghidra version
        ghidra_version = self._detect_ghidra_version()

        # Use isolated directory if specified, otherwise use user home
        if self.isolated_user_dir:
            base_dir = self.isolated_user_dir
            logger.info(f"Using isolated Ghidra user directory: {base_dir}")
        else:
            base_dir = Path.home()
            logger.info("Using default user home directory")

        extensions_dir = base_dir / ".ghidra" / f".ghidra_{ghidra_version}" / "Extensions"
        extensions_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Installing plugin to {extensions_dir}")

        if self.plugin_path.suffix == '.zip':
            import zipfile
            with zipfile.ZipFile(self.plugin_path, 'r') as zip_ref:
                zip_ref.extractall(extensions_dir)
            logger.info(f"Extracted plugin from {self.plugin_path}")
        elif self.plugin_path.is_dir():
            dest = extensions_dir / self.plugin_path.name
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(self.plugin_path, dest)
            logger.info(f"Copied plugin directory to {dest}")
        else:
            raise ValueError(f"Unsupported plugin format: {self.plugin_path}")

    def _import_binary(self):
        """Import binary into Ghidra project using analyzeHeadless"""
        analyze_headless = self.ghidra_dir / "support" / "analyzeHeadless"

        if not analyze_headless.exists():
            raise FileNotFoundError(f"analyzeHeadless not found: {analyze_headless}")

        self.project_dir.mkdir(parents=True, exist_ok=True)
        project_name = "TestProject"

        logger.info(f"Importing {self.binary_path.name} into Ghidra project")

        cmd = [
            str(analyze_headless),
            str(self.project_dir),
            project_name,
            "-import", str(self.binary_path),
            "-analysisTimeoutPerFile", "120",
            "-max-cpu", "2"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            logger.error(f"Binary import failed: {result.stderr}")
            raise RuntimeError(f"Failed to import binary: {result.stderr}")

        logger.info("Binary import completed")
        return project_name

    def _start_ghidra_gui(self, project_name: str):
        """Start Ghidra GUI"""
        ghidra_run = self.ghidra_dir / "ghidraRun"

        if not ghidra_run.exists():
            raise FileNotFoundError(f"ghidraRun script not found: {ghidra_run}")

        project_path = self.project_dir / f"{project_name}.gpr"

        logger.info(f"Starting Ghidra GUI with project: {project_path}")

        cmd = [str(ghidra_run), str(project_path)]
        env = os.environ.copy()

        # Set isolated HOME directory if specified
        if self.isolated_user_dir:
            self.original_user_home = env.get('HOME')
            env['HOME'] = str(self.isolated_user_dir)
            logger.info(f"Setting isolated HOME={env['HOME']} (original: {self.original_user_home})")

        # Create log files for Ghidra output
        self.ghidra_stdout_log = self.project_dir / "ghidra_stdout.log"
        self.ghidra_stderr_log = self.project_dir / "ghidra_stderr.log"

        self.stdout_file = open(self.ghidra_stdout_log, 'w')
        self.stderr_file = open(self.ghidra_stderr_log, 'w')

        self.ghidra_process = subprocess.Popen(
            cmd,
            stdout=self.stdout_file,
            stderr=self.stderr_file,
            env=env
        )

        logger.info(f"Ghidra GUI process started (logs: {self.ghidra_stdout_log}, {self.ghidra_stderr_log})")

    def _read_log_file(self, log_path: Path, max_lines: int = 50):
        """Read last N lines from log file"""
        if not log_path.exists():
            return "<log file not found>"
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                return ''.join(lines[-max_lines:]) if lines else "<empty>"
        except Exception as e:
            return f"<error reading log: {e}>"

    def _get_ghidra_application_log(self):
        """Get path to Ghidra's application.log"""
        if self.isolated_user_dir:
            base_dir = self.isolated_user_dir
        else:
            base_dir = Path.home()

        ghidra_version = self._detect_ghidra_version()
        log_file = base_dir / ".ghidra" / f".ghidra_{ghidra_version}" / "application.log"
        return log_file

    def _wait_for_http_server(self, timeout: int = 60):
        """Wait for HTTP server to become available"""
        logger.info(f"Waiting for HTTP server on port {self.http_port}")

        start_time = time.time()
        last_error = None

        while time.time() - start_time < timeout:
            if self.ghidra_process.poll() is not None:
                # Close log files to ensure all output is flushed
                if hasattr(self, 'stdout_file'):
                    self.stdout_file.close()
                if hasattr(self, 'stderr_file'):
                    self.stderr_file.close()

                # Read logs
                stdout_content = self._read_log_file(self.ghidra_stdout_log)
                stderr_content = self._read_log_file(self.ghidra_stderr_log)
                app_log_content = self._read_log_file(self._get_ghidra_application_log())

                logger.error(f"Ghidra process exited unexpectedly (exit code: {self.ghidra_process.returncode})")
                logger.error(f"STDOUT (last 50 lines from {self.ghidra_stdout_log}):\n{stdout_content}")
                logger.error(f"STDERR (last 50 lines from {self.ghidra_stderr_log}):\n{stderr_content}")
                logger.error(f"Ghidra application.log (last 50 lines):\n{app_log_content}")

                raise RuntimeError(
                    f"Ghidra process exited before server started (exit code: {self.ghidra_process.returncode}). "
                    f"Check logs at:\n"
                    f"  - stdout: {self.ghidra_stdout_log}\n"
                    f"  - stderr: {self.ghidra_stderr_log}\n"
                    f"  - application.log: {self._get_ghidra_application_log()}"
                )

            try:
                response = requests.get(
                    f"http://127.0.0.1:{self.http_port}/ping",
                    timeout=2
                )
                if response.ok:
                    logger.info(f"HTTP server is ready on port {self.http_port}")
                    return True
            except requests.exceptions.RequestException as e:
                last_error = e
                pass

            time.sleep(1)

        raise TimeoutError(
            f"HTTP server did not start within {timeout} seconds. "
            f"Last error: {last_error}"
        )

    def start(self, timeout: int = 120):
        """Start Ghidra with plugin"""
        logger.info("=" * 60)
        logger.info("Starting Ghidra Runner")
        logger.info("=" * 60)

        try:
            if self.use_xvfb:
                self._start_xvfb()

            self._install_plugin()
            project_name = self._import_binary()
            self._start_ghidra_gui(project_name)
            self._wait_for_http_server(timeout=timeout)

            logger.info("Ghidra Runner started successfully")
            logger.info("=" * 60)
            return True

        except Exception as e:
            logger.error(f"Failed to start Ghidra: {e}")
            self.stop()
            raise

    def stop(self):
        """Stop Ghidra and cleanup"""
        logger.info("Stopping Ghidra Runner")

        if self.ghidra_process:
            logger.info("Terminating Ghidra process")
            self.ghidra_process.terminate()
            try:
                self.ghidra_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning("Ghidra did not terminate, killing")
                self.ghidra_process.kill()
                self.ghidra_process.wait()

            self.ghidra_process = None

        # Close log files
        if hasattr(self, 'stdout_file') and self.stdout_file:
            try:
                self.stdout_file.close()
            except:
                pass
        if hasattr(self, 'stderr_file') and self.stderr_file:
            try:
                self.stderr_file.close()
            except:
                pass

        if self.use_xvfb:
            self._stop_xvfb()

        logger.info("Ghidra Runner stopped")

    def cleanup_project(self):
        """Remove test project files"""
        if self.project_dir.exists():
            logger.info(f"Cleaning up project directory: {self.project_dir}")
            shutil.rmtree(self.project_dir)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        self.cleanup_project()
