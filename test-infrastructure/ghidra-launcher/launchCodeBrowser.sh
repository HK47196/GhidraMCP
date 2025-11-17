#!/usr/bin/env bash
##############################################################################
# LaunchCodeBrowser - Launches Ghidra CodeBrowser with a specific program
#
# This script should be placed in your Ghidra installation directory.
#
# Usage:
#   ./launchCodeBrowser.sh <project-path> <program-name>
#
# Arguments:
#   project-path: Full path to .gpr file (e.g., /tmp/test_project/TestProject.gpr)
#   program-name: Name of program within project (e.g., test_simple)
#
# Example:
#   ./launchCodeBrowser.sh /tmp/test_project/TestProject.gpr test_simple
#
# Environment Variables:
#   GHIDRA_HOME: Path to Ghidra installation (default: script directory)
#   DISPLAY: X11 display (can use :99 for Xvfb)
#
##############################################################################

# Exit on error
set -e

# Determine Ghidra home directory
if [ -z "$GHIDRA_HOME" ]; then
    GHIDRA_HOME="$(cd "$(dirname "$0")" && pwd)"
fi

# Validate arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <project-path> <program-name>" >&2
    echo "" >&2
    echo "Arguments:" >&2
    echo "  project-path: Full path to .gpr file" >&2
    echo "  program-name: Name of program within project" >&2
    echo "" >&2
    echo "Example:" >&2
    echo "  $0 /tmp/test_project/TestProject.gpr test_simple" >&2
    exit 1
fi

PROJECT_PATH="$1"
PROGRAM_NAME="$2"

# Validate project file exists
if [ ! -f "$PROJECT_PATH" ]; then
    echo "ERROR: Project file does not exist: $PROJECT_PATH" >&2
    exit 1
fi

# Validate project file extension
if [[ ! "$PROJECT_PATH" =~ \.gpr$ ]]; then
    echo "ERROR: Project file must have .gpr extension: $PROJECT_PATH" >&2
    exit 1
fi

echo "=== LaunchCodeBrowser ==="
echo "Ghidra Home: $GHIDRA_HOME"
echo "Project: $PROJECT_PATH"
echo "Program: $PROGRAM_NAME"
echo "Display: ${DISPLAY:-default}"
echo "========================="
echo ""

# Check if launcher JAR exists in Extensions
LAUNCHER_JAR="$GHIDRA_HOME/Extensions/ghidra-launcher/lib/ghidra-launcher.jar"
if [ ! -f "$LAUNCHER_JAR" ]; then
    echo "WARNING: Launcher JAR not found at: $LAUNCHER_JAR" >&2
    echo "The launcher should be installed as a Ghidra extension." >&2
    echo "Looking for launcher in classpath..." >&2
fi

# Launch using Ghidra's launch.sh
cd "$GHIDRA_HOME"

exec ./support/launch.sh fg jdk Ghidra 4G "" \
    ghidra.LaunchCodeBrowser \
    "$PROJECT_PATH" \
    "$PROGRAM_NAME"
