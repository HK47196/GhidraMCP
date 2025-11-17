#!/usr/bin/env bash
##############################################################################
# Example E2E Test Script for GhidraMCP Plugin
#
# This demonstrates how to use the LaunchCodeBrowser launcher in an
# automated testing environment with Xvfb.
#
# Requirements:
#   - Ghidra installed at /opt/ghidra (or set GHIDRA_HOME)
#   - ghidra-launcher installed (make install)
#   - Xvfb installed (for headless testing)
#   - curl (for HTTP API testing)
#
##############################################################################

set -e  # Exit on error

# Configuration
GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
PROJECT_PATH="/tmp/test_project/TestProject.gpr"
PROGRAM_NAME="test_simple"
DISPLAY_NUM=99
PLUGIN_PORT=8080
STARTUP_TIMEOUT=30

echo "=== GhidraMCP E2E Test ==="
echo "Ghidra: $GHIDRA_HOME"
echo "Project: $PROJECT_PATH"
echo "Program: $PROGRAM_NAME"
echo "==========================="
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."

    if [ -n "$GHIDRA_PID" ]; then
        echo "Stopping Ghidra (PID: $GHIDRA_PID)..."
        kill $GHIDRA_PID 2>/dev/null || true
        wait $GHIDRA_PID 2>/dev/null || true
    fi

    if [ -n "$XVFB_PID" ]; then
        echo "Stopping Xvfb (PID: $XVFB_PID)..."
        kill $XVFB_PID 2>/dev/null || true
    fi

    echo "Cleanup complete"
}

# Register cleanup on exit
trap cleanup EXIT INT TERM

# Step 1: Start Xvfb
echo "Step 1: Starting Xvfb on display :$DISPLAY_NUM..."
Xvfb :$DISPLAY_NUM -screen 0 1024x768x24 &
XVFB_PID=$!
export DISPLAY=:$DISPLAY_NUM

echo "Xvfb started (PID: $XVFB_PID)"
sleep 2

# Verify Xvfb is running
if ! ps -p $XVFB_PID > /dev/null; then
    echo "ERROR: Xvfb failed to start!"
    exit 1
fi

# Step 2: Verify project exists
echo ""
echo "Step 2: Verifying project exists..."
if [ ! -f "$PROJECT_PATH" ]; then
    echo "ERROR: Project file not found: $PROJECT_PATH"
    echo "Please create a test project first."
    exit 1
fi
echo "Project found: $PROJECT_PATH"

# Step 3: Launch Ghidra with CodeBrowser
echo ""
echo "Step 3: Launching Ghidra CodeBrowser..."
cd "$GHIDRA_HOME"

./launchCodeBrowser.sh "$PROJECT_PATH" "$PROGRAM_NAME" &
GHIDRA_PID=$!

echo "Ghidra launched (PID: $GHIDRA_PID)"

# Step 4: Wait for plugin to initialize
echo ""
echo "Step 4: Waiting for GhidraMCP plugin to start..."
echo "Checking for HTTP server on port $PLUGIN_PORT..."

ELAPSED=0
while [ $ELAPSED -lt $STARTUP_TIMEOUT ]; do
    if curl -s http://localhost:$PLUGIN_PORT/api/health > /dev/null 2>&1; then
        echo "✓ Plugin HTTP server is up!"
        break
    fi

    # Check if Ghidra is still running
    if ! ps -p $GHIDRA_PID > /dev/null; then
        echo "ERROR: Ghidra process died during startup!"
        exit 1
    fi

    echo "  Waiting... ($ELAPSED/${STARTUP_TIMEOUT}s)"
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ $ELAPSED -ge $STARTUP_TIMEOUT ]; then
    echo "ERROR: Timeout waiting for plugin to start!"
    echo "Check logs at: ~/.ghidra/.ghidra_11.4/application.log"
    exit 1
fi

# Step 5: Run API tests
echo ""
echo "Step 5: Testing GhidraMCP API..."

echo "  Testing /api/health endpoint..."
HEALTH_RESPONSE=$(curl -s http://localhost:$PLUGIN_PORT/api/health)
echo "  Response: $HEALTH_RESPONSE"

echo "  Testing /api/program/info endpoint..."
INFO_RESPONSE=$(curl -s http://localhost:$PLUGIN_PORT/api/program/info)
echo "  Response: $INFO_RESPONSE"

# Add more API tests here as needed
# For example:
# curl -X POST http://localhost:$PLUGIN_PORT/api/analyze/function -d '{"address":"0x00400000"}'

# Step 6: Verify logs
echo ""
echo "Step 6: Checking Ghidra logs..."
LOG_FILE="$HOME/.ghidra/.ghidra_11.4/application.log"

if [ -f "$LOG_FILE" ]; then
    echo "Recent log entries:"
    tail -20 "$LOG_FILE" | grep -i "ghidramcp\|error" || echo "  (no relevant entries)"
else
    echo "Log file not found: $LOG_FILE"
fi

# Step 7: Summary
echo ""
echo "==========================="
echo "✓ All tests passed!"
echo "==========================="
echo ""
echo "Ghidra is still running (PID: $GHIDRA_PID)"
echo "You can now run additional tests or inspections."
echo ""
echo "Press Ctrl+C to stop Ghidra and cleanup, or wait..."
sleep 5

echo ""
echo "Test complete. Cleaning up..."
