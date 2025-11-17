#!/bin/bash
set -e

echo "========================================="
echo "Building GhidraMCP plugin..."
echo "========================================="

# Build the plugin (clean ensures fresh build, skip unit tests)
# -q = quiet mode (less verbose output)
# -ntp = no transfer progress (cleaner output)
# Filter out systemPath warnings but don't fail if grep finds nothing
mvn clean package -DskipTests -q -ntp 2>&1 | { grep -v "systemPath" || true; }
BUILD_STATUS=${PIPESTATUS[0]}

if [ $BUILD_STATUS -ne 0 ]; then
    echo ""
    echo "========================================="
    echo "ERROR: Maven build failed!"
    echo "Re-running with verbose output..."
    echo "========================================="
    echo ""
    mvn clean package -DskipTests
    exit 1
fi

echo ""
echo "========================================="
echo "Plugin built successfully!"
echo "Running E2E tests..."
echo "========================================="
echo ""

# Clear Python bytecode cache to ensure fresh test code
echo "Clearing Python bytecode cache..."
find /workspace -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find /workspace -type f -name "*.pyc" -delete 2>/dev/null || true

# Run pytest with all arguments passed to this script
# Use -vv for verbose output showing variable values in assertions
# Run all tests (unit + integration)
exec pytest tests/ -c test-infrastructure/pytest.ini --ghidra-dir=/opt/ghidra -vv "$@"
