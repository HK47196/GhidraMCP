#!/bin/bash
set -e

cd "$(dirname "$0")"

# Ensure binaries directory exists
mkdir -p binaries

# Build C test binary
echo "Building C test binary..."
gcc test_source.c -o binaries/test_simple -g -O0
echo "  Built: binaries/test_simple"
file binaries/test_simple

# Build C++ test binary
# Flags:
#   -g: Debug symbols (DWARF info for class detection)
#   -O0: No optimization (preserves structure)
#   -frtti: Enable RTTI (type info for class detection)
#   -fno-omit-frame-pointer: Better stack traces
echo ""
echo "Building C++ test binary..."
g++ test_source_cpp.cpp -o binaries/test_cpp -g -O0 -frtti -fno-omit-frame-pointer
echo "  Built: binaries/test_cpp"
file binaries/test_cpp

echo ""
echo "All test binaries built successfully!"
ls -la binaries/
