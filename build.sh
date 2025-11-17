#!/bin/bash
# Build and test script for GhidraMCP
# Handles both Java (Maven) and Python (pytest) components

set -e  # Exit immediately if any command fails

echo "=== GhidraMCP Build and Test ==="
echo

# 1. Setup Python virtual environment
echo "Setting up Python environment..."
if [ ! -d "venv" ]; then
    echo "  Creating virtual environment..."
    python3 -m venv venv
fi

echo "  Activating virtual environment..."
source venv/bin/activate

echo "  Installing Python dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "  Python environment ready"
echo

# 2. Run Maven build (compiles Java code, runs Java tests, creates JAR and ZIP)
echo "Running Maven build (includes Java tests)..."
mvn clean package

echo

# 3. Run Python tests
echo "Running Python tests..."
pytest

echo
echo "=== All tests passed! Build successful ==="
echo "Output artifacts:"
echo "  - target/GhidraMCP.jar"
echo "  - target/GhidraMCP-1.0-SNAPSHOT.zip"
