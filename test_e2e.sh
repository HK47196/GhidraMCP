#!/bin/bash
# E2E tests for GhidraMCP
# Runs comprehensive integration tests using Docker

set -e  # Exit immediately if any command fails

echo "=== GhidraMCP E2E Tests ==="
echo

echo "Running E2E tests in Docker..."
docker-compose -f test-infrastructure/docker/docker-compose.yml run --build --rm ghidra-mcp-tests

echo
echo "=== E2E tests passed! ==="
