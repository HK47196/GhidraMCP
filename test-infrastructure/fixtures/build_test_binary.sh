#!/bin/bash
set -e

cd "$(dirname "$0")"

gcc test_source.c -o binaries/test_simple -g -O0

echo "Test binary built: binaries/test_simple"
file binaries/test_simple
