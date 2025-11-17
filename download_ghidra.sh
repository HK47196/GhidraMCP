#!/bin/bash
# Script to download and extract Ghidra libraries
# This is called automatically during the build process

set -e  # Exit on error

# Configuration - aligned with test-infrastructure/docker/Dockerfile
GHIDRA_VERSION="${GHIDRA_VERSION:-11.4.2}"
GHIDRA_DATE="${GHIDRA_DATE:-20250826}"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
DOWNLOAD_DIR="build/ghidra-download"
LIB_DIR="lib"

echo "=== Downloading Ghidra ${GHIDRA_VERSION} ==="

# Create directories
mkdir -p "$DOWNLOAD_DIR"
mkdir -p "$LIB_DIR"

# Check if we already have the required libraries
if [ -f "$LIB_DIR/Base.jar" ] && \
   [ -f "$LIB_DIR/Decompiler.jar" ] && \
   [ -f "$LIB_DIR/BSim.jar" ]; then
    echo "Libraries already exist in $LIB_DIR, skipping download"
    exit 0
fi

# Download Ghidra if not already downloaded
GHIDRA_ZIP="$DOWNLOAD_DIR/ghidra.zip"
if [ ! -f "$GHIDRA_ZIP" ]; then
    echo "Downloading Ghidra from $GHIDRA_URL..."
    wget -q -O "$GHIDRA_ZIP" "$GHIDRA_URL"
    echo "Download complete"
else
    echo "Using cached Ghidra download"
fi

# Extract Ghidra
echo "Extracting Ghidra..."
EXTRACT_DIR="$DOWNLOAD_DIR/extracted"
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
unzip -q "$GHIDRA_ZIP" -d "$EXTRACT_DIR"

# Find the Ghidra directory (it should be the only directory in EXTRACT_DIR)
GHIDRA_DIR=$(find "$EXTRACT_DIR" -maxdepth 1 -type d -name "ghidra_*" | head -n 1)

if [ -z "$GHIDRA_DIR" ]; then
    echo "Error: Could not find extracted Ghidra directory"
    exit 1
fi

echo "Found Ghidra at: $GHIDRA_DIR"

# Array of files to copy (source:destination pairs)
# Note: Some files use wildcards to handle version differences between Ghidra releases
declare -a FILES=(
    "Ghidra/Features/Base/lib/Base.jar:Base.jar"
    "Ghidra/Features/Decompiler/lib/Decompiler.jar:Decompiler.jar"
    "Ghidra/Features/DecompilerDependent/lib/DecompilerDependent.jar:DecompilerDependent.jar"
    "Ghidra/Framework/Docking/lib/Docking.jar:Docking.jar"
    "Ghidra/Framework/Generic/lib/Generic.jar:Generic.jar"
    "Ghidra/Framework/Project/lib/Project.jar:Project.jar"
    "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar:SoftwareModeling.jar"
    "Ghidra/Framework/Utility/lib/Utility.jar:Utility.jar"
    "Ghidra/Framework/Gui/lib/Gui.jar:Gui.jar"
    "Ghidra/Features/BSim/lib/BSim.jar:BSim.jar"
    "Ghidra/Features/BSim/lib/commons-dbcp2-*.jar:commons-dbcp2.jar"
    "Ghidra/Features/BSim/lib/commons-logging-*.jar:commons-logging.jar"
    "Ghidra/Features/BSim/lib/commons-pool2-*.jar:commons-pool2.jar"
    "Ghidra/Features/BSim/lib/h2-*.jar:h2.jar"
    "Ghidra/Features/BSim/lib/postgresql-*.jar:postgresql.jar"
)

# Copy files
echo "Copying libraries to $LIB_DIR..."
FAILED=0

for file_pair in "${FILES[@]}"; do
    IFS=':' read -r source dest <<< "$file_pair"
    source_pattern="$GHIDRA_DIR/$source"
    dest_path="$LIB_DIR/$dest"

    # Use glob pattern matching for files with wildcards
    if [[ "$source" == *"*"* ]]; then
        # Find the matching file(s)
        matching_files=($source_pattern)
        if [ -f "${matching_files[0]}" ]; then
            cp "${matching_files[0]}" "$dest_path"
            echo "  ✓ $dest (from $(basename "${matching_files[0]}"))"
        else
            echo "  ✗ Not found: $source"
            FAILED=$((FAILED + 1))
        fi
    else
        # Exact file match
        if [ -f "$source_pattern" ]; then
            cp "$source_pattern" "$dest_path"
            echo "  ✓ $dest"
        else
            echo "  ✗ Not found: $source"
            FAILED=$((FAILED + 1))
        fi
    fi
done

echo ""
if [ $FAILED -eq 0 ]; then
    echo "All libraries extracted successfully!"
    if [ "${SKIP_CLEANUP}" != "1" ]; then
        echo "Cleaning up extracted files..."
        rm -rf "$EXTRACT_DIR"
    fi
    echo "Done!"
    exit 0
else
    echo "Error: $FAILED file(s) could not be found"
    exit 1
fi
