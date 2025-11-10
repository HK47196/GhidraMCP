#!/bin/bash

# Check if Ghidra directory is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <ghidra_directory>"
    echo "Example: $0 /path/to/ghidra_11.0"
    exit 1
fi

GHIDRA_DIR="$1"
LIB_DIR="lib"

# Check if Ghidra directory exists
if [ ! -d "$GHIDRA_DIR" ]; then
    echo "Error: Ghidra directory '$GHIDRA_DIR' does not exist"
    exit 1
fi

# Create lib directory if it doesn't exist
mkdir -p "$LIB_DIR"

# Array of files to copy (source:destination pairs)
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
    "Ghidra/Features/BSim/lib/commons-dbcp2-2.9.0.jar:commons-dbcp2-2.9.0.jar"
    "Ghidra/Features/BSim/lib/commons-logging-1.2.jar:commons-logging-1.2.jar"
    "Ghidra/Features/BSim/lib/commons-pool2-2.11.1.jar:commons-pool2-2.11.1.jar"
    "Ghidra/Features/BSim/lib/h2-2.2.220.jar:h2-2.2.220.jar"
    "Ghidra/Features/BSim/lib/postgresql-42.7.6.jar:postgresql-42.7.6.jar"
)

# Copy files
echo "Copying files from $GHIDRA_DIR to $LIB_DIR..."
FAILED=0

for file_pair in "${FILES[@]}"; do
    IFS=':' read -r source dest <<< "$file_pair"
    source_path="$GHIDRA_DIR/$source"
    dest_path="$LIB_DIR/$dest"
    
    if [ -f "$source_path" ]; then
        cp "$source_path" "$dest_path"
        echo "✓ Copied $dest"
    else
        echo "✗ Not found: $source_path"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
if [ $FAILED -eq 0 ]; then
    echo "All files copied successfully!"
    exit 0
else
    echo "Warning: $FAILED file(s) could not be found"
    exit 1
fi
