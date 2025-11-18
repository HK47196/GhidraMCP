package com.ghidramcp.services;

import ghidra.program.model.listing.Data;

/**
 * Result of looking up data at an address, including composite type handling.
 * Used by both ProgramAnalyzer and DisassemblyService.
 */
public class DataLookupResult {
    private final Data data;
    private final Data containingData;
    private final int componentIndex;
    private final int offsetInParent;

    public DataLookupResult(Data data, Data containingData, int componentIndex, int offsetInParent) {
        this.data = data;
        this.containingData = containingData;
        this.componentIndex = componentIndex;
        this.offsetInParent = offsetInParent;
    }

    /** The data/component found at the address */
    public Data getData() { return data; }

    /** Parent composite type, or null if data is at top level */
    public Data getContainingData() { return containingData; }

    /** Index within parent composite (-1 if top level or not found) */
    public int getComponentIndex() { return componentIndex; }

    /** Byte offset within parent composite */
    public int getOffsetInParent() { return offsetInParent; }

    /** Whether this is a component inside a composite type */
    public boolean isComponent() { return containingData != null; }
}
