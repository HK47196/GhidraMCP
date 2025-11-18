package com.ghidramcp.services;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

/**
 * Shared service for looking up data at addresses, including addresses
 * inside composite types (structs, arrays, unions).
 */
public class DataLookupService {

    /**
     * Find data at an address, handling composite types.
     *
     * @param program The Ghidra program
     * @param addr The address to look up
     * @return DataLookupResult with the data found, or null if no data at address
     */
    public DataLookupResult lookupDataAtAddress(Program program, Address addr) {
        if (program == null || addr == null) {
            return null;
        }

        // Try exact match first
        Data data = program.getListing().getDataAt(addr);
        if (data != null) {
            return new DataLookupResult(data, null, -1, 0);
        }

        // Check if inside composite type (struct/array/union)
        Data containing = program.getListing().getDataContaining(addr);
        if (containing == null) {
            return null; // No data at this address
        }

        int offsetInParent = (int)(addr.getOffset() - containing.getAddress().getOffset());

        // Find component by iterating through and comparing address ranges
        // This is more robust than offset calculation for nested types
        int numComponents = containing.getNumComponents();
        for (int i = 0; i < numComponents; i++) {
            Data comp = containing.getComponent(i);
            if (comp != null &&
                comp.getMinAddress().compareTo(addr) <= 0 &&
                comp.getMaxAddress().compareTo(addr) >= 0) {
                return new DataLookupResult(comp, containing, i, offsetInParent);
            }
        }

        // Component not found in iteration - fall back to getComponentAt
        // This can happen with certain data layouts
        Data componentData = containing.getComponentAt(offsetInParent);
        if (componentData != null) {
            return new DataLookupResult(componentData, containing, -1, offsetInParent);
        }

        // Last resort: return the containing data itself
        return new DataLookupResult(containing, null, -1, 0);
    }
}
