package com.ghidramcp.services;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.*;

/**
 * Service for decompilation and data reference operations
 */
public class DecompilationService {

    private final FunctionNavigator navigator;
    private final int decompileTimeout;

    public DecompilationService(FunctionNavigator navigator, int decompileTimeout) {
        this.navigator = navigator;
        this.decompileTimeout = decompileTimeout;
    }

    /**
     * Decompile a function by name
     * @param name Function name
     * @return Decompiled C code or error message
     */
    public String decompileFunctionByName(String name) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, this.decompileTimeout, new ConsoleTaskMonitor());
                decomp.flushCache();
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    /**
     * Decompile a function by address
     * @param addressStr Address as string
     * @return Decompiled C code or error message
     */
    public String decompileFunctionByAddress(String addressStr) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = navigator.getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            String decompCode = decompileFunctionInProgram(func, program);
            return (decompCode != null && !decompCode.isEmpty())
                ? decompCode
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Decompile a function within a program
     * @param func Function to decompile
     * @param program Program containing the function
     * @return Decompiled C code or null
     */
    public String decompileFunctionInProgram(Function func, Program program) {
        try {
            DecompInterface decomp = new DecompInterface();
            DecompileOptions options = new DecompileOptions();
            decomp.setOptions(options);
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, this.decompileTimeout, new ConsoleTaskMonitor());
            decomp.flushCache();

            if (result != null && result.decompileCompleted()) {
                return result.getDecompiledFunction().getC();
            }
        } catch (Exception e) {
            Msg.error(this, "Error decompiling function in external program", e);
        }
        return null;
    }

    /**
     * Helper method to decompile a function and return results
     * @param func Function to decompile
     * @param program Program containing the function
     * @return Decompilation results or null
     */
    public DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, this.decompileTimeout, new ConsoleTaskMonitor());
        decomp.flushCache();

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    // ==================== DATA REFERENCES ====================

    /**
     * Container for data reference information
     */
    public static class DataReference {
        public final Address fromAddress;      // Where the reference originates
        public final Address toAddress;        // Where the data is located
        public final Reference reference;      // The reference object
        public final Data data;                // The data object
        public final String label;             // Symbol/label (e.g., "DAT_0022d5f6")
        public final String dataType;          // Data type (e.g., "dword", "char[10]")
        public final Object value;             // Data value (if available)

        public DataReference(Address from, Address to, Reference ref, Data data) {
            this.fromAddress = from;
            this.toAddress = to;
            this.reference = ref;
            this.data = data;

            // Get label/symbol
            Symbol symbol = data.getProgram().getSymbolTable().getPrimarySymbol(to);
            this.label = symbol != null ? symbol.getName() : to.toString();

            // Get data type
            this.dataType = data.getDataType().getDisplayName();

            // Get value (may be null for some types)
            Object tempValue;
            try {
                tempValue = data.getValue();
            } catch (Exception e) {
                tempValue = null;
            }
            this.value = tempValue;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(label);
            sb.append(" (").append(toAddress).append(")");
            sb.append(" - Type: ").append(dataType);
            if (value != null) {
                sb.append(", Value: ").append(value);
            }
            return sb.toString();
        }
    }

    /**
     * Get all data references from a function
     * @param func Function to analyze
     * @param program Program containing the function
     * @return List of data references with details
     */
    public List<DataReference> getDataReferencesFromFunction(Function func, Program program) {
        List<DataReference> dataRefs = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();
        Listing listing = program.getListing();
        Set<Address> seenAddresses = new HashSet<>();  // Avoid duplicates

        // Get all addresses in the function body
        AddressSetView functionBody = func.getBody();

        // Iterate through all addresses in the function
        AddressIterator addrIter = functionBody.getAddresses(true);
        while (addrIter.hasNext()) {
            Address fromAddr = addrIter.next();

            // Get all references FROM this address
            Reference[] refs = refMgr.getReferencesFrom(fromAddr);
            for (Reference ref : refs) {
                // Skip if not a memory reference
                if (!ref.isMemoryReference()) {
                    continue;
                }

                Address toAddr = ref.getToAddress();

                // Skip if we've already seen this data address
                if (seenAddresses.contains(toAddr)) {
                    continue;
                }

                // Check if the destination is data (not an instruction)
                Data data = listing.getDataAt(toAddr);
                if (data == null) {
                    continue;
                }

                seenAddresses.add(toAddr);
                dataRefs.add(new DataReference(fromAddr, toAddr, ref, data));
            }
        }

        // Sort by data address for consistent output
        dataRefs.sort((a, b) -> a.toAddress.compareTo(b.toAddress));

        return dataRefs;
    }

    /**
     * Get data references from a function as formatted text
     * @param func Function to analyze
     * @param program Program containing the function
     * @return Formatted string with data references
     */
    public String getDataReferencesAsText(Function func, Program program) {
        List<DataReference> dataRefs = getDataReferencesFromFunction(func, program);

        StringBuilder result = new StringBuilder();
        result.append("Data references from ").append(func.getName());
        result.append(" (").append(func.getEntryPoint()).append("):\n\n");

        if (dataRefs.isEmpty()) {
            result.append("  No data references found.\n");
            return result.toString();
        }

        // Calculate column widths for alignment
        int maxLabelLen = 20;
        for (DataReference ref : dataRefs) {
            maxLabelLen = Math.max(maxLabelLen, ref.label.length());
        }

        // Header
        result.append(String.format("  %-" + maxLabelLen + "s  %-12s  %-20s  %-12s  %s\n",
            "Symbol", "Address", "Type", "RefFrom", "Value"));
        result.append("  " + "-".repeat(maxLabelLen + 70) + "\n");

        // Data references
        for (DataReference ref : dataRefs) {
            String valueStr = ref.value != null ? ref.value.toString() : "";
            // Handle string values specially
            if (ref.data.hasStringValue()) {
                try {
                    Object strValue = ref.data.getValue();
                    if (strValue != null) {
                        valueStr = "\"" + strValue.toString() + "\"";
                    }
                } catch (Exception e) {
                    // Keep default valueStr
                }
            }

            if (valueStr.length() > 40) {
                valueStr = valueStr.substring(0, 37) + "...";
            }

            result.append(String.format("  %-" + maxLabelLen + "s  %-12s  %-20s  %-12s  %s\n",
                ref.label,
                ref.toAddress.toString(),
                ref.dataType,
                ref.fromAddress.toString(),
                valueStr));
        }

        result.append("\n  Total: ").append(dataRefs.size()).append(" data references\n");

        return result.toString();
    }

    /**
     * Get data references from a function by name
     * @param functionName Function name
     * @return Formatted string with data references
     */
    public String getDataReferencesFromFunctionByName(String functionName) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(functionName)) {
                return getDataReferencesAsText(func, program);
            }
        }
        return "Function not found: " + functionName;
    }

    /**
     * Get data references from a function by address
     * @param addressStr Address as string
     * @return Formatted string with data references
     */
    public String getDataReferencesFromFunctionByAddress(String addressStr) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = navigator.getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            return getDataReferencesAsText(func, program);
        } catch (Exception e) {
            return "Error getting data references: " + e.getMessage();
        }
    }
}
