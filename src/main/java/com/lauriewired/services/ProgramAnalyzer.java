package com.lauriewired.services;

import com.lauriewired.util.PluginUtils;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.util.*;

/**
 * Service for listing and querying program entities
 */
public class ProgramAnalyzer {

    private final FunctionNavigator navigator;

    public ProgramAnalyzer(FunctionNavigator navigator) {
        this.navigator = navigator;
    }

    /**
     * Get all function names with pagination
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of function names
     */
    public String getAllFunctionNames(int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return PluginUtils.paginateList(names, offset, limit);
    }

    /**
     * Get all class names with pagination
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of class names
     */
    public String getAllClassNames(int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return PluginUtils.paginateList(sorted, offset, limit);
    }

    /**
     * List memory segments with pagination
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of memory segments
     */
    public String listSegments(int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return PluginUtils.paginateList(lines, offset, limit);
    }

    /**
     * List imported symbols with pagination
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of imports
     */
    public String listImports(int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return PluginUtils.paginateList(lines, offset, limit);
    }

    /**
     * List exported symbols with pagination
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of exports
     */
    public String listExports(int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return PluginUtils.paginateList(lines, offset, limit);
    }

    /**
     * List namespaces with pagination
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of namespaces
     */
    public String listNamespaces(int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return PluginUtils.paginateList(sorted, offset, limit);
    }

    /**
     * List defined data with pagination
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of defined data
     */
    public String listDefinedData(int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        PluginUtils.escapeNonAscii(label),
                        PluginUtils.escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return PluginUtils.paginateList(lines, offset, limit);
    }

    /**
     * List all functions (no pagination)
     * @return Formatted list of all functions
     */
    public String listFunctions() {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n",
                func.getName(),
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Search for functions by name
     * @param searchTerm Search term (substring match)
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of matching functions
     */
    public String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";

        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return PluginUtils.paginateList(matches, offset, limit);
    }

    /**
     * List defined strings with optional filtering
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @param filter Optional filter string (substring match on string value)
     * @return Paginated list of strings
     */
    public String listDefinedStrings(int offset, int limit, String filter) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }

        return PluginUtils.paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     * @param data Data to check
     * @return true if data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;

        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     * @param input String to escape
     * @return Escaped string
     */
    private String escapeString(String input) {
        if (input == null) return "";

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * List functions within a segment or address range with pagination
     * @param segmentName Name of the memory segment (e.g., "CODE_70")
     * @param startAddress Start address of range (if segmentName is null)
     * @param endAddress End address of range (if segmentName is null)
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of functions with name, address (segment:offset format), and size
     */
    public String listFunctionsBySegment(String segmentName, String startAddress, String endAddress, int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        MemoryBlock targetBlock = null;
        ghidra.program.model.address.Address start = null;
        ghidra.program.model.address.Address end = null;

        // Determine the address range
        if (segmentName != null && !segmentName.isEmpty()) {
            // Find segment by name
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (block.getName().equals(segmentName)) {
                    targetBlock = block;
                    start = block.getStart();
                    end = block.getEnd();
                    break;
                }
            }
            if (targetBlock == null) {
                return "Segment not found: " + segmentName;
            }
        } else if (startAddress != null && endAddress != null) {
            // Use provided address range
            try {
                start = program.getAddressFactory().getAddress(startAddress);
                end = program.getAddressFactory().getAddress(endAddress);
            } catch (Exception e) {
                return "Invalid address range: " + e.getMessage();
            }
        } else {
            return "Either segment_name or start_address/end_address must be provided";
        }

        // Collect functions within the range
        List<String> lines = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            ghidra.program.model.address.Address entryPoint = func.getEntryPoint();
            if (entryPoint.compareTo(start) >= 0 && entryPoint.compareTo(end) <= 0) {
                // Find which segment this function is in for proper formatting
                MemoryBlock funcBlock = program.getMemory().getBlock(entryPoint);
                String segOffset = formatSegmentOffset(entryPoint, funcBlock);
                long size = func.getBody().getNumAddresses();

                lines.add(String.format("%s @ %s (size: %d bytes)",
                    func.getName(),
                    segOffset,
                    size
                ));
            }
        }

        if (lines.isEmpty()) {
            return segmentName != null ?
                "No functions found in segment: " + segmentName :
                "No functions found in address range";
        }

        return PluginUtils.paginateList(lines, offset, limit);
    }

    /**
     * List data items within a segment or address range with pagination
     * @param segmentName Name of the memory segment (e.g., "CODE_70")
     * @param startAddress Start address of range (if segmentName is null)
     * @param endAddress End address of range (if segmentName is null)
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of data items with label, address (segment:offset format), type, and value
     */
    public String listDataBySegment(String segmentName, String startAddress, String endAddress, int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        MemoryBlock targetBlock = null;
        ghidra.program.model.address.Address start = null;
        ghidra.program.model.address.Address end = null;

        // Determine the address range
        if (segmentName != null && !segmentName.isEmpty()) {
            // Find segment by name
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (block.getName().equals(segmentName)) {
                    targetBlock = block;
                    start = block.getStart();
                    end = block.getEnd();
                    break;
                }
            }
            if (targetBlock == null) {
                return "Segment not found: " + segmentName;
            }
        } else if (startAddress != null && endAddress != null) {
            // Use provided address range
            try {
                start = program.getAddressFactory().getAddress(startAddress);
                end = program.getAddressFactory().getAddress(endAddress);
            } catch (Exception e) {
                return "Invalid address range: " + e.getMessage();
            }
        } else {
            return "Either segment_name or start_address/end_address must be provided";
        }

        // Collect data items within the range
        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(start, true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            ghidra.program.model.address.Address addr = data.getAddress();

            // Check if within range
            if (addr.compareTo(start) >= 0 && addr.compareTo(end) <= 0) {
                // Find which segment this data is in for proper formatting
                MemoryBlock dataBlock = program.getMemory().getBlock(addr);
                String segOffset = formatSegmentOffset(addr, dataBlock);

                String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                String typeName = data.getDataType() != null ? data.getDataType().getName() : "undefined";
                String value = data.getDefaultValueRepresentation();

                lines.add(String.format("%s @ %s [%s] = %s",
                    PluginUtils.escapeNonAscii(label),
                    segOffset,
                    typeName,
                    PluginUtils.escapeNonAscii(value)
                ));
            }
        }

        if (lines.isEmpty()) {
            return segmentName != null ?
                "No data items found in segment: " + segmentName :
                "No data items found in address range";
        }

        return PluginUtils.paginateList(lines, offset, limit);
    }

    /**
     * Format an address as segment:offset
     * @param addr Address to format
     * @param block Memory block containing the address (unused, kept for compatibility)
     * @return Formatted address string
     */
    private String formatSegmentOffset(ghidra.program.model.address.Address addr, MemoryBlock block) {
        // Return the address in Ghidra's native format (e.g., "4608:000e")
        // This matches the actual binary segment:offset addressing
        return addr.toString();
    }

    /**
     * Get data information at a specific address
     * @param addressStr Address string (e.g., "5356:3cd8" or "0x1400010a0")
     * @return Data information including name, type, and value
     */
    public String getDataByAddress(String addressStr) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        if (addressStr == null || addressStr.isEmpty()) {
            return "Error: Address is required";
        }

        try {
            // Parse the address
            ghidra.program.model.address.Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "Error: Invalid address format: " + addressStr;
            }

            // Get the data at this address
            Data data = program.getListing().getDataAt(addr);
            if (data == null) {
                return "Error: No data defined at address " + addressStr;
            }

            // Build the result
            StringBuilder result = new StringBuilder();
            result.append("Address: ").append(addr.toString()).append("\n");

            // Get the name/label
            String label = data.getLabel();
            if (label != null && !label.isEmpty()) {
                result.append("Name: ").append(PluginUtils.escapeNonAscii(label)).append("\n");
            } else {
                result.append("Name: (unnamed)\n");
            }

            // Get the type
            DataType dataType = data.getDataType();
            if (dataType != null) {
                result.append("Type: ").append(dataType.getDisplayName()).append("\n");
            } else {
                result.append("Type: undefined\n");
            }

            // Get the value
            String value = data.getDefaultValueRepresentation();
            if (value != null && !value.isEmpty()) {
                result.append("Value: ").append(PluginUtils.escapeNonAscii(value)).append("\n");
            } else {
                result.append("Value: (no value)\n");
            }

            // Get the size
            result.append("Size: ").append(data.getLength()).append(" bytes\n");

            return result.toString();

        } catch (Exception e) {
            return "Error getting data at address " + addressStr + ": " + e.getMessage();
        }
    }
}
