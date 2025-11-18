package com.ghidramcp.services;

import com.ghidramcp.util.PluginUtils;
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
    private final DataLookupService dataLookupService;

    public ProgramAnalyzer(FunctionNavigator navigator) {
        this.navigator = navigator;
        this.dataLookupService = new DataLookupService();
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
        return getAllClassNames(offset, limit, null);
    }

    /**
     * Get all class names with pagination and optional search filter
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @param search Optional search string for filtering (case-insensitive substring match)
     * @return Paginated list of class names
     */
    public String getAllClassNames(int offset, int limit, String search) {
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

        // Apply search filter if provided
        if (search != null && !search.isEmpty()) {
            String searchLower = search.toLowerCase();
            sorted = sorted.stream()
                .filter(name -> name.toLowerCase().contains(searchLower))
                .collect(java.util.stream.Collectors.toList());
        }

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
     * Search for functions by name with optional namespace support
     * @param searchTerm Search term (substring match) - used when not doing namespace search
     * @param namespace Namespace to search within (e.g., "Compression" for C++)
     * @param functionName Function name within namespace (can be null/empty for all functions in namespace)
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of matching functions
     */
    public String searchFunctionsByName(String searchTerm, String namespace, String functionName, int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> matches = new ArrayList<>();

        // Namespace-based search
        if (namespace != null && !namespace.isEmpty()) {
            // Search for functions in a specific namespace
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                Namespace funcNamespace = func.getParentNamespace();

                // Check if function is in the specified namespace
                if (funcNamespace != null && matchesNamespace(funcNamespace, namespace)) {
                    String funcName = func.getName();

                    // If functionName is specified, filter by it (substring match)
                    if (functionName == null || functionName.isEmpty() ||
                        funcName.toLowerCase().contains(functionName.toLowerCase())) {
                        // Format with full namespace path
                        String fullName = getFullyQualifiedName(func);
                        matches.add(String.format("%s @ %s", fullName, func.getEntryPoint()));
                    }
                }
            }

            Collections.sort(matches);

            if (matches.isEmpty()) {
                if (functionName != null && !functionName.isEmpty()) {
                    return "No functions matching '" + functionName + "' in namespace '" + namespace + "'";
                } else {
                    return "No functions found in namespace '" + namespace + "'";
                }
            }
            return PluginUtils.paginateList(matches, offset, limit);
        }

        // Standard substring search (original behavior)
        if (searchTerm == null || searchTerm.isEmpty()) {
            return "Search term is required";
        }

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
     * Check if a namespace matches the target namespace name
     * Handles nested namespaces by checking the full path
     * @param funcNamespace The function's namespace
     * @param targetNamespace The target namespace to match (e.g., "Compression" or "std::vector")
     * @return true if namespace matches
     */
    private boolean matchesNamespace(Namespace funcNamespace, String targetNamespace) {
        if (funcNamespace == null || targetNamespace == null) {
            return false;
        }

        // Build the full namespace path for this function
        String fullPath = getNamespacePath(funcNamespace);

        // Check for exact match or if it starts with the target namespace
        // This handles both "Compression" and "std::vector" style namespaces
        return fullPath.equals(targetNamespace) ||
               fullPath.startsWith(targetNamespace + "::");
    }

    /**
     * Get the full namespace path for a namespace
     * @param namespace The namespace
     * @return Full path (e.g., "std::vector" or "Compression")
     */
    private String getNamespacePath(Namespace namespace) {
        if (namespace == null || namespace.isGlobal()) {
            return "";
        }

        List<String> parts = new ArrayList<>();
        Namespace current = namespace;

        while (current != null && !current.isGlobal()) {
            parts.add(0, current.getName());
            current = current.getParentNamespace();
        }

        return String.join("::", parts);
    }

    /**
     * Get the fully qualified name of a function (including namespace)
     * @param func The function
     * @return Fully qualified name (e.g., "Compression::compress" or "std::vector::push_back")
     */
    private String getFullyQualifiedName(Function func) {
        if (func == null) {
            return "";
        }

        Namespace namespace = func.getParentNamespace();
        if (namespace == null || namespace.isGlobal()) {
            return func.getName();
        }

        String namespacePath = getNamespacePath(namespace);
        if (namespacePath.isEmpty()) {
            return func.getName();
        }

        return namespacePath + "::" + func.getName();
    }

    /**
     * Search for data by label/name
     * @param searchTerm Search term (substring match)
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Paginated list of matching data variables
     */
    public String searchDataByName(String searchTerm, int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";

        List<String> matches = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data == null) continue;

            String label = data.getLabel();
            if (label != null && label.toLowerCase().contains(searchTerm.toLowerCase())) {
                String typeName = data.getDataType() != null ? data.getDataType().getDisplayName() : "undefined";
                matches.add(String.format("%s @ %s (type: %s)", label, data.getAddress(), typeName));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return "No data variables matching '" + searchTerm + "'";
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

            // Use shared lookup service
            DataLookupResult lookup = dataLookupService.lookupDataAtAddress(program, addr);
            if (lookup == null) {
                return "Error: No data defined at address " + addressStr;
            }

            Data data = lookup.getData();

            // Build the result
            StringBuilder result = new StringBuilder();
            result.append("Address: ").append(addr.toString()).append("\n");

            // Get the name/label
            String label = data.getLabel();
            if (label != null && !label.isEmpty()) {
                result.append("Name: ").append(PluginUtils.escapeNonAscii(label)).append("\n");
            } else {
                // For struct/array members, try to get the field name
                String fieldName = data.getFieldName();
                if (fieldName != null && !fieldName.isEmpty()) {
                    result.append("Name: ").append(PluginUtils.escapeNonAscii(fieldName)).append("\n");
                } else {
                    result.append("Name: (unnamed)\n");
                }
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

            // If this is a component of a larger structure, show parent info
            if (lookup.isComponent()) {
                Data containingData = lookup.getContainingData();
                result.append("\n--- Parent Structure ---\n");
                result.append("Parent Address: ").append(containingData.getAddress().toString()).append("\n");

                String parentLabel = containingData.getLabel();
                if (parentLabel != null && !parentLabel.isEmpty()) {
                    result.append("Parent Name: ").append(PluginUtils.escapeNonAscii(parentLabel)).append("\n");
                }

                DataType parentType = containingData.getDataType();
                if (parentType != null) {
                    result.append("Parent Type: ").append(parentType.getDisplayName()).append("\n");
                }

                result.append("Parent Size: ").append(containingData.getLength()).append(" bytes\n");
                result.append("Offset in Parent: ").append(lookup.getOffsetInParent()).append("\n");

                if (lookup.getComponentIndex() >= 0) {
                    result.append("Component Index: ").append(lookup.getComponentIndex()).append("\n");
                }
            }

            return result.toString();

        } catch (Exception e) {
            return "Error getting data at address " + addressStr + ": " + e.getMessage();
        }
    }

    /**
     * Get all data items within an address range, optionally including undefined data.
     * This is useful for seeing what's defined around a specific address without global pagination.
     *
     * @param startAddress Start address of range (e.g., "0x00231fec")
     * @param endAddress End address of range (e.g., "0x00232100")
     * @param includeUndefined If true, include undefined data items in the range
     * @return Formatted list of data items in the range
     */
    public String getDataInRange(String startAddress, String endAddress, boolean includeUndefined) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";

        if (startAddress == null || startAddress.isEmpty()) {
            return "Error: Start address is required";
        }
        if (endAddress == null || endAddress.isEmpty()) {
            return "Error: End address is required";
        }

        try {
            // Parse addresses
            ghidra.program.model.address.Address start = program.getAddressFactory().getAddress(startAddress);
            ghidra.program.model.address.Address end = program.getAddressFactory().getAddress(endAddress);

            if (start == null) {
                return "Error: Invalid start address format: " + startAddress;
            }
            if (end == null) {
                return "Error: Invalid end address format: " + endAddress;
            }

            if (start.compareTo(end) > 0) {
                return "Error: Start address must be less than or equal to end address";
            }

            // Build result
            StringBuilder result = new StringBuilder();
            result.append(String.format("Data items from %s to %s (include_undefined=%s):\n\n",
                start.toString(), end.toString(), includeUndefined));

            List<String> items = new ArrayList<>();

            // Get the appropriate data iterator based on includeUndefined flag
            DataIterator dataIt;
            if (includeUndefined) {
                // Get all data (including undefined)
                dataIt = program.getListing().getData(start, true);
            } else {
                // Get only defined data
                dataIt = program.getListing().getDefinedData(start, true);
            }

            int count = 0;
            while (dataIt.hasNext()) {
                Data data = dataIt.next();
                ghidra.program.model.address.Address addr = data.getAddress();

                // Check if within range
                if (addr.compareTo(start) >= 0 && addr.compareTo(end) <= 0) {
                    // Find which segment this data is in for proper formatting
                    MemoryBlock dataBlock = program.getMemory().getBlock(addr);
                    String segOffset = formatSegmentOffset(addr, dataBlock);

                    String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    DataType dataType = data.getDataType();
                    String typeName = dataType != null ? dataType.getName() : "undefined";
                    String value = data.getDefaultValueRepresentation();
                    int size = data.getLength();

                    items.add(String.format("%s: %s [%s, %d bytes] = %s",
                        segOffset,
                        PluginUtils.escapeNonAscii(label),
                        typeName,
                        size,
                        PluginUtils.escapeNonAscii(value)
                    ));
                    count++;
                } else if (addr.compareTo(end) > 0) {
                    // We've passed the end of the range, stop iterating
                    break;
                }
            }

            if (count == 0) {
                result.append("No data items found in the specified range\n");
            } else {
                for (String item : items) {
                    result.append(item).append("\n");
                }
                result.append(String.format("\nTotal: %d item(s)\n", count));
            }

            return result.toString();

        } catch (Exception e) {
            return "Error getting data in range: " + e.getMessage();
        }
    }
}
