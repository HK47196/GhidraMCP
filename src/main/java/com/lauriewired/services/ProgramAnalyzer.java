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
}
