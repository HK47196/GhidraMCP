package com.ghidramcp.services;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;

import java.util.*;

/**
 * Service for building and analyzing function call graphs
 */
public class FunctionCallGraphService {

    private final FunctionNavigator navigator;

    public FunctionCallGraphService(FunctionNavigator navigator) {
        this.navigator = navigator;
    }

    /**
     * Get a hierarchical tree of functions called by the given function
     * @param addressStr Starting function address
     * @param depth Maximum depth to traverse (default 1)
     * @return Formatted tree string
     */
    public String getFunctionCallees(String addressStr, int depth) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (depth < 1) return "Depth must be at least 1";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) {
                func = program.getFunctionManager().getFunctionContaining(addr);
            }

            if (func == null) {
                return "No function found at address " + addressStr;
            }

            StringBuilder result = new StringBuilder();
            Set<Address> visited = new HashSet<>();

            // Build the tree starting from the root function
            buildCallTree(program, func, 0, depth, visited, result, "", true);

            return result.toString().trim();
        } catch (Exception e) {
            return "Error building call graph: " + e.getMessage();
        }
    }

    /**
     * Recursively build the call tree
     * @param program The program being analyzed
     * @param func The current function
     * @param currentDepth Current depth in the tree
     * @param maxDepth Maximum depth to traverse
     * @param visited Set of visited function addresses to detect cycles
     * @param result StringBuilder to accumulate the tree output
     * @param prefix Current line prefix for tree formatting
     * @param isLast Whether this is the last child at this level
     */
    private void buildCallTree(Program program, Function func, int currentDepth, int maxDepth,
                               Set<Address> visited, StringBuilder result, String prefix, boolean isLast) {

        Address entryPoint = func.getEntryPoint();

        // Format the current function node
        if (currentDepth == 0) {
            // Root node
            result.append(String.format("%s (%s)\n", func.getName(), entryPoint));
        } else {
            // Child node with tree characters
            String connector = isLast ? "└─" : "├─";
            result.append(String.format("%s%s %s (%s)\n", prefix, connector, func.getName(), entryPoint));
        }

        // Check if we've reached max depth or if we've already visited this function
        if (currentDepth >= maxDepth) {
            return;
        }

        // Mark as visited for this branch (but allow revisiting in other branches at same depth)
        if (visited.contains(entryPoint)) {
            // Show cycle detection
            String childPrefix = prefix + (isLast ? "    " : "│   ");
            result.append(childPrefix).append("└─ [circular reference detected]\n");
            return;
        }

        visited.add(entryPoint);

        // Get all call references from this function
        List<Function> callees = getCallees(program, func);

        // Process each callee
        for (int i = 0; i < callees.size(); i++) {
            Function callee = callees.get(i);
            boolean isLastCallee = (i == callees.size() - 1);

            // Calculate the prefix for the next level
            String childPrefix = prefix + (isLast ? "    " : "│   ");

            // Recursively build the tree for this callee
            Set<Address> childVisited = new HashSet<>(visited);
            buildCallTree(program, callee, currentDepth + 1, maxDepth, childVisited, result, childPrefix, isLastCallee);
        }

        visited.remove(entryPoint);
    }

    /**
     * Get all functions called by the given function
     * @param program The program
     * @param func The function to analyze
     * @return List of called functions
     */
    private List<Function> getCallees(Program program, Function func) {
        List<Function> callees = new ArrayList<>();
        Set<Address> seenAddresses = new HashSet<>();

        // Iterate through all addresses in the function body
        Address minAddr = func.getBody().getMinAddress();
        Address maxAddr = func.getBody().getMaxAddress();

        ReferenceIterator refIter = program.getReferenceManager().getReferenceIterator(minAddr);

        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            Address fromAddr = ref.getFromAddress();

            // Only process references within this function's body
            if (fromAddr.compareTo(minAddr) < 0 || fromAddr.compareTo(maxAddr) > 0) {
                break;
            }

            RefType refType = ref.getReferenceType();

            // Only process call-type references
            if (refType.isCall() || refType.isJump()) {
                Address toAddr = ref.getToAddress();

                // Avoid duplicates
                if (seenAddresses.contains(toAddr)) {
                    continue;
                }
                seenAddresses.add(toAddr);

                Function callee = program.getFunctionManager().getFunctionAt(toAddr);
                if (callee != null) {
                    callees.add(callee);
                }
            }
        }

        // Sort by address for consistent output
        callees.sort(Comparator.comparing(f -> f.getEntryPoint()));

        return callees;
    }
}
