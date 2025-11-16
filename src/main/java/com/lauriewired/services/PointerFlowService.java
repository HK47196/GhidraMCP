package com.lauriewired.services;

import com.lauriewired.model.XRefThroughResult;
import ghidra.program.model.listing.Program;

/**
 * Service for analyzing pointer dereferences (get_xrefs_through).
 * Provides methods to find all locations where code accesses memory through a pointer.
 */
public class PointerFlowService {

    private final FunctionNavigator navigator;
    private static final int DEFAULT_MAX_RESULTS = 100;

    public PointerFlowService(FunctionNavigator navigator) {
        this.navigator = navigator;
    }

    /**
     * Get cross-references through a pointer with all options.
     *
     * @param addressStr Address or symbol name of the pointer
     * @param maxDepth Search depth (1=local, -1=full program)
     * @param accessType Filter: "all", "read", or "write"
     * @param followAliases Whether to track pointer copies
     * @param maxResults Maximum results to return
     * @return Formatted string of analysis results
     */
    public String getXRefsThrough(String addressStr, int maxDepth, String accessType,
                                   boolean followAliases, int maxResults) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Address is required";
        }

        try {
            PointerFlowAnalyzer analyzer = new PointerFlowAnalyzer(program, maxResults);
            XRefThroughResult result = analyzer.analyzePointerFlow(
                addressStr, maxDepth, accessType, followAliases);

            return result.toFormattedString();

        } catch (Exception e) {
            return "Error analyzing pointer flow: " + e.getMessage();
        }
    }

    /**
     * Get cross-references through a pointer with default options.
     *
     * @param addressStr Address or symbol name of the pointer
     * @return Formatted string of analysis results
     */
    public String getXRefsThrough(String addressStr) {
        return getXRefsThrough(addressStr, 1, "all", true, DEFAULT_MAX_RESULTS);
    }

    /**
     * Get cross-references through a pointer with custom max results.
     *
     * @param addressStr Address or symbol name of the pointer
     * @param maxResults Maximum results to return
     * @return Formatted string of analysis results
     */
    public String getXRefsThrough(String addressStr, int maxResults) {
        return getXRefsThrough(addressStr, 1, "all", true, maxResults);
    }

    /**
     * Get cross-references through a pointer with access type filter.
     *
     * @param addressStr Address or symbol name of the pointer
     * @param accessType Filter: "all", "read", or "write"
     * @param maxResults Maximum results to return
     * @return Formatted string of analysis results
     */
    public String getXRefsThrough(String addressStr, String accessType, int maxResults) {
        return getXRefsThrough(addressStr, 1, accessType, true, maxResults);
    }
}
