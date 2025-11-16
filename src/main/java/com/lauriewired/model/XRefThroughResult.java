package com.lauriewired.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Result of a get_xrefs_through analysis.
 */
public class XRefThroughResult {
    private final boolean success;
    private final String pointerAddress;
    private final String pointerSymbol;
    private final String dataType;
    private final int totalFound;
    private final AnalysisStats analysisStats;
    private final List<XRefThrough> xrefs;
    private final String errorMessage;

    private XRefThroughResult(Builder builder) {
        this.success = builder.success;
        this.pointerAddress = builder.pointerAddress;
        this.pointerSymbol = builder.pointerSymbol;
        this.dataType = builder.dataType;
        this.totalFound = builder.xrefs.size();
        this.analysisStats = builder.analysisStats;
        this.xrefs = new ArrayList<>(builder.xrefs);
        this.errorMessage = builder.errorMessage;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getPointerAddress() {
        return pointerAddress;
    }

    public String getPointerSymbol() {
        return pointerSymbol;
    }

    public String getDataType() {
        return dataType;
    }

    public int getTotalFound() {
        return totalFound;
    }

    public AnalysisStats getAnalysisStats() {
        return analysisStats;
    }

    public List<XRefThrough> getXrefs() {
        return new ArrayList<>(xrefs);
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Format result as human-readable string.
     */
    public String toFormattedString() {
        if (!success) {
            return "Error: " + errorMessage;
        }

        StringBuilder sb = new StringBuilder();

        // Header
        sb.append("Cross-references through pointer");
        if (pointerSymbol != null) {
            sb.append(" ").append(pointerSymbol);
        }
        sb.append(" at ").append(pointerAddress);
        if (dataType != null) {
            sb.append(" (").append(dataType).append(")");
        }
        sb.append("\n");

        // Stats
        sb.append(analysisStats.toString()).append("\n");
        if (!analysisStats.getWarnings().isEmpty()) {
            sb.append("Warnings:\n");
            for (String warning : analysisStats.getWarnings()) {
                sb.append("  - ").append(warning).append("\n");
            }
        }

        // Results
        sb.append(String.format("\nFound %d dereference(s):\n", totalFound));
        for (XRefThrough xref : xrefs) {
            sb.append("\n").append(xref.toString()).append("\n");

            // Show trace if available
            if (!xref.getTrace().isEmpty()) {
                sb.append("  Trace:\n");
                for (TraceStep step : xref.getTrace()) {
                    sb.append("    ").append(step.toString()).append("\n");
                }
            }
        }

        return sb.toString();
    }

    public static class Builder {
        private boolean success = true;
        private String pointerAddress;
        private String pointerSymbol;
        private String dataType;
        private AnalysisStats analysisStats;
        private List<XRefThrough> xrefs = new ArrayList<>();
        private String errorMessage;

        public Builder success(boolean success) {
            this.success = success;
            return this;
        }

        public Builder pointerAddress(String pointerAddress) {
            this.pointerAddress = pointerAddress;
            return this;
        }

        public Builder pointerSymbol(String pointerSymbol) {
            this.pointerSymbol = pointerSymbol;
            return this;
        }

        public Builder dataType(String dataType) {
            this.dataType = dataType;
            return this;
        }

        public Builder analysisStats(AnalysisStats analysisStats) {
            this.analysisStats = analysisStats;
            return this;
        }

        public Builder xrefs(List<XRefThrough> xrefs) {
            this.xrefs = new ArrayList<>(xrefs);
            return this;
        }

        public Builder addXRef(XRefThrough xref) {
            this.xrefs.add(xref);
            return this;
        }

        public Builder errorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            this.success = false;
            return this;
        }

        public XRefThroughResult build() {
            return new XRefThroughResult(this);
        }
    }
}
