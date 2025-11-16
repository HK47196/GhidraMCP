package com.lauriewired.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Statistics about the pointer flow analysis performed.
 */
public class AnalysisStats {
    private final int functionsAnalyzed;
    private final int instructionsExamined;
    private final long analysisTimeMs;
    private final boolean stoppedEarly;
    private final List<String> warnings;

    private AnalysisStats(Builder builder) {
        this.functionsAnalyzed = builder.functionsAnalyzed;
        this.instructionsExamined = builder.instructionsExamined;
        this.analysisTimeMs = builder.analysisTimeMs;
        this.stoppedEarly = builder.stoppedEarly;
        this.warnings = new ArrayList<>(builder.warnings);
    }

    public int getFunctionsAnalyzed() {
        return functionsAnalyzed;
    }

    public int getInstructionsExamined() {
        return instructionsExamined;
    }

    public long getAnalysisTimeMs() {
        return analysisTimeMs;
    }

    public boolean isStoppedEarly() {
        return stoppedEarly;
    }

    public List<String> getWarnings() {
        return new ArrayList<>(warnings);
    }

    @Override
    public String toString() {
        return String.format("Analyzed %d functions, %d instructions in %dms%s",
            functionsAnalyzed,
            instructionsExamined,
            analysisTimeMs,
            stoppedEarly ? " (stopped early)" : "");
    }

    public static class Builder {
        private int functionsAnalyzed;
        private int instructionsExamined;
        private long analysisTimeMs;
        private boolean stoppedEarly;
        private List<String> warnings = new ArrayList<>();

        public Builder functionsAnalyzed(int functionsAnalyzed) {
            this.functionsAnalyzed = functionsAnalyzed;
            return this;
        }

        public Builder instructionsExamined(int instructionsExamined) {
            this.instructionsExamined = instructionsExamined;
            return this;
        }

        public Builder analysisTimeMs(long analysisTimeMs) {
            this.analysisTimeMs = analysisTimeMs;
            return this;
        }

        public Builder stoppedEarly(boolean stoppedEarly) {
            this.stoppedEarly = stoppedEarly;
            return this;
        }

        public Builder addWarning(String warning) {
            this.warnings.add(warning);
            return this;
        }

        public Builder warnings(List<String> warnings) {
            this.warnings = new ArrayList<>(warnings);
            return this;
        }

        public AnalysisStats build() {
            return new AnalysisStats(this);
        }
    }
}
