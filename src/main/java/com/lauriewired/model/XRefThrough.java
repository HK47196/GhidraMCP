package com.lauriewired.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Single dereference of a pointer (LOAD/STORE operation).
 */
public class XRefThrough {

    public enum AccessType {
        READ, WRITE
    }

    public enum Confidence {
        HIGH, MEDIUM, LOW
    }

    private final String fromAddress;
    private final AccessType accessType;
    private final String instruction;
    private final String functionName;
    private final Confidence confidence;
    private final List<TraceStep> trace;
    private final String pcodeOp;
    private final Integer offset;
    private final Integer size;

    private XRefThrough(Builder builder) {
        this.fromAddress = builder.fromAddress;
        this.accessType = builder.accessType;
        this.instruction = builder.instruction;
        this.functionName = builder.functionName;
        this.confidence = builder.confidence;
        this.trace = new ArrayList<>(builder.trace);
        this.pcodeOp = builder.pcodeOp;
        this.offset = builder.offset;
        this.size = builder.size;
    }

    public String getFromAddress() {
        return fromAddress;
    }

    public AccessType getAccessType() {
        return accessType;
    }

    public String getInstruction() {
        return instruction;
    }

    public String getFunctionName() {
        return functionName;
    }

    public Confidence getConfidence() {
        return confidence;
    }

    public List<TraceStep> getTrace() {
        return new ArrayList<>(trace);
    }

    public String getPcodeOp() {
        return pcodeOp;
    }

    public Integer getOffset() {
        return offset;
    }

    public Integer getSize() {
        return size;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[%s] %s - %s", confidence, accessType, fromAddress));
        if (functionName != null) {
            sb.append(" in ").append(functionName);
        }
        sb.append("\n  ").append(instruction);
        if (offset != null && offset != 0) {
            sb.append(String.format(" [offset: %d]", offset));
        }
        if (size != null) {
            sb.append(String.format(" [size: %d bytes]", size));
        }
        return sb.toString();
    }

    public static class Builder {
        private String fromAddress;
        private AccessType accessType;
        private String instruction;
        private String functionName;
        private Confidence confidence = Confidence.MEDIUM;
        private List<TraceStep> trace = new ArrayList<>();
        private String pcodeOp;
        private Integer offset;
        private Integer size;

        public Builder fromAddress(String fromAddress) {
            this.fromAddress = fromAddress;
            return this;
        }

        public Builder accessType(AccessType accessType) {
            this.accessType = accessType;
            return this;
        }

        public Builder instruction(String instruction) {
            this.instruction = instruction;
            return this;
        }

        public Builder functionName(String functionName) {
            this.functionName = functionName;
            return this;
        }

        public Builder confidence(Confidence confidence) {
            this.confidence = confidence;
            return this;
        }

        public Builder trace(List<TraceStep> trace) {
            this.trace = new ArrayList<>(trace);
            return this;
        }

        public Builder pcodeOp(String pcodeOp) {
            this.pcodeOp = pcodeOp;
            return this;
        }

        public Builder offset(Integer offset) {
            this.offset = offset;
            return this;
        }

        public Builder size(Integer size) {
            this.size = size;
            return this;
        }

        public XRefThrough build() {
            return new XRefThrough(this);
        }
    }
}
