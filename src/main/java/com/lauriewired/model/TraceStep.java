package com.lauriewired.model;

/**
 * Represents a single step in the data flow trace showing how a pointer value
 * flows from its origin to a dereference point.
 */
public class TraceStep {
    private final String address;
    private final String operation;
    private final String varnode;

    public TraceStep(String address, String operation, String varnode) {
        this.address = address;
        this.operation = operation;
        this.varnode = varnode;
    }

    public String getAddress() {
        return address;
    }

    public String getOperation() {
        return operation;
    }

    public String getVarnode() {
        return varnode;
    }

    @Override
    public String toString() {
        return String.format("%s: %s%s",
            address,
            operation,
            varnode != null ? " (" + varnode + ")" : "");
    }
}
