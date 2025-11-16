package com.lauriewired.model;

/**
 * A single step in the data flow trace showing how a pointer value flows.
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
        StringBuilder sb = new StringBuilder();
        sb.append(address).append(": ").append(operation);
        if (varnode != null && !varnode.isEmpty()) {
            sb.append(" -> ").append(varnode);
        }
        return sb.toString();
    }
}
