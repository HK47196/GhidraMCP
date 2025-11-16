package com.ghidramcp.model;

import java.util.Map;

/**
 * Represents a single bulk operation with endpoint and parameters
 */
public class BulkOperation {
    String endpoint;
    Map<String, String> params;

    public BulkOperation() {
    }

    public BulkOperation(String endpoint, Map<String, String> params) {
        this.endpoint = endpoint;
        this.params = params;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public Map<String, String> getParams() {
        return params;
    }

    public void setParams(Map<String, String> params) {
        this.params = params;
    }
}
