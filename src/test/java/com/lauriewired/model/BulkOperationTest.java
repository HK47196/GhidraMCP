package com.lauriewired.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Test suite for BulkOperation model class.
 */
class BulkOperationTest {

    @Test
    @DisplayName("BulkOperation should store and retrieve endpoint")
    void testBulkOperationGetSetEndpoint() {
        BulkOperation bulkOp = new BulkOperation();
        bulkOp.setEndpoint("/decompile");

        assertEquals("/decompile", bulkOp.getEndpoint());
    }

    @Test
    @DisplayName("BulkOperation should store and retrieve params map")
    void testBulkOperationGetSetParams() {
        BulkOperation bulkOp = new BulkOperation();
        Map<String, String> params = new HashMap<>();
        params.put("name", "testFunction");
        params.put("address", "0x401000");

        bulkOp.setParams(params);

        assertNotNull(bulkOp.getParams());
        assertEquals(2, bulkOp.getParams().size());
        assertEquals("testFunction", bulkOp.getParams().get("name"));
        assertEquals("0x401000", bulkOp.getParams().get("address"));
    }

    @Test
    @DisplayName("BulkOperation constructor should initialize fields")
    void testBulkOperationConstructor() {
        Map<String, String> params = new HashMap<>();
        params.put("oldName", "oldFunc");
        params.put("newName", "newFunc");

        BulkOperation bulkOp = new BulkOperation("/rename_function", params);

        assertEquals("/rename_function", bulkOp.getEndpoint());
        assertNotNull(bulkOp.getParams());
        assertEquals("oldFunc", bulkOp.getParams().get("oldName"));
        assertEquals("newFunc", bulkOp.getParams().get("newName"));
    }

    @Test
    @DisplayName("BulkOperation should handle empty params")
    void testBulkOperationEmptyParams() {
        BulkOperation bulkOp = new BulkOperation();
        bulkOp.setEndpoint("/list_functions");
        bulkOp.setParams(new HashMap<>());

        assertEquals("/list_functions", bulkOp.getEndpoint());
        assertNotNull(bulkOp.getParams());
        assertTrue(bulkOp.getParams().isEmpty());
    }

    @Test
    @DisplayName("BulkOperation should handle null params")
    void testBulkOperationNullParams() {
        BulkOperation bulkOp = new BulkOperation();
        bulkOp.setEndpoint("/test");
        bulkOp.setParams(null);

        assertEquals("/test", bulkOp.getEndpoint());
        assertNull(bulkOp.getParams());
    }

    @Test
    @DisplayName("BulkOperation default constructor should work")
    void testBulkOperationDefaultConstructor() {
        BulkOperation bulkOp = new BulkOperation();

        assertNull(bulkOp.getEndpoint());
        assertNull(bulkOp.getParams());
    }

    @Test
    @DisplayName("BulkOperation should support multiple param keys")
    void testBulkOperationMultipleParams() {
        BulkOperation bulkOp = new BulkOperation();
        Map<String, String> params = new HashMap<>();
        params.put("name", "func1");
        params.put("address", "0x401000");
        params.put("type", "void");
        params.put("comment", "Test function");

        bulkOp.setEndpoint("/set_function_signature");
        bulkOp.setParams(params);

        assertEquals("/set_function_signature", bulkOp.getEndpoint());
        assertEquals(4, bulkOp.getParams().size());
        assertEquals("func1", bulkOp.getParams().get("name"));
        assertEquals("0x401000", bulkOp.getParams().get("address"));
        assertEquals("void", bulkOp.getParams().get("type"));
        assertEquals("Test function", bulkOp.getParams().get("comment"));
    }
}
