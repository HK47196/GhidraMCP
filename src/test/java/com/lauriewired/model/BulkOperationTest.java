package com.lauriewired.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.Collections;

/**
 * Test suite for BulkOperation model class.
 */
class BulkOperationTest {

    @Test
    @DisplayName("BulkOperation should store and retrieve operations list")
    void testBulkOperationGetOperations() {
        BulkOperation bulkOp = new BulkOperation();
        BulkOperation.Operation op1 = new BulkOperation.Operation();
        op1.setType("rename_function");

        bulkOp.setOperations(Arrays.asList(op1));

        assertNotNull(bulkOp.getOperations());
        assertEquals(1, bulkOp.getOperations().size());
        assertEquals("rename_function", bulkOp.getOperations().get(0).getType());
    }

    @Test
    @DisplayName("Operation should store and retrieve type")
    void testOperationGetSetType() {
        BulkOperation.Operation op = new BulkOperation.Operation();
        op.setType("decompile");

        assertEquals("decompile", op.getType());
    }

    @Test
    @DisplayName("Operation should store and retrieve params")
    void testOperationGetSetParams() {
        BulkOperation.Operation op = new BulkOperation.Operation();
        BulkOperation.Params params = new BulkOperation.Params();
        params.setName("testFunction");

        op.setParams(params);

        assertNotNull(op.getParams());
        assertEquals("testFunction", op.getParams().getName());
    }

    @Test
    @DisplayName("Params should store and retrieve name")
    void testParamsGetSetName() {
        BulkOperation.Params params = new BulkOperation.Params();
        params.setName("functionName");

        assertEquals("functionName", params.getName());
    }

    @Test
    @DisplayName("Params should store and retrieve oldName")
    void testParamsGetSetOldName() {
        BulkOperation.Params params = new BulkOperation.Params();
        params.setOldName("oldFunctionName");

        assertEquals("oldFunctionName", params.getOldName());
    }

    @Test
    @DisplayName("Params should store and retrieve newName")
    void testParamsGetSetNewName() {
        BulkOperation.Params params = new BulkOperation.Params();
        params.setNewName("newFunctionName");

        assertEquals("newFunctionName", params.getNewName());
    }

    @Test
    @DisplayName("Params should store and retrieve address")
    void testParamsGetSetAddress() {
        BulkOperation.Params params = new BulkOperation.Params();
        params.setAddress("0x401000");

        assertEquals("0x401000", params.getAddress());
    }

    @Test
    @DisplayName("BulkOperation should handle empty operations list")
    void testBulkOperationEmptyList() {
        BulkOperation bulkOp = new BulkOperation();
        bulkOp.setOperations(Collections.emptyList());

        assertNotNull(bulkOp.getOperations());
        assertEquals(0, bulkOp.getOperations().size());
    }

    @Test
    @DisplayName("BulkOperation should handle multiple operations")
    void testBulkOperationMultipleOperations() {
        BulkOperation bulkOp = new BulkOperation();

        BulkOperation.Operation op1 = new BulkOperation.Operation();
        op1.setType("rename_function");
        BulkOperation.Params params1 = new BulkOperation.Params();
        params1.setOldName("func1");
        params1.setNewName("newFunc1");
        op1.setParams(params1);

        BulkOperation.Operation op2 = new BulkOperation.Operation();
        op2.setType("decompile");
        BulkOperation.Params params2 = new BulkOperation.Params();
        params2.setName("func2");
        op2.setParams(params2);

        bulkOp.setOperations(Arrays.asList(op1, op2));

        assertEquals(2, bulkOp.getOperations().size());
        assertEquals("rename_function", bulkOp.getOperations().get(0).getType());
        assertEquals("decompile", bulkOp.getOperations().get(1).getType());
    }

    @Test
    @DisplayName("Params should handle null values gracefully")
    void testParamsNullValues() {
        BulkOperation.Params params = new BulkOperation.Params();

        // Should not throw exceptions
        assertNull(params.getName());
        assertNull(params.getOldName());
        assertNull(params.getNewName());
        assertNull(params.getAddress());
    }
}
