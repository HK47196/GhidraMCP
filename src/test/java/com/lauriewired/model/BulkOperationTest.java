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
        bulkOp.setEndpoint("/methods");
        bulkOp.setParams(new HashMap<>());

        assertEquals("/methods", bulkOp.getEndpoint());
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

    @Test
    @DisplayName("BulkOperation should store comments with actual newlines")
    void testBulkOperationWithNewlines() {
        // After parsing, the comment should contain actual newline characters,
        // not the literal string "\n"
        BulkOperation bulkOp = new BulkOperation();
        Map<String, String> params = new HashMap<>();
        params.put("address", "0x401000");
        params.put("comment", "Line 1\nLine 2\nLine 3");

        bulkOp.setEndpoint("/set_plate_comment");
        bulkOp.setParams(params);

        String comment = bulkOp.getParams().get("comment");
        assertNotNull(comment);
        assertTrue(comment.contains("\n"), "Comment should contain actual newline characters");
        assertFalse(comment.contains("\\n"), "Comment should not contain literal \\n");

        // Verify we can split by actual newlines
        String[] lines = comment.split("\n");
        assertEquals(3, lines.length);
        assertEquals("Line 1", lines[0]);
        assertEquals("Line 2", lines[1]);
        assertEquals("Line 3", lines[2]);
    }

    @Test
    @DisplayName("BulkOperation should handle comments with tabs and newlines")
    void testBulkOperationWithMixedEscapes() {
        BulkOperation bulkOp = new BulkOperation();
        Map<String, String> params = new HashMap<>();
        params.put("address", "0x402000");
        params.put("comment", "Function: ProcessData\nParameters:\n\t- input: char*\n\t- size: int");

        bulkOp.setEndpoint("/set_plate_comment");
        bulkOp.setParams(params);

        String comment = bulkOp.getParams().get("comment");
        assertTrue(comment.contains("\n"), "Should contain newlines");
        assertTrue(comment.contains("\t"), "Should contain tabs");

        // Verify structure
        String[] lines = comment.split("\n");
        assertEquals(4, lines.length);
        assertEquals("Function: ProcessData", lines[0]);
        assertTrue(lines[2].startsWith("\t"), "Line should start with tab");
    }

    @Test
    @DisplayName("BulkOperation should preserve backslashes in paths")
    void testBulkOperationWithBackslashes() {
        BulkOperation bulkOp = new BulkOperation();
        Map<String, String> params = new HashMap<>();
        // After unescaping \\, we should get a single backslash
        params.put("path", "C:\\Users\\test\\file.txt");

        bulkOp.setParams(params);

        String path = bulkOp.getParams().get("path");
        // Single backslashes in the actual path
        assertTrue(path.contains("\\"));
        // Count backslashes - should be 3 single backslashes
        long backslashCount = path.chars().filter(ch -> ch == '\\').count();
        assertEquals(3, backslashCount);
    }

    @Test
    @DisplayName("BulkOperation should handle Unicode characters in comments")
    void testBulkOperationWithUnicode() {
        BulkOperation bulkOp = new BulkOperation();
        Map<String, String> params = new HashMap<>();
        params.put("comment", "Copyright © 2024");

        bulkOp.setEndpoint("/set_plate_comment");
        bulkOp.setParams(params);

        String comment = bulkOp.getParams().get("comment");
        assertTrue(comment.contains("©"), "Should contain copyright symbol");
    }
}
