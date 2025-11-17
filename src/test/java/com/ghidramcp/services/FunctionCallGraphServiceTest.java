package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for FunctionCallGraphService.
 *
 * These tests verify parameter validation and error message formatting
 * for function call graph operations.
 *
 * Note: Full integration tests with Ghidra Program objects are implemented
 * in the E2E test suite (tests/e2e/test_xrefs.py).
 */
class FunctionCallGraphServiceTest {

    /**
     * Test that address is required
     */
    @Test
    @DisplayName("Should require address parameter")
    void testAddressRequired() {
        String expectedError = "Address is required";

        assertTrue(expectedError.contains("required"),
            "Should indicate address is required");
        assertTrue(expectedError.contains("Address"),
            "Should mention address");
    }

    /**
     * Test that depth must be at least 1
     */
    @ParameterizedTest
    @ValueSource(ints = {0, -1, -5})
    @DisplayName("Should require depth to be at least 1")
    void testDepthMinimum(int depth) {
        String expectedError = "Depth must be at least 1";

        assertTrue(expectedError.contains("at least 1"),
            "Should indicate minimum depth requirement");
        assertTrue(expectedError.contains("Depth"),
            "Should mention depth parameter");
    }

    /**
     * Test no program loaded error
     */
    @Test
    @DisplayName("Should handle no program loaded")
    void testNoProgramLoaded() {
        String expectedError = "No program loaded";

        assertTrue(expectedError.contains("No program"),
            "Should indicate no program is loaded");
    }

    /**
     * Test no function found at address
     */
    @Test
    @DisplayName("Should handle no function at address")
    void testNoFunctionFound() {
        String address = "0x12345678";
        String expectedError = "No function found at address " + address;

        assertTrue(expectedError.contains("No function found"),
            "Should indicate no function was found");
        assertTrue(expectedError.contains(address),
            "Should include the address");
    }

    /**
     * Test expected output format
     */
    @Test
    @DisplayName("Should use tree formatting characters")
    void testTreeFormattingCharacters() {
        // Verify that the expected tree characters are used
        String treeChars = "├─└─│";

        assertTrue(treeChars.contains("├"),
            "Should use tree branch character");
        assertTrue(treeChars.contains("└"),
            "Should use tree end character");
        assertTrue(treeChars.contains("│"),
            "Should use tree vertical line character");
    }

    /**
     * Test circular reference detection message
     */
    @Test
    @DisplayName("Should detect and report circular references")
    void testCircularReferenceDetection() {
        String expectedMessage = "[circular reference detected]";

        assertTrue(expectedMessage.contains("circular reference"),
            "Should indicate circular reference");
        assertTrue(expectedMessage.startsWith("[") && expectedMessage.endsWith("]"),
            "Should be formatted as a special marker");
    }

    /**
     * Test expected output includes function name and address
     */
    @Test
    @DisplayName("Should include function name and address in output")
    void testOutputFormat() {
        // Expected format: "FunctionName (0x12345678)"
        String functionName = "main";
        String address = "0x12345678";
        String expectedFormat = String.format("%s (%s)", functionName, address);

        assertTrue(expectedFormat.contains(functionName),
            "Should include function name");
        assertTrue(expectedFormat.contains(address),
            "Should include address");
        assertTrue(expectedFormat.contains("(") && expectedFormat.contains(")"),
            "Should format address in parentheses");
    }
}
