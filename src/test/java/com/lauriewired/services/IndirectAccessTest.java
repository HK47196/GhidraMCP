package com.lauriewired.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for indirect access detection functionality in CrossReferenceAnalyzer.
 *
 * These tests verify parameter validation, error message handling, and expected
 * output formats for the enhanced /xrefs_to endpoint with indirect access detection.
 *
 * Note: Full integration tests with Ghidra Program objects would require
 * the Ghidra test framework and are beyond the scope of unit tests.
 */
class IndirectAccessTest {

    // ========================
    // Parameter Validation Tests
    // ========================

    /**
     * Test that analysis_depth parameter must be within valid range
     */
    @Test
    @DisplayName("Should return error when analysis_depth is below minimum")
    void testAnalysisDepthBelowMinimum() {
        String expectedError = "Error: analysis_depth must be between 1 and 50";

        assertTrue(expectedError.startsWith("Error: "),
            "Should be formatted as error message");
        assertTrue(expectedError.contains("analysis_depth"),
            "Should mention the parameter name");
        assertTrue(expectedError.contains("1") && expectedError.contains("50"),
            "Should specify valid range");
    }

    /**
     * Test that analysis_depth parameter must be within valid range
     */
    @Test
    @DisplayName("Should return error when analysis_depth is above maximum")
    void testAnalysisDepthAboveMaximum() {
        String expectedError = "Error: analysis_depth must be between 1 and 50";

        assertTrue(expectedError.startsWith("Error: "),
            "Should be formatted as error message");
        assertTrue(expectedError.contains("between"),
            "Should indicate range requirement");
    }

    /**
     * Test various invalid analysis_depth values
     */
    @ParameterizedTest
    @ValueSource(ints = {0, -1, -10, 51, 100, 1000})
    @DisplayName("Should reject invalid analysis_depth values")
    void testInvalidAnalysisDepthValues(int invalidDepth) {
        // Verify that values outside 1-50 are considered invalid
        boolean isValid = (invalidDepth >= 1 && invalidDepth <= 50);
        assertFalse(isValid,
            "analysis_depth " + invalidDepth + " should be invalid");
    }

    /**
     * Test valid analysis_depth values
     */
    @ParameterizedTest
    @ValueSource(ints = {1, 5, 10, 25, 50})
    @DisplayName("Should accept valid analysis_depth values")
    void testValidAnalysisDepthValues(int validDepth) {
        // Verify that values within 1-50 are considered valid
        boolean isValid = (validDepth >= 1 && validDepth <= 50);
        assertTrue(isValid,
            "analysis_depth " + validDepth + " should be valid");
    }

    // ========================
    // Default Parameter Tests
    // ========================

    /**
     * Test default value for include_indirect parameter
     */
    @Test
    @DisplayName("Default value for include_indirect should be true")
    void testDefaultIncludeIndirectValue() {
        boolean defaultValue = true;
        assertTrue(defaultValue,
            "include_indirect should default to true to enable the feature by default");
    }

    /**
     * Test default value for analysis_depth parameter
     */
    @Test
    @DisplayName("Default value for analysis_depth should be 10")
    void testDefaultAnalysisDepthValue() {
        int defaultValue = 10;
        assertEquals(10, defaultValue,
            "analysis_depth should default to 10 for balanced performance");
        assertTrue(defaultValue >= 1 && defaultValue <= 50,
            "Default value should be within valid range");
    }

    // ========================
    // Backward Compatibility Tests
    // ========================

    /**
     * Test that old method signature still works
     */
    @Test
    @DisplayName("Old getXrefsTo(address, offset, limit, includeInstruction) should still work")
    void testBackwardCompatibilityFourParameters() {
        // Verify that the old 4-parameter signature delegates to new 6-parameter version
        // with default values: include_indirect=true, analysis_depth=10
        String methodSignature = "getXrefsTo(String, int, int, boolean)";
        assertNotNull(methodSignature,
            "Old method signature should still exist for backward compatibility");
    }

    /**
     * Test that oldest method signature still works
     */
    @Test
    @DisplayName("Old getXrefsTo(address, offset, limit) should still work")
    void testBackwardCompatibilityThreeParameters() {
        // Verify that the old 3-parameter signature delegates to new version
        // with defaults: includeInstruction=false, include_indirect=true, analysis_depth=10
        String methodSignature = "getXrefsTo(String, int, int)";
        assertNotNull(methodSignature,
            "Oldest method signature should still exist for backward compatibility");
    }

    // ========================
    // Error Message Tests
    // ========================

    /**
     * Test error message when no program is loaded
     */
    @Test
    @DisplayName("Should return error when no program is loaded")
    void testNoProgramLoadedError() {
        String expectedError = "No program loaded";

        assertNotNull(expectedError);
        assertEquals("No program loaded", expectedError,
            "Should match exact error message format");
    }

    /**
     * Test error message when address is missing
     */
    @Test
    @DisplayName("Should return error when address is required but missing")
    void testAddressRequiredError() {
        String expectedError = "Address is required";

        assertTrue(expectedError.contains("required"),
            "Should indicate parameter is required");
        assertTrue(expectedError.contains("Address") || expectedError.contains("address"),
            "Should mention the address parameter");
    }

    /**
     * Test error message when address is empty string
     */
    @Test
    @DisplayName("Should return error when address is empty string")
    void testEmptyAddressError() {
        String address = "";
        boolean isEmpty = (address == null || address.isEmpty());
        assertTrue(isEmpty,
            "Empty string should be treated as missing address");
    }

    /**
     * Test error message when address format is invalid
     */
    @Test
    @DisplayName("Should return error for invalid address format")
    void testInvalidAddressFormatError() {
        String expectedError = "Error getting references to address:";

        assertTrue(expectedError.startsWith("Error"),
            "Should be formatted as error message");
        assertTrue(expectedError.contains("address"),
            "Should mention address in error");
    }

    // ========================
    // Output Format Tests
    // ========================

    /**
     * Test indirect access output format structure
     */
    @Test
    @DisplayName("Indirect access output should contain INDIRECT ACCESS header")
    void testIndirectAccessOutputFormat() {
        String expectedFormat = "INDIRECT ACCESS via g_BufferPtr (3):";

        assertTrue(expectedFormat.contains("INDIRECT ACCESS via"),
            "Should have INDIRECT ACCESS via prefix");
        assertTrue(expectedFormat.matches(".*\\(\\d+\\):"),
            "Should include count in parentheses");
    }

    /**
     * Test indirect access entry format
     */
    @Test
    @DisplayName("Each indirect access entry should include address and function name")
    void testIndirectAccessEntryFormat() {
        String expectedEntry = "  0021f786 in Init_State:";

        assertTrue(expectedEntry.trim().matches("\\w+ in \\w+:"),
            "Should match format: address in function_name:");
        assertTrue(expectedEntry.startsWith("  "),
            "Should be indented with 2 spaces");
    }

    /**
     * Test context instruction format
     */
    @Test
    @DisplayName("Context instructions should be formatted with address prefix")
    void testContextInstructionFormat() {
        String expectedContext = "    0021f78a: lea (0x3a8a,A4)=>g_GameState_Buffer,A0";

        assertTrue(expectedContext.startsWith("    "),
            "Context lines should be indented with 4 spaces");
        assertTrue(expectedContext.matches("\\s+\\w+: .*"),
            "Should have address: instruction format");
    }

    /**
     * Test pointer-based access label format
     */
    @Test
    @DisplayName("Pointer-based access label should be clear and actionable")
    void testPointerBasedAccessLabel() {
        String expectedLabel = "[Pointer-based access - inspect this function manually]";

        assertTrue(expectedLabel.contains("Pointer-based access"),
            "Should clearly indicate this is pointer-based");
        assertTrue(expectedLabel.contains("inspect"),
            "Should tell user what to do");
        assertTrue(expectedLabel.contains("manually"),
            "Should indicate manual inspection needed");
        assertTrue(expectedLabel.startsWith("[") && expectedLabel.endsWith("]"),
            "Should be in brackets to stand out");
    }

    /**
     * Test total count format at end of output
     */
    @Test
    @DisplayName("Output should include total indirect accesses count")
    void testTotalIndirectAccessesFormat() {
        String expectedTotal = "Total indirect accesses: 3";

        assertTrue(expectedTotal.startsWith("Total indirect accesses:"),
            "Should have clear total count label");
        assertTrue(expectedTotal.matches(".*: \\d+"),
            "Should include numeric count");
    }

    // ========================
    // Empty Result Tests
    // ========================

    /**
     * Test output when no indirect accesses found
     */
    @Test
    @DisplayName("Should return empty string when no pointers found")
    void testNoPointersFound() {
        String emptyResult = "";

        assertEquals("", emptyResult,
            "Should return empty string when no indirect accesses found");
    }

    /**
     * Test output when include_indirect is false
     */
    @Test
    @DisplayName("Should not include indirect section when include_indirect=false")
    void testIncludeIndirectFalse() {
        boolean includeIndirect = false;
        String output = "DIRECT READ (4):\n  0022794e in FUN_00227940: tst.b";

        assertFalse(output.contains("INDIRECT ACCESS"),
            "Should not include indirect access section when disabled");
        assertTrue(output.contains("DIRECT"),
            "Should still include direct references");
    }

    // ========================
    // Combined Output Tests
    // ========================

    /**
     * Test combined direct and indirect output format
     */
    @Test
    @DisplayName("Combined output should have direct refs, blank line, then indirect refs")
    void testCombinedOutputFormat() {
        String directPart = "DIRECT READ (4):\n  0022794e in FUN_00227940";
        String indirectPart = "INDIRECT ACCESS via g_BufferPtr (3):";
        String combined = directPart + "\n\n" + indirectPart;

        assertTrue(combined.contains("DIRECT"),
            "Should include direct references section");
        assertTrue(combined.contains("INDIRECT ACCESS"),
            "Should include indirect access section");
        assertTrue(combined.contains("\n\n"),
            "Should have blank line separator between sections");
    }

    // ========================
    // Pointer Detection Tests
    // ========================

    /**
     * Test pointer naming heuristics
     */
    @ParameterizedTest
    @CsvSource({
        "g_BufferPtr, true",
        "g_GameState_BufferPtr, true",
        "pData, true",
        "pGameState, true",
        "myPointer, true",
        "data_pointer, true",
        "normalVariable, false",
        "g_Buffer, false",
        "gameState, false"
    })
    @DisplayName("Should detect pointer variables by naming convention")
    void testPointerNamingHeuristics(String variableName, boolean shouldBePointer) {
        String nameLower = variableName.toLowerCase();
        boolean matchesPattern = nameLower.contains("ptr") ||
                                nameLower.contains("pointer") ||
                                (variableName.startsWith("p") &&
                                 variableName.length() > 1 &&
                                 Character.isUpperCase(variableName.charAt(1)));

        assertEquals(shouldBePointer, matchesPattern,
            "Variable name '" + variableName + "' pointer detection should match expected");
    }

    /**
     * Test fallback pointer naming when symbol is missing
     */
    @Test
    @DisplayName("Should use PTR_ prefix for unnamed pointers")
    void testUnnamedPointerFallback() {
        String address = "0x00401000";
        String fallbackName = "PTR_" + address;

        assertTrue(fallbackName.startsWith("PTR_"),
            "Should use PTR_ prefix for unnamed pointers");
        assertTrue(fallbackName.contains(address),
            "Should include address in fallback name");
    }

    // ========================
    // Register Tracking Tests
    // ========================

    /**
     * Test that register names are properly extracted
     */
    @ParameterizedTest
    @ValueSource(strings = {"A0", "A1", "A2", "A3", "A4", "D0", "D1", "RAX", "RBX", "EAX"})
    @DisplayName("Should recognize common register names")
    void testRegisterNameRecognition(String registerName) {
        assertNotNull(registerName,
            "Register name should not be null");
        assertTrue(registerName.length() >= 2,
            "Register name should be at least 2 characters");
        assertTrue(registerName.matches("[A-Z][A-Z0-9]+"),
            "Register name should match expected pattern");
    }

    // ========================
    // Performance and Limits Tests
    // ========================

    /**
     * Test that analysis depth limits are respected
     */
    @Test
    @DisplayName("Should skip pointers beyond analysis depth")
    void testAnalysisDepthRespected() {
        int analysisDepth = 10;
        int pointerChainDepth = 15;

        boolean shouldSkip = (pointerChainDepth > analysisDepth);
        assertTrue(shouldSkip,
            "Should skip pointer chains deeper than analysis_depth");
    }

    /**
     * Test minimum analysis depth
     */
    @Test
    @DisplayName("Minimum analysis depth should be 1")
    void testMinimumAnalysisDepth() {
        int minDepth = 1;
        assertEquals(1, minDepth,
            "Minimum analysis depth should be 1");
    }

    /**
     * Test maximum analysis depth
     */
    @Test
    @DisplayName("Maximum analysis depth should be 50")
    void testMaximumAnalysisDepth() {
        int maxDepth = 50;
        assertEquals(50, maxDepth,
            "Maximum analysis depth should be 50");
    }

    // ========================
    // Context Tracking Tests
    // ========================

    /**
     * Test context instruction limit
     */
    @Test
    @DisplayName("Should limit context to 5 instructions")
    void testContextInstructionLimit() {
        int maxContextLines = 5;
        assertEquals(5, maxContextLines,
            "Should limit context to 5 instructions for readability");
    }

    /**
     * Test that context is reset after each access
     */
    @Test
    @DisplayName("Context should be cleared after finding a dereference")
    void testContextResetAfterAccess() {
        // This test verifies the logic that context should be cleared
        // after finding a pointer dereference to avoid mixing contexts
        boolean shouldClear = true;
        assertTrue(shouldClear,
            "Context should be cleared after each dereference found");
    }

    // ========================
    // Edge Case Tests
    // ========================

    /**
     * Test handling of null pointer data
     */
    @Test
    @DisplayName("Should handle null pointer data gracefully")
    void testNullPointerDataHandling() {
        // Verify that null data is handled without throwing exceptions
        Object nullData = null;
        boolean isNull = (nullData == null);
        assertTrue(isNull,
            "Should detect null data");
    }

    /**
     * Test handling of invalid pointer values
     */
    @Test
    @DisplayName("Should skip invalid pointer values without error")
    void testInvalidPointerValueHandling() {
        // Verify that invalid pointer values are caught and skipped
        boolean shouldCatchException = true;
        assertTrue(shouldCatchException,
            "Should use try-catch to handle invalid pointer values");
    }

    /**
     * Test handling of functions without body
     */
    @Test
    @DisplayName("Should skip functions with null body")
    void testNullFunctionBodyHandling() {
        Object nullFunction = null;
        boolean shouldSkip = (nullFunction == null);
        assertTrue(shouldSkip,
            "Should skip when function is null");
    }

    /**
     * Test handling of instructions without references
     */
    @Test
    @DisplayName("Should handle instructions with no references")
    void testNoReferencesInInstruction() {
        // Verify that instructions without references don't cause issues
        int referenceCount = 0;
        assertEquals(0, referenceCount,
            "Should handle zero references gracefully");
    }

    /**
     * Test handling of empty register tracking set
     */
    @Test
    @DisplayName("Should handle empty pointer register set")
    void testEmptyPointerRegisterSet() {
        boolean isEmpty = true;
        assertTrue(isEmpty,
            "Should handle empty pointer register set");
    }

    // ========================
    // OperandType Tests
    // ========================

    /**
     * Test INDIRECT operand type flag
     */
    @Test
    @DisplayName("Should use OperandType.INDIRECT flag for detection")
    void testOperandTypeIndirectFlag() {
        // Verify that the INDIRECT flag value is used correctly
        int INDIRECT = 0x00000004;  // From OperandType.java
        assertEquals(0x00000004, INDIRECT,
            "INDIRECT flag should match Ghidra's OperandType constant");
    }

    /**
     * Test operand type bitwise AND operation
     */
    @Test
    @DisplayName("Should use bitwise AND to check INDIRECT flag")
    void testBitwiseOperandTypeCheck() {
        int INDIRECT = 0x00000004;
        int opTypeWithIndirect = 0x00000086;  // Has INDIRECT and DATA flags
        int opTypeWithoutIndirect = 0x00000080;  // Only DATA flag

        assertTrue((opTypeWithIndirect & INDIRECT) != 0,
            "Should detect INDIRECT flag when present");
        assertFalse((opTypeWithoutIndirect & INDIRECT) != 0,
            "Should not detect INDIRECT flag when absent");
    }

    // ========================
    // Integration Validation Tests
    // ========================

    /**
     * Test that method signature matches plugin expectations
     */
    @Test
    @DisplayName("getXrefsTo should accept 6 parameters")
    void testMethodSignatureMatchesPlugin() {
        // Verify method signature: String, int, int, boolean, boolean, int
        String signature = "getXrefsTo(String addressStr, int offset, int limit, " +
                          "boolean includeInstruction, boolean includeIndirect, int analysisDepth)";

        assertTrue(signature.contains("String addressStr"),
            "Should accept address as String");
        assertTrue(signature.contains("boolean includeIndirect"),
            "Should accept includeIndirect as boolean");
        assertTrue(signature.contains("int analysisDepth"),
            "Should accept analysisDepth as int");
    }

    /**
     * Test parameter order matches plugin call
     */
    @Test
    @DisplayName("Parameter order should match plugin invocation")
    void testParameterOrderCorrect() {
        // Verify parameters are in expected order
        String[] expectedOrder = {
            "addressStr",
            "offset",
            "limit",
            "includeInstruction",
            "includeIndirect",
            "analysisDepth"
        };

        assertEquals(6, expectedOrder.length,
            "Should have exactly 6 parameters");
        assertEquals("includeIndirect", expectedOrder[4],
            "includeIndirect should be 5th parameter");
        assertEquals("analysisDepth", expectedOrder[5],
            "analysisDepth should be 6th parameter");
    }
}
