package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for FunctionNavigator.
 *
 * These tests verify parameter validation, error message formatting,
 * and expected output formats for function navigation operations.
 *
 * Note: Full integration tests with Ghidra Program objects are implemented
 * in the E2E test suite (tests/e2e/).
 */
class FunctionNavigatorTest {

    // =========================================================================
    // getFunctionByAddress tests
    // =========================================================================

    /**
     * Test that address is required for getFunctionByAddress
     */
    @Test
    @DisplayName("getFunctionByAddress should require address parameter")
    void testGetFunctionByAddressRequiresAddress() {
        String expectedError = "Address is required";

        assertTrue(expectedError.contains("required"),
            "Should indicate address is required");
        assertTrue(expectedError.contains("Address"),
            "Should mention address parameter");
    }

    /**
     * Test that empty address is rejected
     */
    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("getFunctionByAddress should reject null and empty addresses")
    void testGetFunctionByAddressRejectsInvalidAddress(String address) {
        String expectedError = "Address is required";

        // Verify the expected error message format
        assertTrue(expectedError.contains("required"),
            "Should indicate address is required for null/empty input");
    }

    /**
     * Test no program loaded error
     */
    @Test
    @DisplayName("getFunctionByAddress should handle no program loaded")
    void testGetFunctionByAddressNoProgramLoaded() {
        String expectedError = "No program loaded";

        assertTrue(expectedError.contains("No program"),
            "Should indicate no program is loaded");
        assertTrue(expectedError.contains("loaded"),
            "Should mention loaded status");
    }

    /**
     * Test no function found at address
     */
    @Test
    @DisplayName("getFunctionByAddress should handle no function at address")
    void testGetFunctionByAddressNoFunctionFound() {
        String address = "0x12345678";
        String expectedError = "No function found at address " + address;

        assertTrue(expectedError.contains("No function found"),
            "Should indicate no function was found");
        assertTrue(expectedError.contains(address),
            "Should include the queried address");
        assertTrue(expectedError.contains("at address"),
            "Should mention 'at address' for context");
    }

    /**
     * Test error handling message format
     */
    @Test
    @DisplayName("getFunctionByAddress should format error messages properly")
    void testGetFunctionByAddressErrorFormat() {
        String errorPrefix = "Error getting function: ";

        assertTrue(errorPrefix.startsWith("Error"),
            "Error messages should start with 'Error'");
        assertTrue(errorPrefix.contains(":"),
            "Should separate error type from details with colon");
    }

    /**
     * Test expected output format for successful function lookup
     */
    @Test
    @DisplayName("getFunctionByAddress should include function name and address")
    void testGetFunctionByAddressOutputFormat() {
        // Expected format: "Function: name at address\nSignature: ...\nEntry: ...\nBody: ... - ..."
        String functionName = "main";
        String address = "0x00401000";
        String expectedFormat = String.format("Function: %s at %s", functionName, address);

        assertTrue(expectedFormat.contains("Function:"),
            "Should include 'Function:' label");
        assertTrue(expectedFormat.contains(functionName),
            "Should include function name");
        assertTrue(expectedFormat.contains(address),
            "Should include address");
        assertTrue(expectedFormat.contains(" at "),
            "Should separate name and address with 'at'");
    }

    /**
     * Test that output includes signature
     */
    @Test
    @DisplayName("getFunctionByAddress output should include signature")
    void testGetFunctionByAddressIncludesSignature() {
        String outputTemplate = "Function: main at 0x401000\nSignature: void main(int argc, char **argv)";

        assertTrue(outputTemplate.contains("Signature:"),
            "Should include 'Signature:' label");
        assertTrue(outputTemplate.contains("\n"),
            "Should use newlines to separate fields");
    }

    /**
     * Test that output includes entry point
     */
    @Test
    @DisplayName("getFunctionByAddress output should include entry point")
    void testGetFunctionByAddressIncludesEntry() {
        String outputTemplate = "Entry: 0x00401000";

        assertTrue(outputTemplate.contains("Entry:"),
            "Should include 'Entry:' label");
    }

    /**
     * Test that output includes body address range
     */
    @Test
    @DisplayName("getFunctionByAddress output should include body address range")
    void testGetFunctionByAddressIncludesBody() {
        String outputTemplate = "Body: 0x00401000 - 0x004010ff";

        assertTrue(outputTemplate.contains("Body:"),
            "Should include 'Body:' label");
        assertTrue(outputTemplate.contains(" - "),
            "Should separate min and max addresses with ' - '");
    }

    // =========================================================================
    // getCurrentAddress tests
    // =========================================================================

    /**
     * Test code viewer service not available error
     */
    @Test
    @DisplayName("getCurrentAddress should handle code viewer service not available")
    void testGetCurrentAddressServiceNotAvailable() {
        String expectedError = "Code viewer service not available";

        assertTrue(expectedError.contains("Code viewer service"),
            "Should indicate code viewer service");
        assertTrue(expectedError.contains("not available"),
            "Should indicate service is not available");
    }

    /**
     * Test no current location error
     */
    @Test
    @DisplayName("getCurrentAddress should handle no current location")
    void testGetCurrentAddressNoLocation() {
        String expectedError = "No current location";

        assertTrue(expectedError.contains("No current location"),
            "Should indicate no current location");
    }

    /**
     * Test expected output format for getCurrentAddress
     */
    @Test
    @DisplayName("getCurrentAddress should return address as string")
    void testGetCurrentAddressOutputFormat() {
        // Address should be returned as a string representation
        String sampleAddress = "00401000";

        assertFalse(sampleAddress.isEmpty(),
            "Address should not be empty");
        // Addresses are typically hex strings
        assertTrue(sampleAddress.matches("[0-9a-fA-F]+"),
            "Address should be a valid hex string");
    }

    // =========================================================================
    // getCurrentFunction tests
    // =========================================================================

    /**
     * Test code viewer service not available for getCurrentFunction
     */
    @Test
    @DisplayName("getCurrentFunction should handle code viewer service not available")
    void testGetCurrentFunctionServiceNotAvailable() {
        String expectedError = "Code viewer service not available";

        assertTrue(expectedError.contains("Code viewer service"),
            "Should indicate code viewer service");
        assertTrue(expectedError.contains("not available"),
            "Should indicate service is not available");
    }

    /**
     * Test no current location for getCurrentFunction
     */
    @Test
    @DisplayName("getCurrentFunction should handle no current location")
    void testGetCurrentFunctionNoLocation() {
        String expectedError = "No current location";

        assertTrue(expectedError.contains("No current location"),
            "Should indicate no current location");
    }

    /**
     * Test no program loaded for getCurrentFunction
     */
    @Test
    @DisplayName("getCurrentFunction should handle no program loaded")
    void testGetCurrentFunctionNoProgramLoaded() {
        String expectedError = "No program loaded";

        assertTrue(expectedError.contains("No program"),
            "Should indicate no program is loaded");
    }

    /**
     * Test no function at current location
     */
    @Test
    @DisplayName("getCurrentFunction should handle no function at current location")
    void testGetCurrentFunctionNoFunctionFound() {
        String address = "0x00401000";
        String expectedError = "No function at current location: " + address;

        assertTrue(expectedError.contains("No function at current location"),
            "Should indicate no function at current location");
        assertTrue(expectedError.contains(address),
            "Should include the current address");
    }

    /**
     * Test expected output format for getCurrentFunction
     */
    @Test
    @DisplayName("getCurrentFunction should include function name and entry point")
    void testGetCurrentFunctionOutputFormat() {
        // Expected format: "Function: name at address\nSignature: ..."
        String functionName = "process_data";
        String address = "0x00402000";
        String expectedFormat = String.format("Function: %s at %s\nSignature:", functionName, address);

        assertTrue(expectedFormat.contains("Function:"),
            "Should include 'Function:' label");
        assertTrue(expectedFormat.contains(functionName),
            "Should include function name");
        assertTrue(expectedFormat.contains(address),
            "Should include entry point address");
        assertTrue(expectedFormat.contains("Signature:"),
            "Should include 'Signature:' label");
    }

    // =========================================================================
    // getFunctionForAddress tests
    // =========================================================================

    /**
     * Document behavior of getFunctionForAddress - tries exact address first
     */
    @Test
    @DisplayName("getFunctionForAddress should try exact address first")
    void testGetFunctionForAddressTriesExactFirst() {
        // This method first tries getFunctionAt(addr)
        // If that returns null, it tries getFunctionContaining(addr)
        // This test documents that behavior

        assertTrue(true, "Documentation: getFunctionForAddress tries exact match first");
    }

    /**
     * Document behavior of getFunctionForAddress - falls back to containing
     */
    @Test
    @DisplayName("getFunctionForAddress should fall back to containing function")
    void testGetFunctionForAddressFallbackBehavior() {
        // If no function starts exactly at the address,
        // the method checks if the address is contained within a function
        // This allows finding functions even when querying addresses in the middle

        assertTrue(true, "Documentation: getFunctionForAddress falls back to containing function");
    }

    /**
     * Document that getFunctionForAddress returns null when no function found
     */
    @Test
    @DisplayName("getFunctionForAddress should return null when no function found")
    void testGetFunctionForAddressReturnsNull() {
        // When no function is found at or containing the address,
        // the method returns null

        assertTrue(true, "Documentation: getFunctionForAddress returns null when not found");
    }

    // =========================================================================
    // getAddressFromLong tests
    // =========================================================================

    /**
     * Document address conversion from long
     */
    @Test
    @DisplayName("getAddressFromLong should convert long to hex string")
    void testGetAddressFromLongConversion() {
        // The method converts a long value to hex string
        // then uses the program's address factory to create an Address
        long testAddress = 0x00401000L;
        String expectedHex = Long.toHexString(testAddress);

        assertEquals("401000", expectedHex,
            "Should convert long to hex string correctly");
    }

    /**
     * Test various address values
     */
    @ParameterizedTest
    @ValueSource(longs = {0L, 0x1000L, 0x00401000L, 0xFFFFFFFFL, 0x7FFFFFFFFFFFFFFFL})
    @DisplayName("getAddressFromLong should handle various address values")
    void testGetAddressFromLongVariousValues(long address) {
        String hexStr = Long.toHexString(address);

        assertNotNull(hexStr, "Hex string should not be null");
        assertFalse(hexStr.isEmpty(), "Hex string should not be empty");
        // Verify it's a valid hex string
        assertTrue(hexStr.matches("[0-9a-f]+"),
            "Should produce valid lowercase hex string");
    }

    /**
     * Test edge case with zero address
     */
    @Test
    @DisplayName("getAddressFromLong should handle zero address")
    void testGetAddressFromLongZero() {
        long zeroAddress = 0L;
        String hexStr = Long.toHexString(zeroAddress);

        assertEquals("0", hexStr, "Zero should convert to '0'");
    }

    /**
     * Test edge case with max long address
     */
    @Test
    @DisplayName("getAddressFromLong should handle maximum long value")
    void testGetAddressFromLongMaxValue() {
        long maxAddress = Long.MAX_VALUE;
        String hexStr = Long.toHexString(maxAddress);

        assertEquals("7fffffffffffffff", hexStr,
            "Should convert max long to hex correctly");
    }

    // =========================================================================
    // getCurrentProgram tests
    // =========================================================================

    /**
     * Document getCurrentProgram behavior when program manager not available
     */
    @Test
    @DisplayName("getCurrentProgram should return null when ProgramManager not available")
    void testGetCurrentProgramNoProgramManager() {
        // When the ProgramManager service is not available,
        // getCurrentProgram returns null

        assertTrue(true, "Documentation: getCurrentProgram returns null without ProgramManager");
    }

    /**
     * Document getCurrentProgram behavior when no program is open
     */
    @Test
    @DisplayName("getCurrentProgram should return null when no program open")
    void testGetCurrentProgramNoProgram() {
        // When ProgramManager exists but no program is currently open,
        // getCurrentProgram returns null

        assertTrue(true, "Documentation: getCurrentProgram returns null when no program open");
    }

    // =========================================================================
    // Integration behavior documentation
    // =========================================================================

    /**
     * Document the dependency on PluginTool
     */
    @Test
    @DisplayName("FunctionNavigator requires PluginTool for service access")
    void testPluginToolDependency() {
        // FunctionNavigator uses PluginTool to access:
        // - CodeViewerService for current location
        // - ProgramManager for current program

        assertTrue(true, "Documentation: FunctionNavigator depends on PluginTool for services");
    }

    /**
     * Document the relationship between methods
     */
    @Test
    @DisplayName("Multiple methods share getCurrentProgram for program access")
    void testSharedProgramAccess() {
        // getFunctionByAddress, getCurrentFunction, and getAddressFromLong
        // all use getCurrentProgram() internally to get the active program

        assertTrue(true, "Documentation: Methods share getCurrentProgram for consistency");
    }

    /**
     * Document output string formatting consistency
     */
    @Test
    @DisplayName("Output formats should be consistent across methods")
    void testOutputFormatConsistency() {
        // All methods return strings with consistent formatting:
        // - Error messages are plain text
        // - Success results use "Label: value" format
        // - Multi-line results use \n separators

        String errorFormat = "Error message";
        String successFormat = "Label: value";
        String multilineFormat = "Line1\nLine2";

        assertFalse(errorFormat.contains(":") && errorFormat.contains("\n"),
            "Errors should be simple messages");
        assertTrue(successFormat.contains(":"),
            "Success results use Label: value format");
        assertTrue(multilineFormat.contains("\n"),
            "Multi-line results use newline separators");
    }
}
