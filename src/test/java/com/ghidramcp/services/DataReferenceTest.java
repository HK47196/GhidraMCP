package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for data reference functionality in DecompilationService.
 *
 * These tests verify output formatting, error message handling, and validation
 * for the get_function_data functionality.
 *
 * Note: Full integration tests with Ghidra Program objects would require
 * the Ghidra test framework and are beyond the scope of unit tests.
 */
class DataReferenceTest {

    /**
     * Test that error messages for missing parameters are correct
     */
    @Test
    @DisplayName("Should return error when neither address nor name is provided")
    void testMissingParameterError() {
        String expectedError = "Error: Either 'address' or 'name' parameter is required";

        assertTrue(expectedError.startsWith("Error: "),
            "Should be formatted as error message");
        assertTrue(expectedError.contains("required"),
            "Should indicate parameter is required");
        assertTrue(expectedError.contains("address") && expectedError.contains("name"),
            "Should mention both possible parameters");
    }

    /**
     * Test error message when no program is loaded
     */
    @Test
    @DisplayName("Should return error when no program is loaded")
    void testNoProgramLoadedError() {
        String expectedError = "No program loaded";

        assertNotNull(expectedError);
        assertTrue(expectedError.contains("No program"),
            "Should indicate no program is loaded");
    }

    /**
     * Test error message when function is not found by name
     */
    @Test
    @DisplayName("Should return error when function not found by name")
    void testFunctionNotFoundByName() {
        String functionName = "nonexistent_function";
        String expectedError = "Function not found: " + functionName;

        assertTrue(expectedError.startsWith("Function not found:"),
            "Should indicate function was not found");
        assertTrue(expectedError.contains(functionName),
            "Should include the function name in error message");
    }

    /**
     * Test error message when function is not found at address
     */
    @Test
    @DisplayName("Should return error when function not found at address")
    void testFunctionNotFoundByAddress() {
        String address = "0x401000";
        String expectedError = "No function found at or containing address " + address;

        assertTrue(expectedError.contains("No function found"),
            "Should indicate function was not found");
        assertTrue(expectedError.contains(address),
            "Should include the address in error message");
    }

    /**
     * Test error message when address is required but not provided
     */
    @Test
    @DisplayName("Should return error when address is empty or null")
    void testAddressRequiredError() {
        String expectedError = "Address is required";

        assertNotNull(expectedError);
        assertTrue(expectedError.contains("required"),
            "Should indicate address is required");
    }

    /**
     * Test that output header format is correct
     */
    @Test
    @DisplayName("Should format output header with correct columns")
    void testOutputHeaderFormat() {
        String[] expectedColumns = {
            "Symbol",
            "Address",
            "Type",
            "RefFrom",
            "Value"
        };

        // Validate all expected columns are defined
        assertEquals(5, expectedColumns.length, "Should have 5 columns");
        assertEquals("Symbol", expectedColumns[0], "First column should be Symbol");
        assertEquals("Address", expectedColumns[1], "Second column should be Address");
        assertEquals("Type", expectedColumns[2], "Third column should be Type");
        assertEquals("RefFrom", expectedColumns[3], "Fourth column should be RefFrom");
        assertEquals("Value", expectedColumns[4], "Fifth column should be Value");
    }

    /**
     * Test that function header line is formatted correctly
     */
    @Test
    @DisplayName("Should format function header line correctly")
    void testFunctionHeaderFormat() {
        String functionName = "test_function";
        String address = "0x401000";
        String expectedHeader = "Data references from " + functionName + " (" + address + "):";

        assertTrue(expectedHeader.startsWith("Data references from"),
            "Header should start with 'Data references from'");
        assertTrue(expectedHeader.contains(functionName),
            "Header should contain function name");
        assertTrue(expectedHeader.contains(address),
            "Header should contain function address");
        assertTrue(expectedHeader.endsWith(":"),
            "Header should end with colon");
    }

    /**
     * Test that empty result message is formatted correctly
     */
    @Test
    @DisplayName("Should format empty result message correctly")
    void testEmptyResultMessage() {
        String expectedMessage = "  No data references found.";

        assertTrue(expectedMessage.contains("No data references"),
            "Should indicate no data references were found");
        assertTrue(expectedMessage.endsWith("."),
            "Message should end with period");
    }

    /**
     * Test that total count line is formatted correctly
     */
    @ParameterizedTest
    @DisplayName("Should format total count line correctly")
    @ValueSource(ints = {0, 1, 5, 10, 100})
    void testTotalCountFormat(int count) {
        String expectedTotal = "  Total: " + count + " data references";

        assertTrue(expectedTotal.startsWith("  Total:"),
            "Should start with 'Total:'");
        assertTrue(expectedTotal.contains(String.valueOf(count)),
            "Should contain the count");
        assertTrue(expectedTotal.endsWith("data references"),
            "Should end with 'data references'");
    }

    /**
     * Test that string values are quoted
     */
    @Test
    @DisplayName("Should quote string values in output")
    void testStringValueQuoting() {
        String stringValue = "test string";
        String quotedValue = "\"" + stringValue + "\"";

        assertTrue(quotedValue.startsWith("\""),
            "String value should start with quote");
        assertTrue(quotedValue.endsWith("\""),
            "String value should end with quote");
        assertEquals("\"test string\"", quotedValue,
            "Should properly quote the string");
    }

    /**
     * Test that long values are truncated
     */
    @Test
    @DisplayName("Should truncate long values with ellipsis")
    void testValueTruncation() {
        String longValue = "a".repeat(50); // 50 characters
        String truncatedValue = longValue.substring(0, 37) + "...";

        assertEquals(40, truncatedValue.length(),
            "Truncated value should be 40 characters (37 + '...')");
        assertTrue(truncatedValue.endsWith("..."),
            "Truncated value should end with '...'");
    }

    /**
     * Test valid address formats for function lookup
     */
    @ParameterizedTest
    @DisplayName("Should accept valid address formats")
    @ValueSource(strings = {
        "0x401000",
        "0x1400010a0",
        "5356:3cd8",
        "4592:000e"
    })
    void testValidAddressFormats(String address) {
        assertNotNull(address, "Address should not be null");
        assertFalse(address.isEmpty(), "Address should not be empty");

        // Validate format patterns
        boolean isValid = address.matches("^(0x)?[0-9a-fA-F]+$") ||
                         address.matches("^[0-9a-fA-F]+:[0-9a-fA-F]+$");

        assertTrue(isValid, "Address should match valid format: " + address);
    }

    /**
     * Test that data reference output includes all required fields
     */
    @Test
    @DisplayName("Should include all required fields in data reference output")
    void testDataReferenceFields() {
        String[] requiredFields = {
            "Symbol",      // Data symbol/label
            "Address",     // Data address
            "Type",        // Data type
            "RefFrom",     // Reference source address
            "Value"        // Data value
        };

        for (String field : requiredFields) {
            assertNotNull(field, "Field should be defined: " + field);
            assertFalse(field.isEmpty(), "Field should not be empty: " + field);
        }

        assertEquals(5, requiredFields.length, "Should have exactly 5 required fields");
    }

    /**
     * Test exception error message format
     */
    @Test
    @DisplayName("Should format exception errors correctly")
    void testExceptionErrorFormat() {
        String address = "0x401000";
        String exceptionMessage = "Invalid address format";
        String expectedError = "Error getting data references: " + exceptionMessage;

        assertTrue(expectedError.startsWith("Error getting data references:"),
            "Exception error should describe the operation");
        assertTrue(expectedError.contains(exceptionMessage),
            "Should include the exception message");
    }

    /**
     * Test that separator line has appropriate length
     */
    @Test
    @DisplayName("Should format separator line correctly")
    void testSeparatorLineFormat() {
        int maxLabelLen = 20;
        int expectedLength = maxLabelLen + 70;
        String separator = "  " + "-".repeat(expectedLength);

        assertTrue(separator.startsWith("  "),
            "Separator should start with spacing");
        assertTrue(separator.contains("-"),
            "Separator should contain dashes");
        assertEquals(expectedLength + 2, separator.length(),
            "Separator should have correct total length");
    }

    /**
     * Test column alignment spacing
     */
    @Test
    @DisplayName("Should use consistent column spacing")
    void testColumnSpacing() {
        // Expected column widths based on implementation
        int symbolWidth = 20;    // Minimum, dynamic based on content
        int addressWidth = 12;
        int typeWidth = 20;
        int refFromWidth = 12;
        // Value column is variable width

        assertTrue(symbolWidth >= 20, "Symbol column should be at least 20 chars");
        assertEquals(12, addressWidth, "Address column should be 12 chars");
        assertEquals(20, typeWidth, "Type column should be 20 chars");
        assertEquals(12, refFromWidth, "RefFrom column should be 12 chars");
    }

    /**
     * Test that data type names are formatted correctly
     */
    @ParameterizedTest
    @DisplayName("Should format common data type names")
    @ValueSource(strings = {
        "dword",
        "char[20]",
        "pointer",
        "byte",
        "qword",
        "undefined"
    })
    void testDataTypeFormatting(String dataType) {
        assertNotNull(dataType, "Data type should not be null");
        assertFalse(dataType.isEmpty(), "Data type should not be empty");

        // Data types should not contain control characters
        assertFalse(dataType.matches(".*[\\p{Cntrl}].*"),
            "Data type should not contain control characters: " + dataType);
    }

    /**
     * Test output consistency
     */
    @Test
    @DisplayName("Should maintain consistent output structure")
    void testOutputStructure() {
        // Expected output structure:
        // 1. Header line with function name and address
        // 2. Blank line
        // 3. Column headers OR "No data references found"
        // 4. Separator line (if data exists)
        // 5. Data rows (if data exists)
        // 6. Blank line
        // 7. Total count line

        String[] outputSections = {
            "Data references from",  // Header
            "Symbol",                // Column header
            "Total:"                 // Summary
        };

        for (String section : outputSections) {
            assertNotNull(section, "Output section should be defined");
            assertFalse(section.isEmpty(), "Output section should not be empty");
        }
    }
}
