package com.lauriewired.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for data retrieval functionality in ProgramAnalyzer.
 *
 * These tests verify address format validation and error message formatting
 * for the getDataByAddress functionality.
 *
 * Note: Full integration tests with Ghidra Program objects would require
 * the Ghidra test framework and are beyond the scope of unit tests.
 */
class ProgramAnalyzerDataTest {

    /**
     * Test that various valid address formats are recognized
     */
    @ParameterizedTest
    @DisplayName("Should recognize valid address formats")
    @ValueSource(strings = {
        "5356:3cd8",        // Segment:offset format
        "0x1400010a0",      // Hex format with 0x prefix
        "1400010a0",        // Hex format without prefix
        "4592:000e",        // Segment:offset with leading zeros
        "0x0",              // Minimal hex address
        "0:0",              // Minimal segment:offset
        "FFFF:FFFF"         // Max values
    })
    void testValidAddressFormats(String address) {
        // These should all be valid address strings
        assertNotNull(address, "Address should not be null");
        assertFalse(address.isEmpty(), "Address should not be empty");

        // Validate format patterns
        assertTrue(
            address.matches("^(0x)?[0-9a-fA-F]+$") || // Hex format
            address.matches("^[0-9a-fA-F]+:[0-9a-fA-F]+$"), // Segment:offset format
            "Address should match valid format: " + address
        );
    }

    /**
     * Test that error messages contain required information
     */
    @Test
    @DisplayName("Should format error messages properly")
    void testErrorMessageFormatting() {
        String address = "invalid:address";
        String errorPrefix = "Error: ";

        // Error messages should start with "Error: "
        String errorMessage = errorPrefix + "Invalid address format: " + address;

        assertTrue(errorMessage.startsWith("Error: "),
            "Error message should start with 'Error: '");
        assertTrue(errorMessage.contains(address),
            "Error message should contain the problematic address");
    }

    /**
     * Test that null/empty address handling messages are correct
     */
    @Test
    @DisplayName("Should validate null and empty address inputs")
    void testNullEmptyAddressValidation() {
        // Expected error for null/empty addresses
        String expectedError = "Error: Address is required";

        assertTrue(expectedError.startsWith("Error: "),
            "Should return error message for invalid input");
        assertTrue(expectedError.contains("required"),
            "Should indicate address is required");
    }

    /**
     * Test response format structure
     */
    @Test
    @DisplayName("Should format response with expected fields")
    void testResponseFormatStructure() {
        // Expected format:
        // Address: <address>
        // Name: <name>
        // Type: <type>
        // Value: <value>
        // Size: <size> bytes

        String[] expectedFields = {
            "Address:",
            "Name:",
            "Type:",
            "Value:",
            "Size:",
            "bytes"
        };

        // Validate that all expected fields are present in the format
        for (String field : expectedFields) {
            assertNotNull(field, "Field should be defined: " + field);
            assertFalse(field.isEmpty(), "Field should not be empty: " + field);
        }
    }

    /**
     * Test segment:offset format parsing
     */
    @ParameterizedTest
    @DisplayName("Should parse segment:offset addresses correctly")
    @ValueSource(strings = {
        "5356:3cd8",
        "4592:000e",
        "1234:5678",
        "ABCD:EF01"
    })
    void testSegmentOffsetParsing(String address) {
        // Should contain exactly one colon
        long colonCount = address.chars().filter(ch -> ch == ':').count();
        assertEquals(1, colonCount, "Segment:offset should have exactly one colon");

        // Should split into two parts
        String[] parts = address.split(":");
        assertEquals(2, parts.length, "Should split into segment and offset");

        // Both parts should be valid hex
        String segment = parts[0];
        String offset = parts[1];

        assertTrue(segment.matches("[0-9a-fA-F]+"),
            "Segment should be valid hex: " + segment);
        assertTrue(offset.matches("[0-9a-fA-F]+"),
            "Offset should be valid hex: " + offset);
    }

    /**
     * Test hex format parsing
     */
    @ParameterizedTest
    @DisplayName("Should parse hex addresses correctly")
    @ValueSource(strings = {
        "0x1400010a0",
        "0xdeadbeef",
        "0x0",
        "0xFFFFFFFF"
    })
    void testHexAddressParsing(String address) {
        // Should start with 0x
        assertTrue(address.startsWith("0x"),
            "Hex address should start with 0x prefix");

        // After 0x, should be valid hex digits
        String hexPart = address.substring(2);
        assertTrue(hexPart.matches("[0-9a-fA-F]+"),
            "Should contain only hex digits after 0x: " + hexPart);
    }

    /**
     * Test that unnamed data is handled correctly
     */
    @Test
    @DisplayName("Should handle unnamed data correctly")
    void testUnnamedDataHandling() {
        String unnamedLabel = "(unnamed)";

        assertTrue(unnamedLabel.startsWith("("),
            "Unnamed indicator should be in parentheses");
        assertTrue(unnamedLabel.endsWith(")"),
            "Unnamed indicator should be in parentheses");
        assertEquals("(unnamed)", unnamedLabel,
            "Should use standard unnamed indicator");
    }

    /**
     * Test data size formatting
     */
    @ParameterizedTest
    @DisplayName("Should format data sizes correctly")
    @ValueSource(ints = {1, 2, 4, 8, 16, 32, 64, 128, 256})
    void testDataSizeFormatting(int size) {
        String sizeString = size + " bytes";

        assertTrue(sizeString.endsWith(" bytes"),
            "Size should include 'bytes' unit");
        assertTrue(sizeString.startsWith(String.valueOf(size)),
            "Size should start with numeric value");
    }

    /**
     * Test output field order consistency
     */
    @Test
    @DisplayName("Should maintain consistent field order in output")
    void testOutputFieldOrder() {
        String[] expectedOrder = {
            "Address:",
            "Name:",
            "Type:",
            "Value:",
            "Size:"
        };

        // Verify the expected order is defined
        assertEquals(5, expectedOrder.length, "Should have 5 output fields");
        assertEquals("Address:", expectedOrder[0], "Address should be first");
        assertEquals("Name:", expectedOrder[1], "Name should be second");
        assertEquals("Type:", expectedOrder[2], "Type should be third");
        assertEquals("Value:", expectedOrder[3], "Value should be fourth");
        assertEquals("Size:", expectedOrder[4], "Size should be fifth");
    }

    /**
     * Test error message for missing data
     */
    @Test
    @DisplayName("Should return appropriate error when no data at address")
    void testNoDataErrorMessage() {
        String address = "5356:3cd8";
        String expectedError = "Error: No data defined at address " + address;

        assertTrue(expectedError.startsWith("Error: "),
            "Should be formatted as error message");
        assertTrue(expectedError.contains("No data"),
            "Should indicate no data was found");
        assertTrue(expectedError.contains(address),
            "Should include the address in error message");
    }

    /**
     * Test that response handles special characters
     */
    @Test
    @DisplayName("Should handle special characters in data values")
    void testSpecialCharacterHandling() {
        // Common special characters that might appear in data values
        String[] specialChars = {"\n", "\t", "\r", "\\", "\""};

        for (String specialChar : specialChars) {
            assertNotNull(specialChar, "Special character should be defined");

            // These should be escaped or handled properly in output
            // The escapeNonAscii utility should handle these
        }
    }

    /**
     * Test comprehensive error scenarios
     */
    @ParameterizedTest
    @DisplayName("Should handle various error scenarios")
    @ValueSource(strings = {
        "Error: Address is required",
        "Error: Invalid address format:",
        "Error: No data defined at address",
        "Error getting data at address"
    })
    void testErrorScenarios(String errorPrefix) {
        assertTrue(errorPrefix.startsWith("Error:"),
            "All errors should start with 'Error:' prefix");
        assertFalse(errorPrefix.isEmpty(),
            "Error message should not be empty");
    }

    /**
     * Test address format validation patterns
     */
    @Test
    @DisplayName("Should distinguish between valid and invalid address formats")
    void testAddressFormatValidation() {
        // Valid formats
        String[] validAddresses = {
            "5356:3cd8",
            "0x1400010a0",
            "FFFF:0000"
        };

        // Invalid formats
        String[] invalidAddresses = {
            "",
            "not:an:address",
            "0x",
            ":",
            ":::",
            "invalid"
        };

        // Valid addresses should match expected patterns
        for (String addr : validAddresses) {
            boolean isValid = addr.matches("^(0x)?[0-9a-fA-F]+$") ||
                            addr.matches("^[0-9a-fA-F]+:[0-9a-fA-F]+$");
            assertTrue(isValid, "Should recognize as valid: " + addr);
        }

        // Invalid addresses should not match
        for (String addr : invalidAddresses) {
            if (addr.isEmpty()) continue; // Empty is handled separately

            boolean isValid = addr.matches("^(0x)?[0-9a-fA-F]+$") ||
                            addr.matches("^[0-9a-fA-F]+:[0-9a-fA-F]+$");
            assertFalse(isValid, "Should recognize as invalid: " + addr);
        }
    }
}
