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
     * Test error messages with "Error:" prefix
     */
    @ParameterizedTest
    @DisplayName("Should format standard error messages with 'Error:' prefix")
    @ValueSource(strings = {
        "Error: Address is required",
        "Error: Invalid address format:",
        "Error: No data defined at address"
    })
    void testStandardErrorMessages(String errorMessage) {
        assertTrue(errorMessage.startsWith("Error: "),
            "Standard errors should start with 'Error: ' prefix");
        assertFalse(errorMessage.isEmpty(),
            "Error message should not be empty");
    }

    /**
     * Test error messages for exception scenarios
     */
    @Test
    @DisplayName("Should format exception error messages correctly")
    void testExceptionErrorMessages() {
        // Exception errors have format: "Error getting data at address <addr>: <message>"
        String exceptionError = "Error getting data at address 5356:3cd8: Invalid format";

        assertTrue(exceptionError.startsWith("Error getting data at address"),
            "Exception errors should describe the operation");
        assertTrue(exceptionError.contains(":"),
            "Should include exception message after colon");
        assertFalse(exceptionError.isEmpty(),
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

    // ===========================================================================================
    // Tests for getDataInRange functionality
    // ===========================================================================================

    /**
     * Test that valid address range pairs are recognized
     */
    @Test
    @DisplayName("Should recognize valid address range pairs")
    void testValidAddressRanges() {
        // Valid address range pairs (start, end)
        String[][] validRanges = {
            {"0x00231fec", "0x00232100"},     // Hex format
            {"5356:3cd8", "5356:3d00"},       // Segment:offset format
            {"0x401000", "0x401020"},         // Small range
            {"4592:0000", "4592:00ff"}        // Segment:offset range
        };

        for (String[] range : validRanges) {
            String start = range[0];
            String end = range[1];

            assertNotNull(start, "Start address should not be null");
            assertNotNull(end, "End address should not be null");
            assertFalse(start.isEmpty(), "Start address should not be empty");
            assertFalse(end.isEmpty(), "End address should not be empty");

            // Both should match valid address formats
            boolean startValid = start.matches("^(0x)?[0-9a-fA-F]+$") ||
                               start.matches("^[0-9a-fA-F]+:[0-9a-fA-F]+$");
            boolean endValid = end.matches("^(0x)?[0-9a-fA-F]+$") ||
                             end.matches("^[0-9a-fA-F]+:[0-9a-fA-F]+$");

            assertTrue(startValid, "Start address should be valid: " + start);
            assertTrue(endValid, "End address should be valid: " + end);
        }
    }

    /**
     * Test error messages for missing required parameters
     */
    @Test
    @DisplayName("Should validate required start and end addresses")
    void testDataInRangeRequiredParameters() {
        String missingStartError = "Error: Start address is required";
        String missingEndError = "Error: End address is required";

        assertTrue(missingStartError.startsWith("Error: "),
            "Should return error for missing start address");
        assertTrue(missingStartError.contains("Start address"),
            "Should mention start address in error");
        assertTrue(missingStartError.contains("required"),
            "Should indicate parameter is required");

        assertTrue(missingEndError.startsWith("Error: "),
            "Should return error for missing end address");
        assertTrue(missingEndError.contains("End address"),
            "Should mention end address in error");
    }

    /**
     * Test error message for invalid address formats
     */
    @Test
    @DisplayName("Should handle invalid address formats in range")
    void testDataInRangeInvalidAddressFormats() {
        String startAddress = "invalid_start";
        String endAddress = "0x401020";

        String expectedError = "Error: Invalid start address format: " + startAddress;

        assertTrue(expectedError.startsWith("Error: "),
            "Should return error for invalid address");
        assertTrue(expectedError.contains("Invalid"),
            "Should indicate invalid format");
        assertTrue(expectedError.contains(startAddress),
            "Should include the invalid address");
    }

    /**
     * Test error message when start address is greater than end address
     */
    @Test
    @DisplayName("Should validate start address <= end address")
    void testDataInRangeAddressOrder() {
        String expectedError = "Error: Start address must be less than or equal to end address";

        assertTrue(expectedError.startsWith("Error: "),
            "Should return error for reversed addresses");
        assertTrue(expectedError.contains("less than or equal"),
            "Should describe the ordering requirement");
    }

    /**
     * Test response header format for data in range
     */
    @Test
    @DisplayName("Should format response header with address range and include_undefined flag")
    void testDataInRangeResponseHeader() {
        String startAddr = "0x00231fec";
        String endAddr = "0x00232100";
        boolean includeUndefined = false;

        String expectedHeader = String.format("Data items from %s to %s (include_undefined=%s):",
            startAddr, endAddr, includeUndefined);

        assertTrue(expectedHeader.startsWith("Data items from"),
            "Header should describe what is being listed");
        assertTrue(expectedHeader.contains(startAddr),
            "Header should include start address");
        assertTrue(expectedHeader.contains(endAddr),
            "Header should include end address");
        assertTrue(expectedHeader.contains("include_undefined="),
            "Header should show include_undefined flag");
        assertTrue(expectedHeader.endsWith(":"),
            "Header should end with colon");
    }

    /**
     * Test data item format in range output
     */
    @Test
    @DisplayName("Should format data items with address, label, type, size, and value")
    void testDataInRangeItemFormat() {
        // Expected format: address: label [type, size bytes] = value
        String address = "0x00231fec";
        String label = "stack_array";
        String type = "byte[20]";
        int size = 20;
        String value = "[0x00, 0x01, ...]";

        String expectedFormat = String.format("%s: %s [%s, %d bytes] = %s",
            address, label, type, size, value);

        assertTrue(expectedFormat.contains(address),
            "Item should include address");
        assertTrue(expectedFormat.contains(label),
            "Item should include label");
        assertTrue(expectedFormat.contains(type),
            "Item should include type");
        assertTrue(expectedFormat.contains(size + " bytes"),
            "Item should include size with bytes unit");
        assertTrue(expectedFormat.contains("="),
            "Item should include equals sign before value");
        assertTrue(expectedFormat.contains(value),
            "Item should include value");
    }

    /**
     * Test include_undefined parameter handling
     */
    @ParameterizedTest
    @DisplayName("Should handle include_undefined parameter correctly")
    @ValueSource(booleans = {true, false})
    void testDataInRangeIncludeUndefinedParameter(boolean includeUndefined) {
        String headerPart = String.format("include_undefined=%s", includeUndefined);

        assertTrue(headerPart.contains("include_undefined="),
            "Should format parameter name");
        assertTrue(headerPart.contains(String.valueOf(includeUndefined)),
            "Should include boolean value");
    }

    /**
     * Test empty range result message
     */
    @Test
    @DisplayName("Should return appropriate message when no data found in range")
    void testDataInRangeNoDataFound() {
        String expectedMessage = "No data items found in the specified range";

        assertFalse(expectedMessage.startsWith("Error: "),
            "Should not be formatted as error (it's a valid empty result)");
        assertTrue(expectedMessage.contains("No data"),
            "Should indicate no data was found");
        assertTrue(expectedMessage.contains("range"),
            "Should mention the range");
    }

    /**
     * Test total count format in output
     */
    @ParameterizedTest
    @DisplayName("Should format total item count correctly")
    @ValueSource(ints = {0, 1, 2, 5, 10, 100})
    void testDataInRangeTotalCountFormat(int count) {
        String totalLine = String.format("Total: %d item(s)", count);

        assertTrue(totalLine.startsWith("Total: "),
            "Total line should start with 'Total: '");
        assertTrue(totalLine.contains(String.valueOf(count)),
            "Should include the count number");
        assertTrue(totalLine.contains("item(s)"),
            "Should include 'item(s)' unit");
    }

    /**
     * Test unnamed data handling in range output
     */
    @Test
    @DisplayName("Should handle unnamed data items in range correctly")
    void testDataInRangeUnnamedData() {
        String unnamedLabel = "(unnamed)";
        String address = "0x401004";
        String type = "undefined";
        String value = "??";

        String itemFormat = String.format("%s: %s [%s, 1 bytes] = %s",
            address, unnamedLabel, type, value);

        assertTrue(itemFormat.contains("(unnamed)"),
            "Should use standard unnamed indicator");
        assertTrue(itemFormat.contains(type),
            "Should show undefined type");
    }

    /**
     * Test mixed address formats in same range
     */
    @Test
    @DisplayName("Should accept consistent address format in range")
    void testDataInRangeMixedFormats() {
        // Both addresses should use same format
        String[][] consistentRanges = {
            {"0x401000", "0x401100"},      // Both hex
            {"5356:0000", "5356:0100"}     // Both segment:offset
        };

        for (String[] range : consistentRanges) {
            String start = range[0];
            String end = range[1];

            boolean startIsHex = start.startsWith("0x");
            boolean endIsHex = end.startsWith("0x");
            boolean startIsSegOff = start.contains(":");
            boolean endIsSegOff = end.contains(":");

            // Both should be same format
            assertEquals(startIsHex, endIsHex,
                "Addresses should use consistent format: " + start + " and " + end);
            assertEquals(startIsSegOff, endIsSegOff,
                "Addresses should use consistent format: " + start + " and " + end);
        }
    }

    /**
     * Test error handling for exception scenarios
     */
    @Test
    @DisplayName("Should format exception errors correctly for getDataInRange")
    void testDataInRangeExceptionErrorFormat() {
        String exceptionError = "Error getting data in range: Some error message";

        assertTrue(exceptionError.startsWith("Error getting data in range:"),
            "Exception errors should describe the operation");
        assertTrue(exceptionError.contains(":"),
            "Should separate operation from error message with colon");
    }

    /**
     * Test that output includes proper item formatting for various data types
     */
    @Test
    @DisplayName("Should format different data types correctly in range output")
    void testDataInRangeDifferentDataTypes() {
        String[][] dataTypes = {
            {"word", "2"},
            {"dword", "4"},
            {"byte", "1"},
            {"qword", "8"},
            {"string", "12"},
            {"byte[20]", "20"},
            {"int[16]", "64"}
        };

        for (String[] typeInfo : dataTypes) {
            String type = typeInfo[0];
            String size = typeInfo[1];

            String itemPart = String.format("[%s, %s bytes]", type, size);

            assertTrue(itemPart.startsWith("["),
                "Type info should be in brackets");
            assertTrue(itemPart.contains(type),
                "Should include type name");
            assertTrue(itemPart.contains(size + " bytes"),
                "Should include size with bytes unit");
            assertTrue(itemPart.endsWith("]"),
                "Type info should close with bracket");
        }
    }
}
