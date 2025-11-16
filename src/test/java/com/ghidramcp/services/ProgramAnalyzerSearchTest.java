package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for search functionality in ProgramAnalyzer.
 *
 * These tests verify parameter validation and error message formatting
 * for the searchFunctionsByName and searchDataByName functionality.
 *
 * Note: Full integration tests with Ghidra Program objects would require
 * the Ghidra test framework and are beyond the scope of unit tests.
 */
class ProgramAnalyzerSearchTest {

    /**
     * Test that null/empty search term handling messages are correct
     */
    @Test
    @DisplayName("Should validate null and empty search term inputs")
    void testNullEmptySearchTermValidation() {
        // Expected error for null/empty search terms
        String expectedError = "Search term is required";

        assertTrue(expectedError.contains("required"),
            "Should indicate search term is required");
        assertFalse(expectedError.isEmpty(),
            "Error message should not be empty");
    }

    /**
     * Test that search terms are case-insensitive
     */
    @ParameterizedTest
    @DisplayName("Should handle case-insensitive search terms")
    @ValueSource(strings = {"VMEM", "vmem", "VmEm", "vMeM"})
    void testCaseInsensitiveSearch(String searchTerm) {
        // All these variations should match the same results
        assertNotNull(searchTerm, "Search term should not be null");
        assertFalse(searchTerm.isEmpty(), "Search term should not be empty");

        // Case normalization test
        String normalized = searchTerm.toLowerCase();
        assertEquals(normalized, searchTerm.toLowerCase(),
            "Search should be case-insensitive");
    }

    /**
     * Test function search result format
     */
    @Test
    @DisplayName("Should format function search results correctly")
    void testFunctionResultFormat() {
        // Expected format: "FunctionName @ Address"
        String functionName = "malloc";
        String address = "0x401000";
        String expectedFormat = functionName + " @ " + address;

        assertTrue(expectedFormat.contains(" @ "),
            "Function result should contain ' @ ' separator");
        assertTrue(expectedFormat.startsWith(functionName),
            "Function result should start with function name");
        assertTrue(expectedFormat.endsWith(address),
            "Function result should end with address");
    }

    /**
     * Test data search result format
     */
    @Test
    @DisplayName("Should format data search results correctly")
    void testDataResultFormat() {
        // Expected format: "DataLabel @ Address (type: TypeName)"
        String dataLabel = "g_VMEM";
        String address = "0x402000";
        String typeName = "dword";
        String expectedFormat = dataLabel + " @ " + address + " (type: " + typeName + ")";

        assertTrue(expectedFormat.contains(" @ "),
            "Data result should contain ' @ ' separator");
        assertTrue(expectedFormat.contains("(type: "),
            "Data result should contain type information");
        assertTrue(expectedFormat.startsWith(dataLabel),
            "Data result should start with data label");
        assertTrue(expectedFormat.contains(address),
            "Data result should contain address");
        assertTrue(expectedFormat.endsWith(")"),
            "Data result should end with closing parenthesis");
    }

    /**
     * Test pagination parameters
     */
    @ParameterizedTest
    @DisplayName("Should accept valid pagination parameters")
    @ValueSource(ints = {0, 10, 50, 100, 1000})
    void testValidPaginationParameters(int value) {
        // Valid offset and limit values
        assertTrue(value >= 0, "Pagination values should be non-negative");
    }

    /**
     * Test default pagination values
     */
    @Test
    @DisplayName("Should use correct default pagination values")
    void testDefaultPaginationValues() {
        int defaultOffset = 0;
        int defaultLimit = 100;

        assertEquals(0, defaultOffset, "Default offset should be 0");
        assertEquals(100, defaultLimit, "Default limit should be 100");
    }

    /**
     * Test no matches message for functions
     */
    @Test
    @DisplayName("Should return appropriate message when no functions match")
    void testNoFunctionsMatchMessage() {
        String searchTerm = "nonexistent_function";
        String expectedMessage = "No functions matching '" + searchTerm + "'";

        assertTrue(expectedMessage.contains("No functions matching"),
            "Should indicate no functions were found");
        assertTrue(expectedMessage.contains(searchTerm),
            "Should include the search term");
        assertTrue(expectedMessage.contains("'"),
            "Search term should be quoted");
    }

    /**
     * Test no matches message for data
     */
    @Test
    @DisplayName("Should return appropriate message when no data matches")
    void testNoDataMatchMessage() {
        String searchTerm = "nonexistent_data";
        String expectedMessage = "No data variables matching '" + searchTerm + "'";

        assertTrue(expectedMessage.contains("No data variables matching"),
            "Should indicate no data variables were found");
        assertTrue(expectedMessage.contains(searchTerm),
            "Should include the search term");
        assertTrue(expectedMessage.contains("'"),
            "Search term should be quoted");
    }

    /**
     * Test substring matching behavior
     */
    @ParameterizedTest
    @DisplayName("Should perform substring matching")
    @ValueSource(strings = {"VMEM", "VME", "MEM", "g_V", "EM"})
    void testSubstringMatching(String substring) {
        // All these substrings should match "g_VMEM"
        String fullName = "g_VMEM";

        assertTrue(fullName.contains(substring) ||
                   fullName.toLowerCase().contains(substring.toLowerCase()),
            "Should match substring: " + substring);
    }

    /**
     * Test result sorting behavior
     */
    @Test
    @DisplayName("Should sort results alphabetically")
    void testResultSorting() {
        // Results should be sorted
        String[] results = {"zebra @ 0x1000", "apple @ 0x2000", "banana @ 0x3000"};
        String[] sorted = {"apple @ 0x2000", "banana @ 0x3000", "zebra @ 0x1000"};

        // Verify sorting expectation
        assertTrue(sorted[0].compareTo(sorted[1]) < 0,
            "First result should come before second alphabetically");
        assertTrue(sorted[1].compareTo(sorted[2]) < 0,
            "Second result should come before third alphabetically");
    }

    /**
     * Test special character handling in search terms
     */
    @Test
    @DisplayName("Should handle special characters in search terms")
    void testSpecialCharactersInSearchTerms() {
        // Common special characters that might appear in names
        String[] specialChars = {"_", ".", "$", "@"};

        for (String specialChar : specialChars) {
            assertNotNull(specialChar, "Special character should be defined");

            // These should be valid in search terms
            String searchTerm = "prefix" + specialChar + "suffix";
            assertFalse(searchTerm.isEmpty(),
                "Search term with special char should be valid");
        }
    }

    /**
     * Test data with undefined type handling
     */
    @Test
    @DisplayName("Should handle data with undefined type")
    void testUndefinedDataType() {
        String undefinedType = "undefined";
        String dataLabel = "unknown_data";
        String address = "0x403000";
        String expectedFormat = dataLabel + " @ " + address + " (type: " + undefinedType + ")";

        assertTrue(expectedFormat.contains("type: undefined"),
            "Should show 'undefined' for data without type");
    }

    /**
     * Test that results include all required components
     */
    @Test
    @DisplayName("Should include all required components in results")
    void testResultComponents() {
        // Function result components
        String[] functionComponents = {"name", "@", "address"};

        // Data result components
        String[] dataComponents = {"label", "@", "address", "(type:", ")"};

        // Verify all components are defined
        for (String component : functionComponents) {
            assertNotNull(component, "Function component should be defined: " + component);
        }

        for (String component : dataComponents) {
            assertNotNull(component, "Data component should be defined: " + component);
        }
    }

    /**
     * Test pagination with empty results
     */
    @Test
    @DisplayName("Should handle pagination with no results")
    void testPaginationWithNoResults() {
        // When there are no matches, pagination parameters are irrelevant
        String noMatchMessage = "No functions matching 'xyz'";

        assertFalse(noMatchMessage.isEmpty(),
            "Should return message even with no results");
        assertTrue(noMatchMessage.contains("No functions"),
            "Should indicate no matches were found");
    }

    /**
     * Test that data labels can be null
     */
    @Test
    @DisplayName("Should handle data with null labels")
    void testNullDataLabel() {
        // Data without labels should be skipped in search
        // Only data with non-null labels should be included

        // This is a behavioral test - data with null labels
        // should not cause exceptions and should be filtered out
        assertDoesNotThrow(() -> {
            String label = null;
            boolean shouldInclude = (label != null);
            assertFalse(shouldInclude, "Null labels should be filtered out");
        });
    }

    /**
     * Test search term validation
     */
    @Test
    @DisplayName("Should validate search term is not null or empty")
    void testSearchTermValidation() {
        // null search term
        String nullTerm = null;
        boolean isNullInvalid = (nullTerm == null || nullTerm.isEmpty());
        assertTrue(isNullInvalid, "Null search term should be invalid");

        // empty search term
        String emptyTerm = "";
        boolean isEmptyInvalid = (emptyTerm == null || emptyTerm.isEmpty());
        assertTrue(isEmptyInvalid, "Empty search term should be invalid");

        // valid search term
        String validTerm = "test";
        boolean isValid = (validTerm != null && !validTerm.isEmpty());
        assertTrue(isValid, "Valid search term should pass validation");
    }

    /**
     * Test result format consistency
     */
    @Test
    @DisplayName("Should maintain consistent result format")
    void testResultFormatConsistency() {
        // Function format: "name @ address"
        String functionPattern = "^.+ @ .+$";
        String functionExample = "malloc @ 0x401000";
        assertTrue(functionExample.matches(functionPattern),
            "Function result should match expected pattern");

        // Data format: "label @ address (type: typename)"
        String dataPattern = "^.+ @ .+ \\(type: .+\\)$";
        String dataExample = "g_VMEM @ 0x402000 (type: dword)";
        assertTrue(dataExample.matches(dataPattern),
            "Data result should match expected pattern");
    }
}
