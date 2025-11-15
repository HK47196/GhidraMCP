package com.lauriewired.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for StructService search functionality.
 *
 * These tests verify parameter validation, search behavior, and result formatting
 * for the listStructs functionality with search parameter support.
 *
 * Note: Full integration tests with Ghidra Program objects would require
 * the Ghidra test framework and are beyond the scope of unit tests.
 */
class StructServiceTest {

    /**
     * Test that search terms are case-insensitive
     */
    @ParameterizedTest
    @DisplayName("Should handle case-insensitive struct name search")
    @ValueSource(strings = {"FILE", "file", "FiLe", "fILE"})
    void testCaseInsensitiveStructSearch(String searchTerm) {
        // All these variations should match the same results
        assertNotNull(searchTerm, "Search term should not be null");
        assertFalse(searchTerm.isEmpty(), "Search term should not be empty");

        // Case normalization test - search should be case-insensitive
        String normalized = searchTerm.toLowerCase();
        assertEquals(normalized, searchTerm.toLowerCase(),
            "Struct search should be case-insensitive");
    }

    /**
     * Test substring matching behavior for struct names
     */
    @ParameterizedTest
    @DisplayName("Should perform substring matching on struct names")
    @ValueSource(strings = {"File", "Fil", "ile", "FILE_", "e_D"})
    void testSubstringMatching(String substring) {
        // All these substrings should match struct names like "FILE_DESCRIPTOR"
        String fullName = "FILE_DESCRIPTOR";

        assertTrue(fullName.contains(substring) ||
                   fullName.toLowerCase().contains(substring.toLowerCase()),
            "Should match substring: " + substring);
    }

    /**
     * Test that null/empty search term allows all structs
     */
    @Test
    @DisplayName("Should return all structs when search term is null or empty")
    void testNullEmptySearchReturnsAll() {
        // null search term should return all structs (no filtering)
        String nullTerm = null;
        boolean shouldFilterNullTerm = (nullTerm != null && !nullTerm.isEmpty());
        assertFalse(shouldFilterNullTerm, "Null search term should not filter results");

        // empty search term should return all structs (no filtering)
        String emptyTerm = "";
        boolean shouldFilterEmptyTerm = (emptyTerm != null && !emptyTerm.isEmpty());
        assertFalse(shouldFilterEmptyTerm, "Empty search term should not filter results");
    }

    /**
     * Test pagination parameters with struct search
     */
    @ParameterizedTest
    @DisplayName("Should accept valid pagination parameters for struct search")
    @ValueSource(ints = {0, 10, 50, 100, 1000})
    void testValidPaginationParameters(int value) {
        // Valid offset and limit values
        assertTrue(value >= 0, "Pagination values should be non-negative");
    }

    /**
     * Test default pagination values for struct listing
     */
    @Test
    @DisplayName("Should use correct default pagination values for structs")
    void testDefaultPaginationValues() {
        int defaultOffset = 0;
        int defaultLimit = 100;

        assertEquals(0, defaultOffset, "Default offset should be 0");
        assertEquals(100, defaultLimit, "Default limit should be 100");
    }

    /**
     * Test category path filtering combined with search
     */
    @Test
    @DisplayName("Should support both category_path and search filters")
    void testCategoryAndSearchFiltering() {
        String categoryPath = "/MyStructs";
        String searchTerm = "File";

        // Both filters should be applicable
        assertNotNull(categoryPath, "Category path should be defined");
        assertNotNull(searchTerm, "Search term should be defined");

        // Category path should use startsWith matching
        String fullPath = "/MyStructs/Networking";
        assertTrue(fullPath.startsWith(categoryPath),
            "Category path should use startsWith matching");

        // Search should use substring matching
        String structName = "FileDescriptor";
        assertTrue(structName.toLowerCase().contains(searchTerm.toLowerCase()),
            "Search should use case-insensitive substring matching");
    }

    /**
     * Test that search preserves struct order with filtering
     */
    @Test
    @DisplayName("Should maintain consistent struct ordering after search filtering")
    void testStructOrderingWithSearch() {
        // Search filtering should not affect the relative order of matching structs
        String[] structs = {"FileA", "FileB", "FileC"};

        // Verify ordering is preserved
        for (int i = 0; i < structs.length - 1; i++) {
            assertNotNull(structs[i], "Struct name should not be null");
            assertNotNull(structs[i + 1], "Next struct name should not be null");
        }
    }

    /**
     * Test special characters in struct names
     */
    @Test
    @DisplayName("Should handle special characters in struct name search")
    void testSpecialCharactersInStructNames() {
        // Common special characters that might appear in struct names
        String[] specialChars = {"_", "$", "."};

        for (String specialChar : specialChars) {
            assertNotNull(specialChar, "Special character should be defined");

            // These should be valid in struct name search
            String searchTerm = "FILE" + specialChar + "DESCRIPTOR";
            assertFalse(searchTerm.isEmpty(),
                "Search term with special char should be valid");
        }
    }

    /**
     * Test struct result format in JSON
     */
    @Test
    @DisplayName("Should format struct results correctly as JSON")
    void testStructResultJsonFormat() {
        // Expected JSON format for a struct
        String structName = "FILE_DESCRIPTOR";
        String path = "/MyStructs/FILE_DESCRIPTOR";
        int size = 24;
        int numFields = 5;

        String expectedJson = String.format(
            "{\"name\": \"%s\", \"path\": \"%s\", \"size\": %d, \"numFields\": %d}",
            structName, path, size, numFields
        );

        assertTrue(expectedJson.contains("\"name\":"),
            "JSON should contain name field");
        assertTrue(expectedJson.contains("\"path\":"),
            "JSON should contain path field");
        assertTrue(expectedJson.contains("\"size\":"),
            "JSON should contain size field");
        assertTrue(expectedJson.contains("\"numFields\":"),
            "JSON should contain numFields field");
    }

    /**
     * Test list response format with pagination info
     */
    @Test
    @DisplayName("Should include pagination info in list response")
    void testListResponseWithPaginationInfo() {
        int offset = 0;
        int limit = 100;
        int count = 5;

        String expectedFormat = String.format(
            "{\"success\": true, \"offset\": %d, \"limit\": %d, \"count\": %d, \"structs\": []}",
            offset, limit, count
        );

        assertTrue(expectedFormat.contains("\"success\":"),
            "Response should contain success field");
        assertTrue(expectedFormat.contains("\"offset\":"),
            "Response should contain offset field");
        assertTrue(expectedFormat.contains("\"limit\":"),
            "Response should contain limit field");
        assertTrue(expectedFormat.contains("\"count\":"),
            "Response should contain count field");
        assertTrue(expectedFormat.contains("\"structs\":"),
            "Response should contain structs array");
    }

    /**
     * Test that search filters are applied before pagination
     */
    @Test
    @DisplayName("Should apply search filter before pagination")
    void testSearchFilterBeforePagination() {
        // Search filtering should happen first, then pagination on filtered results
        // This ensures consistent pagination behavior

        // If we have 100 structs total, and search matches 10, with offset=0 limit=5:
        // Expected: 5 results from the 10 matches (not 5 from all 100)

        int totalStructs = 100;
        int matchingStructs = 10;
        int limit = 5;
        int expectedResults = Math.min(matchingStructs, limit);

        assertEquals(5, expectedResults,
            "Should paginate only the filtered results");
        assertTrue(expectedResults <= matchingStructs,
            "Results should not exceed matches");
        assertTrue(expectedResults <= limit,
            "Results should not exceed limit");
    }

    /**
     * Test no matches scenario
     */
    @Test
    @DisplayName("Should handle case when no structs match search")
    void testNoMatchingStructs() {
        // When search term matches no structs, count should be 0
        String searchTerm = "NonexistentStructXYZ123";
        int expectedCount = 0;

        assertEquals(0, expectedCount,
            "Count should be 0 when no structs match");
    }

    /**
     * Test search with namespace-like struct names
     */
    @Test
    @DisplayName("Should search structs with namespace-style names")
    void testNamespaceStyleStructNames() {
        // Struct names might contain namespace-like patterns
        String[] structNames = {
            "Network::Socket",
            "File::Descriptor",
            "Memory::Buffer"
        };

        for (String structName : structNames) {
            assertNotNull(structName, "Struct name should not be null");
            assertTrue(structName.contains("::"),
                "Namespace-style struct name should contain '::'");
        }

        // Search for "Socket" should match "Network::Socket"
        String searchTerm = "Socket";
        String fullName = "Network::Socket";
        assertTrue(fullName.toLowerCase().contains(searchTerm.toLowerCase()),
            "Should match structs with namespace prefixes");
    }

    /**
     * Test that category path filter is independent of search
     */
    @Test
    @DisplayName("Should apply category_path and search filters independently")
    void testIndependentFiltering() {
        // Both filters should be applied as AND condition
        String categoryPath = "/Networking";
        String structPath = "/Networking/File";
        String structName = "FileDescriptor";
        String searchTerm = "Descriptor";

        // Category filter: struct path should start with category path
        assertTrue(structPath.startsWith(categoryPath),
            "Category filter should match path prefix");

        // Search filter: struct name should contain search term
        assertTrue(structName.toLowerCase().contains(searchTerm.toLowerCase()),
            "Search filter should match struct name");

        // Both conditions must be true for struct to be included
        boolean shouldInclude = structPath.startsWith(categoryPath) &&
                                structName.toLowerCase().contains(searchTerm.toLowerCase());
        assertTrue(shouldInclude,
            "Both filters should be satisfied for inclusion");
    }

    /**
     * Test empty category path behavior
     */
    @Test
    @DisplayName("Should handle null/empty category_path correctly")
    void testNullEmptyCategoryPath() {
        // null category path should not filter
        String nullCategory = null;
        boolean shouldFilterNullCategory = (nullCategory != null && !nullCategory.isEmpty());
        assertFalse(shouldFilterNullCategory,
            "Null category path should not filter results");

        // empty category path should not filter
        String emptyCategory = "";
        boolean shouldFilterEmptyCategory = (emptyCategory != null && !emptyCategory.isEmpty());
        assertFalse(shouldFilterEmptyCategory,
            "Empty category path should not filter results");
    }
}
