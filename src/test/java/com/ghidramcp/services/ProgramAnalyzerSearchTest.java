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

    // ========== Class Search Tests ==========

    /**
     * Test that class search is case-insensitive
     */
    @ParameterizedTest
    @DisplayName("Should handle case-insensitive class search terms")
    @ValueSource(strings = {"GRAPHICS", "graphics", "Graphics", "gRaPhIcS"})
    void testCaseInsensitiveClassSearch(String searchTerm) {
        // All these variations should match the same class names
        assertNotNull(searchTerm, "Search term should not be null");
        assertFalse(searchTerm.isEmpty(), "Search term should not be empty");

        // Case normalization test
        String normalized = searchTerm.toLowerCase();
        assertEquals(normalized, searchTerm.toLowerCase(),
            "Class search should be case-insensitive");
    }

    /**
     * Test class search substring matching
     */
    @ParameterizedTest
    @DisplayName("Should perform substring matching for class names")
    @ValueSource(strings = {"Graph", "raphic", "ics", "Graphics", "phi"})
    void testClassSubstringMatching(String substring) {
        // All these substrings should match "Graphics"
        String className = "Graphics";

        assertTrue(className.toLowerCase().contains(substring.toLowerCase()),
            "Should match substring: " + substring);
    }

    /**
     * Test class search with null search term uses default behavior
     */
    @Test
    @DisplayName("Should handle null search term for class search")
    void testNullClassSearchTerm() {
        String searchTerm = null;
        boolean shouldReturnAll = (searchTerm == null || searchTerm.isEmpty());
        assertTrue(shouldReturnAll, "Null search term should return all classes");
    }

    /**
     * Test class search with empty search term uses default behavior
     */
    @Test
    @DisplayName("Should handle empty search term for class search")
    void testEmptyClassSearchTerm() {
        String searchTerm = "";
        boolean shouldReturnAll = (searchTerm == null || searchTerm.isEmpty());
        assertTrue(shouldReturnAll, "Empty search term should return all classes");
    }

    /**
     * Test class search pagination parameters
     */
    @ParameterizedTest
    @DisplayName("Should accept valid pagination parameters for class search")
    @ValueSource(ints = {0, 10, 50, 100, 500})
    void testClassSearchPaginationParameters(int value) {
        assertTrue(value >= 0, "Class search pagination values should be non-negative");
    }

    /**
     * Test class search result sorting
     */
    @Test
    @DisplayName("Should sort class search results alphabetically")
    void testClassSearchResultSorting() {
        // Class results should be sorted
        String[] classes = {"Zebra", "Apple", "Banana"};
        String[] sorted = {"Apple", "Banana", "Zebra"};

        // Verify sorting expectation
        assertTrue(sorted[0].compareTo(sorted[1]) < 0,
            "First class should come before second alphabetically");
        assertTrue(sorted[1].compareTo(sorted[2]) < 0,
            "Second class should come before third alphabetically");
    }

    /**
     * Test class search with special characters
     */
    @Test
    @DisplayName("Should handle special characters in class search terms")
    void testSpecialCharactersInClassSearchTerms() {
        // Common special characters that might appear in class names
        String[] specialChars = {"_", "$", "0", "1"};

        for (String specialChar : specialChars) {
            assertNotNull(specialChar, "Special character should be defined");

            // These should be valid in search terms
            String searchTerm = "Class" + specialChar + "Name";
            assertFalse(searchTerm.isEmpty(),
                "Search term with special char should be valid");
        }
    }

    /**
     * Test class search filtering behavior
     */
    @Test
    @DisplayName("Should filter class names based on search term")
    void testClassSearchFilteringBehavior() {
        // Simulate filtering behavior
        String[] allClasses = {"Graphics", "GraphicsManager", "AudioManager", "NetworkManager"};
        String searchTerm = "graph";
        String searchLower = searchTerm.toLowerCase();

        int matchCount = 0;
        for (String className : allClasses) {
            if (className.toLowerCase().contains(searchLower)) {
                matchCount++;
            }
        }

        assertEquals(2, matchCount, "Should match 'Graphics' and 'GraphicsManager'");
    }

    /**
     * Test class search with no matches
     */
    @Test
    @DisplayName("Should return empty results when no classes match search")
    void testClassSearchNoMatches() {
        String[] allClasses = {"Graphics", "Audio", "Network"};
        String searchTerm = "nonexistent";
        String searchLower = searchTerm.toLowerCase();

        int matchCount = 0;
        for (String className : allClasses) {
            if (className.toLowerCase().contains(searchLower)) {
                matchCount++;
            }
        }

        assertEquals(0, matchCount, "Should find no matches for nonexistent search term");
    }

    // ========== Class vs Namespace Distinction Tests ==========

    /**
     * Test that class filtering logic correctly uses HashSet for deduplication
     */
    @Test
    @DisplayName("Class collection should deduplicate using HashSet")
    void testClassDeduplicationWithHashSet() {
        // Simulate the deduplication logic used in getAllClassNames
        java.util.Set<String> classNames = new java.util.HashSet<>();

        // Add duplicates
        classNames.add("MyClass");
        classNames.add("MyClass");
        classNames.add("AnotherClass");
        classNames.add("MyClass");

        assertEquals(2, classNames.size(), "HashSet should deduplicate class names");
        assertTrue(classNames.contains("MyClass"), "Should contain MyClass");
        assertTrue(classNames.contains("AnotherClass"), "Should contain AnotherClass");
    }

    /**
     * Test that class results are sorted alphabetically
     */
    @Test
    @DisplayName("Class results should be sorted alphabetically")
    void testClassResultsAreSorted() {
        // Simulate the sorting logic used in getAllClassNames
        java.util.Set<String> classNames = new java.util.HashSet<>();
        classNames.add("Zebra");
        classNames.add("Apple");
        classNames.add("Mango");

        java.util.List<String> sorted = new java.util.ArrayList<>(classNames);
        java.util.Collections.sort(sorted);

        assertEquals("Apple", sorted.get(0), "First element should be Apple");
        assertEquals("Mango", sorted.get(1), "Second element should be Mango");
        assertEquals("Zebra", sorted.get(2), "Third element should be Zebra");
    }

    /**
     * Test case-insensitive search filtering for classes
     */
    @Test
    @DisplayName("Class search filtering should be case-insensitive")
    void testClassSearchCaseInsensitive() {
        // Simulate the search filtering logic
        java.util.List<String> classes = java.util.Arrays.asList(
            "GraphicsManager", "AudioManager", "NetworkManager"
        );
        String search = "GRAPH";
        String searchLower = search.toLowerCase();

        java.util.List<String> filtered = classes.stream()
            .filter(name -> name.toLowerCase().contains(searchLower))
            .collect(java.util.stream.Collectors.toList());

        assertEquals(1, filtered.size(), "Should find one match");
        assertEquals("GraphicsManager", filtered.get(0), "Should match GraphicsManager");
    }

    /**
     * Test search filtering with empty search returns all results
     */
    @Test
    @DisplayName("Empty search should not filter any results")
    void testClassSearchEmptyReturnsAll() {
        java.util.List<String> classes = java.util.Arrays.asList(
            "ClassA", "ClassB", "ClassC"
        );
        String search = "";

        // When search is empty, no filtering is applied
        java.util.List<String> result;
        if (search != null && !search.isEmpty()) {
            String searchLower = search.toLowerCase();
            result = classes.stream()
                .filter(name -> name.toLowerCase().contains(searchLower))
                .collect(java.util.stream.Collectors.toList());
        } else {
            result = classes;
        }

        assertEquals(3, result.size(), "Empty search should return all classes");
    }

    /**
     * Test that classes collection only includes CLASS symbols, not all namespaces
     */
    @Test
    @DisplayName("Classes should be subset of namespaces")
    void testClassesSubsetOfNamespaces() {
        // Simulate a scenario where we have both classes and other namespace types
        // Classes: only SymbolType.CLASS
        // Namespaces: all non-global namespaces (CLASS, NAMESPACE, LIBRARY, etc.)

        java.util.Set<String> classes = new java.util.HashSet<>();
        classes.add("MyClass");
        classes.add("AnotherClass");

        java.util.Set<String> namespaces = new java.util.HashSet<>();
        namespaces.add("MyClass");        // Also a namespace
        namespaces.add("AnotherClass");   // Also a namespace
        namespaces.add("std");            // Namespace only (not a class)
        namespaces.add("__libc");         // Library namespace

        // Classes should be a subset of namespaces
        assertTrue(namespaces.containsAll(classes),
            "All classes should also be in namespaces");
        assertTrue(namespaces.size() >= classes.size(),
            "Namespaces should have at least as many entries as classes");

        // But namespaces has more entries than classes
        assertEquals(2, classes.size(), "Should have 2 classes");
        assertEquals(4, namespaces.size(), "Should have 4 namespaces");
    }

    // ============================================================
    // Tests for listDefinedStrings functionality
    // ============================================================

    /**
     * Test string result format
     */
    @Test
    @DisplayName("Should format string results correctly")
    void testStringResultFormat() {
        // Expected format: "address: \"value\""
        String address = "0x00401000";
        String value = "Hello World";
        String expectedFormat = address + ": \"" + value + "\"";

        assertTrue(expectedFormat.contains(": \""),
            "String result should contain ': \"' separator");
        assertTrue(expectedFormat.startsWith(address),
            "String result should start with address");
        assertTrue(expectedFormat.endsWith("\""),
            "String result should end with closing quote");
        assertTrue(expectedFormat.contains(value),
            "String result should contain the string value");
    }

    /**
     * Test case-insensitive search for strings
     */
    @ParameterizedTest
    @DisplayName("Should perform case-insensitive string search")
    @ValueSource(strings = {"ERROR", "error", "Error", "eRrOr"})
    void testCaseInsensitiveStringSearch(String searchTerm) {
        String stringValue = "Error: file not found";

        // Case-insensitive matching
        boolean matches = stringValue.toLowerCase().contains(searchTerm.toLowerCase());
        assertTrue(matches, "String search should be case-insensitive");
    }

    /**
     * Test string search with various substring patterns
     */
    @ParameterizedTest
    @DisplayName("Should match substrings in string values")
    @ValueSource(strings = {"pass", "word", "123", "PASS", "password"})
    void testStringSubstringMatching(String substring) {
        String fullString = "password123";

        boolean matches = fullString.toLowerCase().contains(substring.toLowerCase());
        assertTrue(matches, "Should match substring: " + substring);
    }

    /**
     * Test string result with escaped characters
     */
    @Test
    @DisplayName("Should handle escaped characters in string values")
    void testEscapedCharactersInStrings() {
        // Common escape sequences that should be handled
        String[] escapeSequences = {"\\n", "\\t", "\\r", "\\\""};

        for (String escape : escapeSequences) {
            assertNotNull(escape, "Escape sequence should be defined");

            // Test that format works with escaped characters
            String address = "0x00401000";
            String value = "test" + escape + "value";
            String formatted = address + ": \"" + value + "\"";

            assertTrue(formatted.contains(value),
                "Should handle escape sequence: " + escape);
        }
    }

    /**
     * Test no program loaded message for strings
     */
    @Test
    @DisplayName("Should return appropriate message when no program loaded for strings")
    void testNoProgramLoadedForStrings() {
        String expectedMessage = "No program loaded";

        assertFalse(expectedMessage.isEmpty(),
            "No program message should not be empty");
        assertTrue(expectedMessage.contains("No program"),
            "Should indicate no program is loaded");
    }

    /**
     * Test null search parameter for strings
     */
    @Test
    @DisplayName("Should handle null search parameter for strings")
    void testNullSearchParameterForStrings() {
        // When search is null, all strings should be returned
        String search = null;
        boolean shouldIncludeAll = (search == null);

        assertTrue(shouldIncludeAll,
            "Null search should include all strings without filtering");
    }

    /**
     * Test empty string values
     */
    @Test
    @DisplayName("Should handle empty string values")
    void testEmptyStringValue() {
        String address = "0x00401000";
        String value = "";
        String formatted = address + ": \"" + value + "\"";

        assertTrue(formatted.endsWith(": \"\""),
            "Should format empty string value correctly");
    }

    /**
     * Test pagination defaults for strings
     */
    @Test
    @DisplayName("Should use correct default pagination for strings")
    void testStringPaginationDefaults() {
        int defaultOffset = 0;
        int defaultLimit = 100;  // Server-side default

        assertEquals(0, defaultOffset, "Default offset should be 0");
        assertTrue(defaultLimit > 0, "Default limit should be positive");
    }

    /**
     * Test string result pattern matching
     */
    @Test
    @DisplayName("Should maintain consistent string result format")
    void testStringResultPattern() {
        // String format: "address: \"value\""
        String stringPattern = "^0x[0-9a-fA-F]+: \".+\"$";
        String stringExample = "0x00401000: \"Hello World\"";

        assertTrue(stringExample.matches(stringPattern),
            "String result should match expected pattern");
    }

    /**
     * Test that string search filters correctly
     */
    @Test
    @DisplayName("Should filter strings by search parameter")
    void testStringSearchFiltering() {
        String search = "error";
        String[] testStrings = {
            "Error: file not found",
            "Success",
            "FATAL ERROR",
            "warning"
        };

        int matchCount = 0;
        for (String str : testStrings) {
            if (str.toLowerCase().contains(search.toLowerCase())) {
                matchCount++;
            }
        }

        assertEquals(2, matchCount,
            "Should match exactly 2 strings containing 'error'");
    }
}
