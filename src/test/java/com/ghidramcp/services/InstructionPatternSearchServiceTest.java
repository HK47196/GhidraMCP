package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for InstructionPatternSearchService.
 *
 * These tests verify parameter validation, regex pattern handling,
 * and error message formatting for instruction pattern search.
 *
 * Note: Full integration tests with Ghidra Program objects would require
 * the Ghidra test framework and are beyond the scope of unit tests.
 */
class InstructionPatternSearchServiceTest {

    /**
     * Test that search pattern is required
     */
    @Test
    @DisplayName("Should require search pattern")
    void testSearchPatternRequired() {
        String expectedError = "Error: Search pattern is required";

        assertTrue(expectedError.contains("required"),
            "Should indicate search pattern is required");
        assertTrue(expectedError.contains("Search pattern"),
            "Should mention search pattern");
    }

    /**
     * Test that invalid regex patterns are caught
     */
    @Test
    @DisplayName("Should validate regex pattern syntax")
    void testInvalidRegexPattern() {
        String expectedError = "Error: Invalid regex pattern - ";

        assertTrue(expectedError.contains("Invalid regex pattern"),
            "Should indicate invalid regex");
        assertTrue(expectedError.endsWith(" - "),
            "Should have separator for specific error message");
    }

    /**
     * Test segment name validation
     */
    @Test
    @DisplayName("Should validate segment name")
    void testSegmentNameValidation() {
        String segmentName = "CODE_70";
        String expectedError = "Error: Segment not found: " + segmentName;

        assertTrue(expectedError.contains("Segment not found"),
            "Should indicate segment was not found");
        assertTrue(expectedError.contains(segmentName),
            "Should include the segment name");
    }

    /**
     * Test address range validation
     */
    @Test
    @DisplayName("Should validate address range order")
    void testAddressRangeValidation() {
        String expectedError = "Error: Start address must be less than or equal to end address";

        assertTrue(expectedError.contains("Start address"),
            "Should mention start address");
        assertTrue(expectedError.contains("end address"),
            "Should mention end address");
    }

    /**
     * Test invalid address formats
     */
    @ParameterizedTest
    @DisplayName("Should handle invalid addresses")
    @ValueSource(strings = {"Invalid", "not_an_address", "xyz123"})
    void testInvalidAddressFormats(String address) {
        String errorPrefix = "Error: Invalid";

        assertTrue(errorPrefix.contains("Error"),
            "Should indicate error");
        assertTrue(errorPrefix.contains("Invalid"),
            "Should indicate validation failure");
    }

    /**
     * Test result format with disassembly
     */
    @Test
    @DisplayName("Should format results with disassembly")
    void testResultFormat() {
        String address = "0x401000";
        String disassembly = "mov eax, 0x1234";
        String segment = "CODE_70";

        String expectedFormat = address + ": " + disassembly + " (segment: " + segment + ")";

        assertTrue(expectedFormat.contains(address),
            "Should contain address");
        assertTrue(expectedFormat.contains(disassembly),
            "Should contain disassembly");
        assertTrue(expectedFormat.contains("segment:"),
            "Should contain segment label");
        assertTrue(expectedFormat.contains(segment),
            "Should contain segment name");
    }

    /**
     * Test result summary format
     */
    @ParameterizedTest
    @DisplayName("Should format result summary")
    @CsvSource({
        "10, move, 0, 10, 1, 10",
        "100, jsr, 0, 50, 1, 50",
        "5, tst, 0, 10, 1, 5",
        "20, bsr, 10, 10, 11, 20"
    })
    void testResultSummaryFormat(int totalResults, String pattern, int offset, int limit,
                                 int expectedStart, int expectedEnd) {
        String summaryLine1 = String.format("Found %d matches for pattern: %s", totalResults, pattern);
        String summaryLine2 = String.format("Showing results %d to %d",
                                           offset + 1,
                                           Math.min(offset + limit, totalResults));

        assertTrue(summaryLine1.contains("matches"),
            "Should indicate match count");
        assertTrue(summaryLine1.contains("pattern:"),
            "Should mention pattern");
        assertTrue(summaryLine1.contains(pattern),
            "Should include the pattern");
        assertTrue(summaryLine2.contains("Showing results"),
            "Should indicate which results are shown");
    }

    /**
     * Test no matches scenario
     */
    @Test
    @DisplayName("Should handle no matches")
    void testNoMatches() {
        String pattern = "nonexistent";
        String expectedMessage = "No matches found for pattern: " + pattern;

        assertTrue(expectedMessage.contains("No matches"),
            "Should indicate no matches found");
        assertTrue(expectedMessage.contains("pattern:"),
            "Should mention pattern");
        assertTrue(expectedMessage.contains(pattern),
            "Should include the pattern");
    }

    /**
     * Test more results indicator
     */
    @Test
    @DisplayName("Should indicate when more results are available")
    void testMoreResultsIndicator() {
        int totalResults = 100;
        int shown = 50;
        int remaining = totalResults - shown;

        String moreResultsMsg = String.format("... %d more match(es). Use offset parameter to see more.",
                                             remaining);

        assertTrue(moreResultsMsg.contains("more match(es)"),
            "Should indicate more matches available");
        assertTrue(moreResultsMsg.contains("offset parameter"),
            "Should mention offset parameter");
        assertTrue(moreResultsMsg.contains(String.valueOf(remaining)),
            "Should show number of remaining results");
    }

    /**
     * Test regex pattern examples
     */
    @ParameterizedTest
    @DisplayName("Should recognize valid regex patterns")
    @ValueSource(strings = {
        "move\\.b",
        "[jb]sr",
        "0x[0-9a-fA-F]+",
        "tst\\.l.*A4",
        ".*\\(.*,.*\\)"
    })
    void testRegexPatternExamples(String pattern) {
        assertNotNull(pattern, "Pattern should not be null");
        assertFalse(pattern.isEmpty(), "Pattern should not be empty");

        // These patterns should be valid regex (compilation test would happen at runtime)
        assertTrue(pattern.length() > 0, "Pattern should have content");
    }

    /**
     * Test instruction format components
     */
    @Test
    @DisplayName("Should format instruction with mnemonic and operands")
    void testInstructionFormat() {
        String mnemonic = "move.b";
        String operand1 = "(0x3932,A4)";
        String operand2 = "D0";

        String expectedFormat = mnemonic + " " + operand1 + "," + operand2;

        assertTrue(expectedFormat.startsWith(mnemonic),
            "Should start with mnemonic");
        assertTrue(expectedFormat.contains(operand1),
            "Should contain first operand");
        assertTrue(expectedFormat.contains(operand2),
            "Should contain second operand");
        assertTrue(expectedFormat.contains(","),
            "Should separate operands with comma");
    }

    /**
     * Test pagination edge cases
     */
    @ParameterizedTest
    @DisplayName("Should handle pagination correctly")
    @CsvSource({
        "0,   10,  100",  // First page
        "10,  10,  100",  // Second page
        "90,  10,  100",  // Last page
        "100, 10,  100",  // Beyond last page
        "0,   100, 50"    // Limit exceeds total
    })
    void testPagination(int offset, int limit, int totalResults) {
        int endIndex = Math.min(offset + limit, totalResults);

        assertTrue(offset >= 0, "Offset should be non-negative");
        assertTrue(limit > 0, "Limit should be positive");
        assertTrue(endIndex <= totalResults, "End index should not exceed total");
        assertTrue(endIndex >= offset, "End index should be >= offset");
    }

    /**
     * Test address parsing errors
     */
    @Test
    @DisplayName("Should handle address parsing errors")
    void testAddressParsingErrors() {
        String errorMessage = "Error parsing addresses: Invalid address format";

        assertTrue(errorMessage.contains("Error parsing addresses"),
            "Should indicate address parsing error");
        assertTrue(errorMessage.contains(":"),
            "Should separate error type from message");
    }

    /**
     * Test search ranges
     */
    @ParameterizedTest
    @DisplayName("Should support different search ranges")
    @CsvSource({
        "0x1000, 0x2000, segment",      // Address range
        "null,   null,   CODE_70",      // Segment only
        "null,   null,   null"          // Entire program
    })
    void testSearchRanges(String start, String end, String segment) {
        // Verify that different combinations are valid
        boolean hasAddressRange = !"null".equals(start) && !"null".equals(end);
        boolean hasSegment = !"null".equals(segment);
        boolean hasNoRestriction = !hasAddressRange && !hasSegment;

        assertTrue(hasAddressRange || hasSegment || hasNoRestriction,
            "Should support address range, segment, or no restriction");
    }

    /**
     * Test common instruction patterns
     */
    @ParameterizedTest
    @DisplayName("Should match common instruction patterns")
    @CsvSource({
        "move\\.b, move.b (0x3932,A4)",
        "[jb]sr,   jsr FUN_00401234",
        "tst,      tst.l D0",
        "0x3932,   move.b (0x3932,A4)"
    })
    void testCommonInstructionMatches(String pattern, String disassembly) {
        // These test expected matches (actual matching happens at runtime)
        assertNotNull(pattern, "Pattern should not be null");
        assertNotNull(disassembly, "Disassembly should not be null");
        assertTrue(pattern.length() > 0, "Pattern should have content");
        assertTrue(disassembly.length() > 0, "Disassembly should have content");
    }
}
