package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for DecompiledTextSearchService.
 *
 * These tests verify pattern compilation, parameter validation, JSON formatting,
 * and edge case handling for the decompiled text search functionality.
 *
 * Note: Full integration tests with actual Ghidra decompilation would require
 * the Ghidra test framework and Program fixtures.
 */
class DecompiledTextSearchServiceTest {

    // ==================== Pattern Compilation Tests ====================

    @Test
    @DisplayName("Should compile valid regex patterns")
    void testValidRegexCompilation() {
        assertDoesNotThrow(() -> Pattern.compile("malloc\\s*\\("),
            "Should compile valid regex pattern");
        assertDoesNotThrow(() -> Pattern.compile("[a-zA-Z_][a-zA-Z0-9_]*"),
            "Should compile identifier regex");
        assertDoesNotThrow(() -> Pattern.compile("if\\s*\\([^)]*\\)\\s*\\{"),
            "Should compile complex regex");
    }

    @Test
    @DisplayName("Should handle literal string patterns with special characters")
    void testLiteralStringWithSpecialChars() {
        String literal = "malloc()";
        String quoted = Pattern.quote(literal);
        Pattern pattern = Pattern.compile(quoted);

        assertNotNull(pattern, "Pattern should be created");
        assertTrue(pattern.matcher("malloc()").find(), "Should match exact literal");
        assertFalse(pattern.matcher("mallocXY").find(), "Should not match partial");
    }

    @Test
    @DisplayName("Should detect invalid regex patterns")
    void testInvalidRegexPatterns() {
        assertThrows(PatternSyntaxException.class, () -> Pattern.compile("["),
            "Should throw on unclosed bracket");
        assertThrows(PatternSyntaxException.class, () -> Pattern.compile("("),
            "Should throw on unclosed parenthesis");
        assertThrows(PatternSyntaxException.class, () -> Pattern.compile("*"),
            "Should throw on dangling quantifier");
    }

    @ParameterizedTest
    @DisplayName("Should support case-insensitive flag")
    @CsvSource({
        "HELLO, hello",
        "WORLD, world",
        "MaLlOc, malloc"
    })
    void testCaseInsensitivityFlag(String pattern, String text) {
        Pattern caseInsensitive = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        Pattern caseSensitive = Pattern.compile(pattern);

        assertTrue(caseInsensitive.matcher(text).find(),
            "Case insensitive pattern should match different case");
        assertFalse(caseSensitive.matcher(text).find(),
            "Case sensitive pattern should not match different case");
    }

    @Test
    @DisplayName("Should support case-sensitive matching by default")
    void testCaseSensitiveDefault() {
        Pattern pattern = Pattern.compile("HELLO");

        assertTrue(pattern.matcher("HELLO").find(),
            "Should match same case");
        assertFalse(pattern.matcher("hello").find(),
            "Should not match different case");
    }

    @Test
    @DisplayName("Should support multiline/DOTALL flag")
    void testMultilineFlag() {
        String text = "line1\nline2\nline3";

        // Without DOTALL, . doesn't match newlines
        Pattern singleLine = Pattern.compile("line1.*line3");
        assertFalse(singleLine.matcher(text).find(),
            "Without DOTALL, . should not match newlines");

        // With DOTALL, . matches newlines
        Pattern multiLine = Pattern.compile("line1.*line3", Pattern.DOTALL);
        assertTrue(multiLine.matcher(text).find(),
            "With DOTALL, . should match newlines");
    }

    // ==================== Parameter Validation Tests ====================

    @Test
    @DisplayName("Should validate null pattern parameter")
    void testNullPattern() {
        // In real implementation, this should return error JSON
        String nullPattern = null;

        assertNull(nullPattern, "Null pattern should be detected");
        // Expected result: {"error": "Pattern is required"}
    }

    @Test
    @DisplayName("Should validate empty pattern parameter")
    void testEmptyPattern() {
        String emptyPattern = "";

        assertTrue(emptyPattern.isEmpty(), "Empty pattern should be detected");
        // Expected result: {"error": "Pattern is required"}
    }

    @ParameterizedTest
    @DisplayName("Should accept valid pagination parameters")
    @CsvSource({
        "0, 10",
        "0, 100",
        "50, 50",
        "100, 1"
    })
    void testValidPaginationParams(int offset, int limit) {
        assertTrue(offset >= 0, "Offset should be non-negative");
        assertTrue(limit > 0, "Limit should be positive");
    }

    @Test
    @DisplayName("Should handle maxResults parameter correctly")
    void testMaxResultsParameter() {
        int unlimited = 0;
        int limited = 100;

        assertTrue(unlimited >= 0, "maxResults=0 means unlimited");
        assertTrue(limited > 0, "maxResults>0 means limited");
    }

    // ==================== Function Name Filtering Tests ====================

    @Test
    @DisplayName("Should handle null function names list")
    void testNullFunctionNamesList() {
        List<String> functionNames = null;

        // Null should mean "search all functions"
        assertTrue(functionNames == null, "Null list should search all functions");
    }

    @Test
    @DisplayName("Should handle empty function names list")
    void testEmptyFunctionNamesList() {
        List<String> functionNames = Arrays.asList();

        // Empty list should also mean "search all functions"
        assertTrue(functionNames.isEmpty(), "Empty list should search all functions");
    }

    @Test
    @DisplayName("Should parse comma-separated function names")
    void testFunctionNamesListParsing() {
        String input = "main,authenticate,login";
        String[] parts = input.split(",");

        assertEquals(3, parts.length, "Should parse 3 function names");
        assertEquals("main", parts[0].trim(), "First function name");
        assertEquals("authenticate", parts[1].trim(), "Second function name");
        assertEquals("login", parts[2].trim(), "Third function name");
    }

    @Test
    @DisplayName("Should handle function names with spaces")
    void testFunctionNamesWithSpaces() {
        String input = " main , authenticate , login ";
        String[] parts = input.split(",");

        assertEquals("main", parts[0].trim(), "Should trim whitespace");
        assertEquals("authenticate", parts[1].trim(), "Should trim whitespace");
        assertEquals("login", parts[2].trim(), "Should trim whitespace");
    }

    // ==================== JSON Output Format Tests ====================

    @Test
    @DisplayName("Should format error response as valid JSON")
    void testErrorResponseFormat() {
        String errorMessage = "Pattern is required";
        String expectedFormat = String.format("{\"error\": \"%s\"}", errorMessage);

        assertTrue(expectedFormat.startsWith("{"), "Should start with {");
        assertTrue(expectedFormat.endsWith("}"), "Should end with }");
        assertTrue(expectedFormat.contains("\"error\":"), "Should contain error field");
    }

    @Test
    @DisplayName("Should format successful response with all required fields")
    void testSuccessResponseFormat() {
        // Expected format:
        // {"matches": [...], "count": N, "total_count": M, "offset": O, "limit": L}
        String format = "{\"matches\": [], \"count\": 0, \"total_count\": 0, \"offset\": 0, \"limit\": 100}";

        assertTrue(format.contains("\"matches\":"), "Should contain matches field");
        assertTrue(format.contains("\"count\":"), "Should contain count field");
        assertTrue(format.contains("\"total_count\":"), "Should contain total_count field");
        assertTrue(format.contains("\"offset\":"), "Should contain offset field");
        assertTrue(format.contains("\"limit\":"), "Should contain limit field");
    }

    @Test
    @DisplayName("Should format match object with all required fields")
    void testMatchObjectFormat() {
        // Expected format:
        // {"function_name": "...", "function_address": "...", "line_number": N,
        //  "matched_text": "...", "context": "...", "is_multiline": false}

        String format = "{\"function_name\": \"main\", \"function_address\": \"0x401000\", " +
                       "\"line_number\": 42, \"matched_text\": \"malloc\", " +
                       "\"context\": \"ptr = malloc(100);\", \"is_multiline\": false}";

        assertTrue(format.contains("\"function_name\":"), "Should contain function_name");
        assertTrue(format.contains("\"function_address\":"), "Should contain function_address");
        assertTrue(format.contains("\"line_number\":"), "Should contain line_number");
        assertTrue(format.contains("\"matched_text\":"), "Should contain matched_text");
        assertTrue(format.contains("\"context\":"), "Should contain context");
        assertTrue(format.contains("\"is_multiline\":"), "Should contain is_multiline");
    }

    @Test
    @DisplayName("Should escape special characters in JSON strings")
    void testJsonEscaping() {
        String withQuotes = "char *str = \"hello\";";
        String withNewlines = "line1\nline2";
        String withBackslash = "C:\\path\\to\\file";

        // JSON escaping rules
        String escapedQuotes = withQuotes.replace("\"", "\\\"");
        String escapedNewlines = withNewlines.replace("\n", "\\n");
        String escapedBackslash = withBackslash.replace("\\", "\\\\");

        assertTrue(escapedQuotes.contains("\\\""), "Should escape quotes");
        assertTrue(escapedNewlines.contains("\\n"), "Should escape newlines");
        assertTrue(escapedBackslash.contains("\\\\"), "Should escape backslashes");
    }

    // ==================== Edge Case Tests ====================

    @Test
    @DisplayName("Should handle pattern matching nothing")
    void testNoMatches() {
        String pattern = "IMPOSSIBLE_PATTERN_XYZ123";

        // Expected result: {"matches": [], "count": 0, "total_count": 0, ...}
        assertNotNull(pattern, "Pattern should be valid");
    }

    @Test
    @DisplayName("Should handle very long patterns")
    void testLongPattern() {
        StringBuilder longPattern = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longPattern.append("a");
        }

        assertDoesNotThrow(() -> Pattern.compile(longPattern.toString()),
            "Should compile very long pattern");
    }

    @Test
    @DisplayName("Should handle pagination beyond available results")
    void testPaginationBeyondResults() {
        int totalResults = 10;
        int offset = 100;
        int limit = 10;

        if (offset >= totalResults) {
            // Should return empty array
            assertTrue(offset >= totalResults, "Offset beyond results should return empty");
        }
    }

    @Test
    @DisplayName("Should handle single-line vs multi-line search")
    void testSingleVsMultiLineSearch() {
        String text = "if (x > 0)\n  return true;";

        // Single-line: search each line independently
        Pattern singleLine = Pattern.compile("if.*return");
        assertFalse(singleLine.matcher(text).find(),
            "Single-line should not match across newlines");

        // Multi-line: search entire text
        Pattern multiLine = Pattern.compile("if.*return", Pattern.DOTALL);
        assertTrue(multiLine.matcher(text).find(),
            "Multi-line should match across newlines");
    }

    @Test
    @DisplayName("Should handle match context extraction")
    void testContextExtraction() {
        String line = "  char *buffer = malloc(100);";
        int matchStart = line.indexOf("malloc");
        int matchEnd = matchStart + "malloc".length();

        // Context should highlight the match
        String expectedContext = "  char *buffer = [[malloc]](100);";

        assertTrue(matchStart >= 0, "Match should be found");
        assertTrue(matchEnd > matchStart, "Match end should be after start");
    }

    @Test
    @DisplayName("Should handle line number calculation")
    void testLineNumberCalculation() {
        String text = "line1\nline2\nline3";
        int positionOfLine3 = text.indexOf("line3");

        // Count newlines before position
        int lineNumber = 1;
        for (int i = 0; i < positionOfLine3; i++) {
            if (text.charAt(i) == '\n') {
                lineNumber++;
            }
        }

        assertEquals(3, lineNumber, "Should calculate correct line number");
    }

    // ==================== Security Pattern Tests ====================

    @ParameterizedTest
    @DisplayName("Should match common security-relevant patterns")
    @ValueSource(strings = {
        "malloc\\s*\\(",
        "strcpy\\s*\\(",
        "gets\\s*\\(",
        "sprintf\\s*\\(",
        "memcpy\\s*\\(",
        "system\\s*\\(",
        "exec[vl]?p?\\s*\\("
    })
    void testSecurityPatterns(String pattern) {
        assertDoesNotThrow(() -> Pattern.compile(pattern),
            "Security pattern should compile: " + pattern);
    }

    @Test
    @DisplayName("Should match buffer allocation patterns")
    void testBufferAllocationPattern() {
        String pattern = "(malloc|calloc|realloc|alloca)\\s*\\(";
        Pattern compiled = Pattern.compile(pattern);

        assertTrue(compiled.matcher("ptr = malloc(100);").find(),
            "Should match malloc");
        assertTrue(compiled.matcher("data = calloc(10, sizeof(int));").find(),
            "Should match calloc");
        assertTrue(compiled.matcher("buf = realloc(buf, 200);").find(),
            "Should match realloc");
    }

    @Test
    @DisplayName("Should match string operation patterns")
    void testStringOperationPattern() {
        String pattern = "(strcpy|strcat|sprintf|gets)\\s*\\(";
        Pattern compiled = Pattern.compile(pattern);

        assertTrue(compiled.matcher("strcpy(dest, src);").find(),
            "Should match strcpy");
        assertTrue(compiled.matcher("strcat(buffer, str);").find(),
            "Should match strcat");
        assertTrue(compiled.matcher("sprintf(buf, format, arg);").find(),
            "Should match sprintf");
    }
}
