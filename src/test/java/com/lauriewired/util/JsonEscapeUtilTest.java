package com.lauriewired.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for JSON escape sequence handling in bulk operations.
 *
 * These tests document the expected behavior of JSON string unescaping
 * that should be applied when parsing bulk operation parameters.
 *
 * Related issue: Bulk operations were inserting literal '\n' instead of
 * actual newlines. The fix added proper JSON escape sequence handling.
 */
class JsonEscapeUtilTest {

    /**
     * Helper method that mimics the unescapeJsonString logic from GhidraMCPPlugin.
     * This is the same implementation that's used in the plugin.
     */
    private String unescapeJsonString(String str) {
        if (str == null) {
            return null;
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c == '\\' && i + 1 < str.length()) {
                char next = str.charAt(i + 1);
                switch (next) {
                    case 'n': result.append('\n'); i++; break;
                    case 't': result.append('\t'); i++; break;
                    case 'r': result.append('\r'); i++; break;
                    case 'b': result.append('\b'); i++; break;
                    case 'f': result.append('\f'); i++; break;
                    case '"': result.append('"'); i++; break;
                    case '\\': result.append('\\'); i++; break;
                    case '/': result.append('/'); i++; break;
                    case 'u': // Unicode escape (backslash-u followed by 4 hex digits)
                        if (i + 5 < str.length()) {
                            String hex = str.substring(i + 2, i + 6);
                            try {
                                result.append((char) Integer.parseInt(hex, 16));
                                i += 5;
                            } catch (NumberFormatException e) {
                                result.append(c); // Keep original if invalid
                            }
                        } else {
                            result.append(c);
                        }
                        break;
                    default:
                        result.append(c); // Keep the backslash for unknown escapes
                }
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    @Test
    @DisplayName("Should convert \\n to actual newline character")
    void testNewlineEscape() {
        String input = "Line 1\\nLine 2\\nLine 3";
        String expected = "Line 1\nLine 2\nLine 3";

        String result = unescapeJsonString(input);

        assertEquals(expected, result);
        assertTrue(result.contains("\n"));
        assertFalse(result.contains("\\n"));
    }

    @Test
    @DisplayName("Should convert \\t to actual tab character")
    void testTabEscape() {
        String input = "Column1\\tColumn2\\tColumn3";
        String expected = "Column1\tColumn2\tColumn3";

        String result = unescapeJsonString(input);

        assertEquals(expected, result);
        assertTrue(result.contains("\t"));
    }

    @Test
    @DisplayName("Should convert \\r to carriage return")
    void testCarriageReturnEscape() {
        String input = "Line 1\\rLine 2";
        String expected = "Line 1\rLine 2";

        assertEquals(expected, unescapeJsonString(input));
    }

    @Test
    @DisplayName("Should handle multiple escape sequences in one string")
    void testMultipleEscapes() {
        String input = "Header\\n\\tColumn1\\tColumn2\\nRow1\\tValue1\\tValue2";
        String expected = "Header\n\tColumn1\tColumn2\nRow1\tValue1\tValue2";

        String result = unescapeJsonString(input);

        assertEquals(expected, result);
        assertTrue(result.contains("\n"));
        assertTrue(result.contains("\t"));
    }

    @Test
    @DisplayName("Should convert \\\" to double quote")
    void testQuoteEscape() {
        String input = "He said \\\"Hello\\\"";
        String expected = "He said \"Hello\"";

        assertEquals(expected, unescapeJsonString(input));
    }

    @Test
    @DisplayName("Should convert \\\\ to single backslash")
    void testBackslashEscape() {
        String input = "Path: C:\\\\Users\\\\test";
        String expected = "Path: C:\\Users\\test";

        assertEquals(expected, unescapeJsonString(input));
    }

    @Test
    @DisplayName("Should convert \\/ to forward slash")
    void testForwardSlashEscape() {
        String input = "http:\\/\\/example.com";
        String expected = "http://example.com";

        assertEquals(expected, unescapeJsonString(input));
    }

    @Test
    @DisplayName("Should handle Unicode escape sequences (backslash-u + 4 hex digits)")
    void testUnicodeEscape() {
        // Use string concatenation to avoid Java compiler processing the unicode escape
        String input = "Copyright " + "\\u" + "00A9 2024";
        String expected = "Copyright © 2024";

        assertEquals(expected, unescapeJsonString(input));
    }

    @Test
    @DisplayName("Should handle multiple Unicode escapes")
    void testMultipleUnicodeEscapes() {
        // Use string concatenation to avoid Java compiler processing unicode escapes
        // This represents: \u0048\u0065\u006C\u006C\u006F which spells "Hello"
        String input = "\\u" + "0048" + "\\u" + "0065" + "\\u" + "006C" + "\\u" + "006C" + "\\u" + "006F";
        String expected = "Hello";

        assertEquals(expected, unescapeJsonString(input));
    }

    @Test
    @DisplayName("Should handle invalid Unicode escape gracefully")
    void testInvalidUnicodeEscape() {
        // Use string concatenation to avoid Java compiler processing the unicode escape
        String input = "Test " + "\\u" + "GGGG value";

        // Should keep the backslash when Unicode escape is invalid
        String result = unescapeJsonString(input);
        assertTrue(result.contains("\\"));
    }

    @Test
    @DisplayName("Should handle string with no escapes")
    void testNoEscapes() {
        String input = "Plain text with no escapes";

        assertEquals(input, unescapeJsonString(input));
    }

    @Test
    @DisplayName("Should handle empty string")
    void testEmptyString() {
        assertEquals("", unescapeJsonString(""));
    }

    @Test
    @DisplayName("Should handle null input")
    void testNullInput() {
        assertNull(unescapeJsonString(null));
    }

    @Test
    @DisplayName("Should handle backslash at end of string")
    void testTrailingBackslash() {
        String input = "Test\\";

        // Trailing backslash with no following character should be kept
        String result = unescapeJsonString(input);
        assertEquals("Test\\", result);
    }

    @Test
    @DisplayName("Should handle unknown escape sequences")
    void testUnknownEscape() {
        String input = "Test\\xValue";

        // Unknown escape sequence \x should keep the backslash
        String result = unescapeJsonString(input);
        assertEquals("Test\\xValue", result);
    }

    @Test
    @DisplayName("Should handle real-world plate comment with newlines")
    void testPlateCommentWithNewlines() {
        // This is the actual use case that was failing
        String input = "Function: ProcessData\\nParameters:\\n  - input: char*\\n  - size: int\\nReturns: bool";
        String expected = "Function: ProcessData\nParameters:\n  - input: char*\n  - size: int\nReturns: bool";

        String result = unescapeJsonString(input);

        assertEquals(expected, result);
        // Verify it's an actual newline, not the literal string
        String[] lines = result.split("\n");
        assertEquals(5, lines.length);
        assertEquals("Function: ProcessData", lines[0]);
    }

    @Test
    @DisplayName("Should handle mixed escapes in plate comment")
    void testMixedEscapesInComment() {
        String input = "Note:\\n\\tThis is indented\\n\\tMultiple escapes: \\\"quoted\\\"";
        String expected = "Note:\n\tThis is indented\n\tMultiple escapes: \"quoted\"";

        assertEquals(expected, unescapeJsonString(input));
    }

    @Test
    @DisplayName("Should handle all standard JSON escapes")
    void testAllStandardEscapes() {
        String input = "\\n\\t\\r\\b\\f\\\"\\\\";
        String expected = "\n\t\r\b\f\"\\";

        assertEquals(expected, unescapeJsonString(input));
    }

    @Test
    @DisplayName("Should handle escape sequences at string boundaries")
    void testEscapesAtBoundaries() {
        String input = "\\nStart with newline\\n";
        String expected = "\nStart with newline\n";

        assertEquals(expected, unescapeJsonString(input));
    }

    @Test
    @DisplayName("Should handle consecutive escape sequences")
    void testConsecutiveEscapes() {
        String input = "Test\\n\\n\\nTriple newline";
        String expected = "Test\n\n\nTriple newline";

        assertEquals(expected, unescapeJsonString(input));
    }
}
