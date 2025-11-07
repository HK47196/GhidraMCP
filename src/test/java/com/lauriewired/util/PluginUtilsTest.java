package com.lauriewired.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Test suite for PluginUtils utility methods.
 */
class PluginUtilsTest {

    @Test
    @DisplayName("paginateList should return correct subset with valid offset and limit")
    void testPaginateListNormalCase() {
        List<String> items = Arrays.asList("item1", "item2", "item3", "item4", "item5");
        String result = PluginUtils.paginateList(items, 1, 2);

        assertEquals("item2\nitem3", result);
    }

    @Test
    @DisplayName("paginateList should return empty string when offset exceeds list size")
    void testPaginateListOffsetExceedsSize() {
        List<String> items = Arrays.asList("item1", "item2", "item3");
        String result = PluginUtils.paginateList(items, 10, 5);

        assertEquals("", result);
    }

    @Test
    @DisplayName("paginateList should handle negative offset by treating it as 0")
    void testPaginateListNegativeOffset() {
        List<String> items = Arrays.asList("item1", "item2", "item3");
        String result = PluginUtils.paginateList(items, -5, 2);

        assertEquals("item1\nitem2", result);
    }

    @Test
    @DisplayName("paginateList should return remaining items when limit exceeds available items")
    void testPaginateListLimitExceedsAvailable() {
        List<String> items = Arrays.asList("item1", "item2", "item3");
        String result = PluginUtils.paginateList(items, 1, 100);

        assertEquals("item2\nitem3", result);
    }

    @Test
    @DisplayName("paginateList should return all items with offset 0 and large limit")
    void testPaginateListAllItems() {
        List<String> items = Arrays.asList("item1", "item2", "item3");
        String result = PluginUtils.paginateList(items, 0, 100);

        assertEquals("item1\nitem2\nitem3", result);
    }

    @Test
    @DisplayName("paginateList should handle empty list")
    void testPaginateListEmptyList() {
        List<String> items = Arrays.asList();
        String result = PluginUtils.paginateList(items, 0, 10);

        assertEquals("", result);
    }

    @Test
    @DisplayName("parseIntOrDefault should parse valid integer string")
    void testParseIntOrDefaultValidInt() {
        int result = PluginUtils.parseIntOrDefault("42", 0);

        assertEquals(42, result);
    }

    @Test
    @DisplayName("parseIntOrDefault should return default for invalid string")
    void testParseIntOrDefaultInvalidString() {
        int result = PluginUtils.parseIntOrDefault("not-a-number", 99);

        assertEquals(99, result);
    }

    @Test
    @DisplayName("parseIntOrDefault should return default for null")
    void testParseIntOrDefaultNull() {
        int result = PluginUtils.parseIntOrDefault(null, 42);

        assertEquals(42, result);
    }

    @Test
    @DisplayName("parseIntOrDefault should parse negative integers")
    void testParseIntOrDefaultNegative() {
        int result = PluginUtils.parseIntOrDefault("-123", 0);

        assertEquals(-123, result);
    }

    @Test
    @DisplayName("parseDoubleOrDefault should parse valid double string")
    void testParseDoubleOrDefaultValidDouble() {
        double result = PluginUtils.parseDoubleOrDefault("3.14", "0.0");

        assertEquals(3.14, result, 0.001);
    }

    @Test
    @DisplayName("parseDoubleOrDefault should use default for invalid string")
    void testParseDoubleOrDefaultInvalidString() {
        double result = PluginUtils.parseDoubleOrDefault("invalid", "2.71");

        assertEquals(2.71, result, 0.001);
    }

    @Test
    @DisplayName("parseDoubleOrDefault should handle null value")
    void testParseDoubleOrDefaultNull() {
        double result = PluginUtils.parseDoubleOrDefault(null, "1.5");

        assertEquals(1.5, result, 0.001);
    }

    @Test
    @DisplayName("parseDoubleOrDefault should return 0.0 when both value and default are invalid")
    void testParseDoubleOrDefaultBothInvalid() {
        double result = PluginUtils.parseDoubleOrDefault("invalid", "also-invalid");

        assertEquals(0.0, result, 0.001);
    }

    @Test
    @DisplayName("escapeNonAscii should preserve ASCII characters")
    void testEscapeNonAsciiPreservesAscii() {
        String result = PluginUtils.escapeNonAscii("Hello World!");

        assertEquals("Hello World!", result);
    }

    @Test
    @DisplayName("escapeNonAscii should escape non-ASCII characters")
    void testEscapeNonAsciiEscapesNonAscii() {
        String result = PluginUtils.escapeNonAscii("Hello\u00A9");

        assertTrue(result.contains("\\x"));
    }

    @Test
    @DisplayName("escapeNonAscii should handle null input")
    void testEscapeNonAsciiNull() {
        String result = PluginUtils.escapeNonAscii(null);

        assertEquals("", result);
    }

    @Test
    @DisplayName("escapeNonAscii should handle empty string")
    void testEscapeNonAsciiEmpty() {
        String result = PluginUtils.escapeNonAscii("");

        assertEquals("", result);
    }

    @Test
    @DisplayName("escapeJson should escape double quotes")
    void testEscapeJsonDoubleQuotes() {
        String result = PluginUtils.escapeJson("He said \"Hello\"");

        assertEquals("He said \\\"Hello\\\"", result);
    }

    @Test
    @DisplayName("escapeJson should escape backslashes")
    void testEscapeJsonBackslashes() {
        String result = PluginUtils.escapeJson("C:\\Windows\\System32");

        assertEquals("C:\\\\Windows\\\\System32", result);
    }

    @Test
    @DisplayName("escapeJson should escape newlines")
    void testEscapeJsonNewlines() {
        String result = PluginUtils.escapeJson("Line1\nLine2");

        assertEquals("Line1\\nLine2", result);
    }

    @Test
    @DisplayName("escapeJson should escape tabs")
    void testEscapeJsonTabs() {
        String result = PluginUtils.escapeJson("Column1\tColumn2");

        assertEquals("Column1\\tColumn2", result);
    }

    @Test
    @DisplayName("escapeJson should handle null input")
    void testEscapeJsonNull() {
        String result = PluginUtils.escapeJson(null);

        assertEquals("", result);
    }

    @Test
    @DisplayName("escapeJson should escape special characters")
    void testEscapeJsonSpecialChars() {
        String result = PluginUtils.escapeJson("\b\f\r");

        assertTrue(result.contains("\\b"));
        assertTrue(result.contains("\\f"));
        assertTrue(result.contains("\\r"));
    }

    @Test
    @DisplayName("escapeJson should handle Unicode characters")
    void testEscapeJsonUnicode() {
        String result = PluginUtils.escapeJson("emoji: \u263A");

        assertTrue(result.contains("\\u"));
    }

    @Test
    @DisplayName("getParamFlexible should return camelCase value when present")
    void testGetParamFlexibleCamelCase() {
        Map<String, String> params = new HashMap<>();
        params.put("newName", "value1");

        String result = PluginUtils.getParamFlexible(params, "newName", "new_name");

        assertEquals("value1", result);
    }

    @Test
    @DisplayName("getParamFlexible should return snake_case value when camelCase not present")
    void testGetParamFlexibleSnakeCase() {
        Map<String, String> params = new HashMap<>();
        params.put("new_name", "value2");

        String result = PluginUtils.getParamFlexible(params, "newName", "new_name");

        assertEquals("value2", result);
    }

    @Test
    @DisplayName("getParamFlexible should prefer camelCase over snake_case when both present")
    void testGetParamFlexibleBothPresent() {
        Map<String, String> params = new HashMap<>();
        params.put("newName", "camelValue");
        params.put("new_name", "snakeValue");

        String result = PluginUtils.getParamFlexible(params, "newName", "new_name");

        assertEquals("camelValue", result);
    }

    @Test
    @DisplayName("getParamFlexible should return null when neither variant present")
    void testGetParamFlexibleNeitherPresent() {
        Map<String, String> params = new HashMap<>();

        String result = PluginUtils.getParamFlexible(params, "newName", "new_name");

        assertNull(result);
    }

    @Test
    @DisplayName("getParamFlexible should handle empty map")
    void testGetParamFlexibleEmptyMap() {
        Map<String, String> params = new HashMap<>();

        String result = PluginUtils.getParamFlexible(params, "anyParam", "any_param");

        assertNull(result);
    }
}
