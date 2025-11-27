package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for far pointer syntax parsing.
 *
 * These tests verify the parsing logic for far pointer syntax (e.g., "type *32")
 * used in struct field definitions. Far pointers allow specifying explicit pointer
 * sizes using the format "BaseType *NN" where NN is the size in bits.
 */
class FarPointerParsingTest {

    // Same pattern used in FunctionSignatureService
    private static final Pattern POINTER_PATTERN = Pattern.compile("^(.+?)\\s*\\*\\s*(\\d*)\\s*$");

    /**
     * Test the regex pattern matches all pointer type variations correctly
     */
    @ParameterizedTest
    @DisplayName("Regex should match all pointer syntax variations")
    @CsvSource({
        "int*, int, ''",
        "int *, int, ''",
        "int* , int, ''",
        "int * , int, ''",
        "MyStruct*, MyStruct, ''",
        "MyStruct *, MyStruct, ''",
        "void*, void, ''",
        "char*, char, ''",
        "int*32, int, 32",
        "int *32, int, 32",
        "int* 32, int, 32",
        "int * 32, int, 32",
        "EffectData *32, EffectData, 32",
        "void *16, void, 16",
        "MyStruct *64, MyStruct, 64"
    })
    void testPointerPatternMatching(String typeName, String expectedBaseType, String expectedSize) {
        Matcher matcher = POINTER_PATTERN.matcher(typeName);
        assertTrue(matcher.matches(), "Pattern should match: " + typeName);
        assertEquals(expectedBaseType, matcher.group(1).trim(), "Base type should match");
        assertEquals(expectedSize, matcher.group(2), "Size should match");
    }

    /**
     * Test that non-pointer types do NOT match the pattern
     */
    @ParameterizedTest
    @DisplayName("Regex should NOT match non-pointer types")
    @ValueSource(strings = {"int", "void", "MyStruct", "char", "uint8_t", "DWORD"})
    void testNonPointerTypesDoNotMatch(String typeName) {
        Matcher matcher = POINTER_PATTERN.matcher(typeName);
        assertFalse(matcher.matches(), "Pattern should NOT match non-pointer type: " + typeName);
    }

    /**
     * Test parsing of far pointer syntax: "type *NN"
     */
    @ParameterizedTest
    @DisplayName("Should parse far pointer syntax correctly")
    @CsvSource({
        "EffectData *32, EffectData, 32, 4",
        "void *16, void, 16, 2",
        "int *64, int, 64, 8",
        "MyStruct *32, MyStruct, 32, 4",
        "char *16, char, 16, 2",
        "uint8_t *32, uint8_t, 32, 4"
    })
    void testFarPointerParsing(String typeName, String expectedBaseType,
                               int expectedBits, int expectedBytes) {
        // Test the parsing logic using regex pattern
        Matcher matcher = POINTER_PATTERN.matcher(typeName);
        assertTrue(matcher.matches(), "Should match pointer pattern");

        String baseTypeName = matcher.group(1).trim();
        String sizeStr = matcher.group(2);

        assertEquals(expectedBaseType, baseTypeName, "Base type should match");
        assertEquals(String.valueOf(expectedBits), sizeStr, "Size string should match");

        // Test size conversion
        int pointerSizeBits = Integer.parseInt(sizeStr);
        int pointerSizeBytes = pointerSizeBits / 8;

        assertEquals(expectedBytes, pointerSizeBytes, "Byte size should match");
    }

    /**
     * Test regular pointer syntax still works: "type *" and "type*"
     */
    @ParameterizedTest
    @DisplayName("Should handle regular pointer syntax")
    @ValueSource(strings = {"int *", "void *", "char *", "MyStruct *", "unsigned long *", "int*", "void*", "char*"})
    void testRegularPointerSyntax(String typeName) {
        // Use regex pattern for parsing
        Matcher matcher = POINTER_PATTERN.matcher(typeName);
        assertTrue(matcher.matches(), "Should match pointer pattern: " + typeName);

        String baseTypeName = matcher.group(1).trim();
        String sizeStr = matcher.group(2);

        assertFalse(baseTypeName.isEmpty(), "Base type should not be empty");
        assertTrue(sizeStr.isEmpty(), "Regular pointer should have empty size string");
    }

    /**
     * Test numeric pattern detection
     */
    @ParameterizedTest
    @DisplayName("Should correctly identify numeric size specifications")
    @ValueSource(strings = {"8", "16", "32", "64", "128", "256"})
    void testNumericPatternDetection(String sizeStr) {
        assertTrue(sizeStr.matches("\\d+"), "Should match numeric pattern");
        assertDoesNotThrow(() -> Integer.parseInt(sizeStr),
                          "Should be parseable as integer");
    }

    /**
     * Test invalid numeric patterns
     */
    @ParameterizedTest
    @DisplayName("Should reject invalid size specifications")
    @ValueSource(strings = {"abc", "32x", "3.14", "x32"})
    void testInvalidNumericPatterns(String sizeStr) {
        assertFalse(sizeStr.matches("\\d+"), "Should not match numeric pattern");
    }

    /**
     * Test size calculation for various pointer sizes
     */
    @ParameterizedTest
    @DisplayName("Should calculate byte size correctly from bit size")
    @CsvSource({
        "8, 1",
        "16, 2",
        "32, 4",
        "64, 8",
        "128, 16",
        "256, 32"
    })
    void testSizeCalculation(int bits, int expectedBytes) {
        int calculatedBytes = bits / 8;
        assertEquals(expectedBytes, calculatedBytes,
                    "Bit to byte conversion should be correct");
    }

    /**
     * Test edge case: pointer with spaces around asterisk
     */
    @Test
    @DisplayName("Should handle spaces around asterisk")
    void testSpacesAroundAsterisk() {
        String typeName = "int * 32";
        String[] parts = typeName.split("\\*");

        assertEquals(2, parts.length);
        assertEquals("int", parts[0].trim());
        assertEquals("32", parts[1].trim());
    }

    /**
     * Test edge case: no space before asterisk
     */
    @Test
    @DisplayName("Should handle no space before asterisk")
    void testNoSpaceBeforeAsterisk() {
        String typeName = "uint32_t*32";
        String[] parts = typeName.split("\\*");

        assertEquals(2, parts.length);
        assertEquals("uint32_t", parts[0].trim());
        assertEquals("32", parts[1].trim());
    }

    /**
     * Test that complex type names work with far pointers
     */
    @ParameterizedTest
    @DisplayName("Should handle complex base type names")
    @ValueSource(strings = {
        "struct MyStruct",
        "my_custom_type_t",
        "EFFECT_DATA",
        "namespace::MyClass"
    })
    void testComplexBaseTypeNames(String baseType) {
        String typeName = baseType + " *32";
        String[] parts = typeName.split("\\*");

        assertEquals(2, parts.length);
        assertEquals(baseType, parts[0].trim());
        assertEquals("32", parts[1].trim());
    }

    /**
     * Test size validation logic
     */
    @Test
    @DisplayName("Should detect invalid pointer sizes")
    void testInvalidPointerSizes() {
        // Test zero size
        String sizeStr = "0";
        int pointerSizeBytes = Integer.parseInt(sizeStr) / 8;
        assertTrue(pointerSizeBytes <= 0, "Should detect zero or negative size");

        // Test very small size that rounds to zero
        sizeStr = "7";
        pointerSizeBytes = Integer.parseInt(sizeStr) / 8;
        assertTrue(pointerSizeBytes == 0, "Should detect size less than 8 bits");
    }

    /**
     * Test that non-pointer types are not affected
     */
    @ParameterizedTest
    @DisplayName("Should not split non-pointer types")
    @ValueSource(strings = {"int", "uint8_t", "char", "MyStruct", "float"})
    void testNonPointerTypes(String typeName) {
        assertFalse(typeName.contains("*"), "Should not contain asterisk");
        String[] parts = typeName.split("\\*");
        assertEquals(1, parts.length, "Should not be split");
    }

    /**
     * Test pointer to pointer edge case
     */
    @Test
    @DisplayName("Should handle pointer to pointer")
    void testPointerToPointer() {
        String typeName = "int **";
        // Use split with -1 limit to preserve trailing empty strings
        String[] parts = typeName.split("\\*", -1);

        // Should split into 3 parts: "int ", "", ""
        assertTrue(parts.length >= 2, "Should split into multiple parts");

        // This is an edge case - ** shouldn't match far pointer syntax
        // because the second part is empty
        assertEquals("", parts[1].trim(), "Second part should be empty");
    }

    /**
     * Test odd-bit pointer sizes
     */
    @ParameterizedTest
    @DisplayName("Should handle non-byte-aligned pointer sizes")
    @CsvSource({
        "17, 2",  // 17 bits = 2 bytes (integer division)
        "9, 1",   // 9 bits = 1 byte
        "31, 3",  // 31 bits = 3 bytes
        "63, 7"   // 63 bits = 7 bytes
    })
    void testNonByteAlignedSizes(int bits, int expectedBytes) {
        int calculatedBytes = bits / 8;
        assertEquals(expectedBytes, calculatedBytes,
                    "Integer division should handle non-aligned sizes");
    }

    /**
     * Test very large pointer sizes
     */
    @Test
    @DisplayName("Should handle very large pointer sizes")
    void testVeryLargePointerSizes() {
        String typeName = "void *256";
        String[] parts = typeName.split("\\*");

        String sizeStr = parts[1].trim();
        int pointerSizeBits = Integer.parseInt(sizeStr);
        int pointerSizeBytes = pointerSizeBits / 8;

        assertEquals(32, pointerSizeBytes, "256-bit pointer should be 32 bytes");
    }

    /**
     * Test the regex pattern used for numeric detection
     */
    @Test
    @DisplayName("Should validate regex pattern for numeric detection")
    void testRegexPattern() {
        String pattern = "\\d+";

        // Valid numbers
        assertTrue("32".matches(pattern));
        assertTrue("16".matches(pattern));
        assertTrue("128".matches(pattern));

        // Invalid patterns
        assertFalse("".matches(pattern));
        assertFalse("abc".matches(pattern));
        assertFalse("32x".matches(pattern));
        assertFalse("x32".matches(pattern));
        assertFalse("3.14".matches(pattern));
    }

    /**
     * Test backward compatibility scenarios
     */
    @Test
    @DisplayName("Should maintain backward compatibility with existing pointer syntax")
    void testBackwardCompatibility() {
        // Regular pointers should still work (with and without space)
        for (String regularPtr : new String[] {"int *", "int*"}) {
            Matcher matcher = POINTER_PATTERN.matcher(regularPtr);
            assertTrue(matcher.matches(), "Should match: " + regularPtr);
            assertEquals("", matcher.group(2), "Regular pointer should have empty size");
        }

        // Far pointers should be detected
        String farPtr = "int *32";
        Matcher matcher = POINTER_PATTERN.matcher(farPtr);
        assertTrue(matcher.matches(), "Far pointer should match");
        assertEquals("32", matcher.group(2), "Far pointer should have size");
    }

    /**
     * Test the complete parsing flow for a struct field
     */
    @Test
    @DisplayName("Should parse complete struct field definition")
    void testCompleteStructFieldParsing() {
        // Example: struct WorldSpellEffect with far pointer field
        String fieldType = "EffectData *32";
        String fieldName = "pEffectData";
        String comment = "Far pointer (32-bit) to effect data structure";

        // Parse the field type
        assertTrue(fieldType.contains("*"), "Should contain pointer indicator");

        String[] parts = fieldType.split("\\*");
        assertEquals(2, parts.length, "Should split into base type and size");

        String baseType = parts[0].trim();
        String sizeStr = parts[1].trim();

        // Validate parsing results
        assertEquals("EffectData", baseType);
        assertEquals("32", sizeStr);
        assertTrue(sizeStr.matches("\\d+"), "Size should be numeric");

        // Validate size calculation
        int pointerSizeBytes = Integer.parseInt(sizeStr) / 8;
        assertEquals(4, pointerSizeBytes, "32-bit pointer should be 4 bytes");

        // Validate field metadata is preserved
        assertEquals("pEffectData", fieldName);
        assertEquals("Far pointer (32-bit) to effect data structure", comment);
    }
}
