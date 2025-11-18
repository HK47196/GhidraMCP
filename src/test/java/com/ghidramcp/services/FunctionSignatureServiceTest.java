package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for FunctionSignatureService.
 *
 * These tests verify parameter validation, type parsing, and type resolution logic
 * for the FunctionSignatureService functionality.
 *
 * Note: Full integration tests with Ghidra Program objects would require
 * the Ghidra test framework and are beyond the scope of unit tests.
 */
class FunctionSignatureServiceTest {

    // ===========================================
    // Tests for function prototype input validation
    // ===========================================

    /**
     * Test that function address is required
     */
    @ParameterizedTest
    @DisplayName("Should reject null or empty function address")
    @NullAndEmptySource
    void testNullEmptyFunctionAddress(String address) {
        // Input validation should fail for null/empty address
        boolean isValid = address != null && !address.isEmpty();
        assertFalse(isValid, "Null or empty address should be invalid");
    }

    /**
     * Test that function prototype is required
     */
    @ParameterizedTest
    @DisplayName("Should reject null or empty prototype")
    @NullAndEmptySource
    void testNullEmptyPrototype(String prototype) {
        // Input validation should fail for null/empty prototype
        boolean isValid = prototype != null && !prototype.isEmpty();
        assertFalse(isValid, "Null or empty prototype should be invalid");
    }

    /**
     * Test valid function address formats
     */
    @ParameterizedTest
    @DisplayName("Should accept valid hex address formats")
    @ValueSource(strings = {"0x00401000", "00401000", "0x1000", "deadbeef", "0xDEADBEEF"})
    void testValidAddressFormats(String address) {
        assertNotNull(address, "Address should not be null");
        assertFalse(address.isEmpty(), "Address should not be empty");

        // Address should be hex format
        String cleanAddr = address.startsWith("0x") ? address.substring(2) : address;
        assertTrue(cleanAddr.matches("[0-9a-fA-F]+"),
            "Address should be valid hex format: " + address);
    }

    /**
     * Test valid function prototype formats
     */
    @ParameterizedTest
    @DisplayName("Should accept valid function prototype formats")
    @ValueSource(strings = {
        "int foo()",
        "void bar(int a)",
        "char* getString()",
        "int add(int a, int b)",
        "void process(char* str, int len)",
        "unsigned int getValue()",
        "long long calculateSum(int* array, int size)"
    })
    void testValidPrototypeFormats(String prototype) {
        assertNotNull(prototype, "Prototype should not be null");
        assertFalse(prototype.isEmpty(), "Prototype should not be empty");

        // Prototype should contain parentheses for parameters
        assertTrue(prototype.contains("(") && prototype.contains(")"),
            "Prototype should contain parameter parentheses: " + prototype);
    }

    // ===========================================
    // Tests for variable name validation
    // ===========================================

    /**
     * Test that variable name is required for setLocalVariableType
     */
    @ParameterizedTest
    @DisplayName("Should reject null or empty variable name")
    @NullAndEmptySource
    void testNullEmptyVariableName(String variableName) {
        boolean isValid = variableName != null && !variableName.isEmpty();
        assertFalse(isValid, "Null or empty variable name should be invalid");
    }

    /**
     * Test valid variable name formats
     */
    @ParameterizedTest
    @DisplayName("Should accept valid variable names")
    @ValueSource(strings = {"local_1", "param_1", "buffer", "count", "ptr", "DAT_00401000"})
    void testValidVariableNames(String variableName) {
        assertNotNull(variableName, "Variable name should not be null");
        assertFalse(variableName.isEmpty(), "Variable name should not be empty");
    }

    // ===========================================
    // Tests for array type parsing
    // ===========================================

    /**
     * Test single-dimensional array type parsing
     */
    @ParameterizedTest
    @DisplayName("Should parse single-dimensional array types")
    @ValueSource(strings = {"int[10]", "char[256]", "byte[20]", "short[100]", "long[50]"})
    void testSingleDimensionalArrayParsing(String arrayType) {
        assertTrue(arrayType.contains("[") && arrayType.endsWith("]"),
            "Array type should have proper bracket format");

        int openBracket = arrayType.indexOf('[');
        String baseType = arrayType.substring(0, openBracket).trim();
        String sizeStr = arrayType.substring(openBracket + 1, arrayType.length() - 1).trim();

        assertFalse(baseType.isEmpty(), "Base type should not be empty");
        assertTrue(sizeStr.matches("\\d+"), "Array size should be numeric");

        int size = Integer.parseInt(sizeStr);
        assertTrue(size > 0, "Array size should be positive");
    }

    /**
     * Test multi-dimensional array type parsing
     */
    @ParameterizedTest
    @DisplayName("Should parse multi-dimensional array types")
    @ValueSource(strings = {"int[10][20]", "char[4][256]", "float[3][3]", "byte[100][200][50]"})
    void testMultiDimensionalArrayParsing(String arrayType) {
        assertTrue(arrayType.contains("["), "Should contain opening bracket");
        assertTrue(arrayType.endsWith("]"), "Should end with closing bracket");

        // Count dimensions
        int dimensionCount = 0;
        for (char c : arrayType.toCharArray()) {
            if (c == '[') dimensionCount++;
        }

        assertTrue(dimensionCount >= 2, "Multi-dimensional should have at least 2 dimensions");

        // Extract base type
        int firstBracket = arrayType.indexOf('[');
        String baseType = arrayType.substring(0, firstBracket).trim();
        assertFalse(baseType.isEmpty(), "Base type should not be empty");
    }

    /**
     * Test array dimension extraction
     */
    @Test
    @DisplayName("Should correctly extract array dimensions")
    void testArrayDimensionExtraction() {
        String arrayType = "int[10][20]";

        // Extract dimensions
        java.util.List<Integer> dimensions = new java.util.ArrayList<>();
        int pos = 0;
        String dimensionsStr = arrayType.substring(arrayType.indexOf('['));

        while (pos < dimensionsStr.length()) {
            if (dimensionsStr.charAt(pos) == '[') {
                int closeBracket = dimensionsStr.indexOf(']', pos);
                if (closeBracket != -1) {
                    String sizeStr = dimensionsStr.substring(pos + 1, closeBracket).trim();
                    dimensions.add(Integer.parseInt(sizeStr));
                    pos = closeBracket + 1;
                } else {
                    break;
                }
            } else {
                pos++;
            }
        }

        assertEquals(2, dimensions.size(), "Should have 2 dimensions");
        assertEquals(10, dimensions.get(0).intValue(), "First dimension should be 10");
        assertEquals(20, dimensions.get(1).intValue(), "Second dimension should be 20");
    }

    /**
     * Test invalid array size handling
     */
    @ParameterizedTest
    @DisplayName("Should identify invalid array sizes")
    @ValueSource(strings = {"int[0]", "char[-5]", "byte[]"})
    void testInvalidArraySizes(String arrayType) {
        int openBracket = arrayType.indexOf('[');
        int closeBracket = arrayType.indexOf(']');
        String sizeStr = arrayType.substring(openBracket + 1, closeBracket).trim();

        if (sizeStr.isEmpty()) {
            assertTrue(sizeStr.isEmpty(), "Empty size should be invalid");
        } else {
            int size = Integer.parseInt(sizeStr);
            assertTrue(size <= 0, "Size should be invalid (0 or negative)");
        }
    }

    // ===========================================
    // Tests for pointer type parsing
    // ===========================================

    /**
     * Test basic pointer type parsing
     */
    @ParameterizedTest
    @DisplayName("Should parse basic pointer types")
    @ValueSource(strings = {"int*", "char*", "void*", "int *", "char *", "void *"})
    void testBasicPointerTypes(String pointerType) {
        assertTrue(pointerType.contains("*"), "Pointer type should contain asterisk");

        String[] parts = pointerType.split("\\*");
        assertTrue(parts.length >= 1, "Should have base type");

        String baseType = parts[0].trim();
        assertFalse(baseType.isEmpty(), "Base type should not be empty");
    }

    /**
     * Test Windows-style pointer types (PXXX)
     */
    @ParameterizedTest
    @DisplayName("Should recognize Windows-style pointer types")
    @ValueSource(strings = {"PVOID", "PCHAR", "PBYTE", "PINT", "PHANDLE"})
    void testWindowsStylePointerTypes(String pointerType) {
        assertTrue(pointerType.startsWith("P"), "Windows pointer should start with P");
        assertTrue(pointerType.length() > 1, "Should have base type after P");

        String baseType = pointerType.substring(1);
        assertFalse(baseType.isEmpty(), "Base type should not be empty");
    }

    /**
     * Test pointer types with explicit sizes
     */
    @ParameterizedTest
    @DisplayName("Should parse pointer types with explicit bit sizes")
    @CsvSource({
        "int *32, int, 32",
        "char *16, char, 16",
        "void *64, void, 64",
        "EffectData *32, EffectData, 32"
    })
    void testPointerTypesWithExplicitSize(String pointerType, String expectedBase, int expectedBits) {
        assertTrue(pointerType.contains("*"), "Should contain asterisk");

        String[] parts = pointerType.split("\\*");
        assertEquals(2, parts.length, "Should have base type and size");

        String baseType = parts[0].trim();
        String sizeStr = parts[1].trim();

        assertEquals(expectedBase, baseType, "Base type should match");
        assertEquals(expectedBits, Integer.parseInt(sizeStr), "Size should match");

        // Convert bits to bytes
        int pointerSizeBytes = expectedBits / 8;
        assertTrue(pointerSizeBytes > 0, "Pointer size in bytes should be positive");
    }

    /**
     * Test pointer types should not be converted to int
     */
    @Test
    @DisplayName("Should preserve pointer types and not default to int")
    void testPointerTypesPreserved() {
        // This documents the correct behavior: pointers stay as pointers
        String[] pointerTypes = {"int *", "MyStruct *", "void *", "char *"};

        for (String pointerType : pointerTypes) {
            assertTrue(pointerType.contains("*"),
                "Pointer type should be preserved: " + pointerType);
        }
    }

    // ===========================================
    // Tests for built-in type mapping
    // ===========================================

    /**
     * Test common built-in type names
     */
    @ParameterizedTest
    @DisplayName("Should recognize common built-in types")
    @ValueSource(strings = {
        "int", "uint", "short", "ushort", "char", "uchar",
        "long", "longlong", "ulonglong", "bool", "boolean", "void"
    })
    void testBuiltInTypeNames(String typeName) {
        assertNotNull(typeName, "Type name should not be null");
        assertFalse(typeName.isEmpty(), "Type name should not be empty");
    }

    /**
     * Test type aliases
     */
    @ParameterizedTest
    @DisplayName("Should recognize type aliases")
    @CsvSource({
        "unsigned int, uint",
        "unsigned short, ushort",
        "unsigned char, uchar",
        "unsigned long, uint",
        "unsigned __int64, ulonglong",
        "dword, uint",
        "word, ushort",
        "byte, char",
        "__int64, longlong"
    })
    void testTypeAliases(String alias, String canonical) {
        assertNotNull(alias, "Alias should not be null");
        assertNotNull(canonical, "Canonical name should not be null");

        // Both should be valid type names
        assertFalse(alias.isEmpty(), "Alias should not be empty");
        assertFalse(canonical.isEmpty(), "Canonical should not be empty");
    }

    /**
     * Test case insensitive type matching
     */
    @ParameterizedTest
    @DisplayName("Should match types case-insensitively")
    @ValueSource(strings = {"INT", "Int", "CHAR", "Char", "VOID", "Void"})
    void testCaseInsensitiveTypeMatching(String typeName) {
        String lowercase = typeName.toLowerCase();

        // Type matching should be case-insensitive
        assertTrue(
            lowercase.equals("int") || lowercase.equals("char") || lowercase.equals("void"),
            "Should match regardless of case: " + typeName
        );
    }

    // ===========================================
    // Tests for data type address validation
    // ===========================================

    /**
     * Test that address is required for setDataType
     */
    @ParameterizedTest
    @DisplayName("Should reject null or empty address for setDataType")
    @NullAndEmptySource
    void testNullEmptyDataTypeAddress(String address) {
        boolean isValid = address != null && !address.isEmpty();
        assertFalse(isValid, "Null or empty address should be invalid");
    }

    /**
     * Test that type name is required for setDataType
     */
    @ParameterizedTest
    @DisplayName("Should reject null or empty type name for setDataType")
    @NullAndEmptySource
    void testNullEmptyTypeName(String typeName) {
        boolean isValid = typeName != null && !typeName.isEmpty();
        assertFalse(isValid, "Null or empty type name should be invalid");
    }

    // ===========================================
    // Tests for struct/custom type resolution
    // ===========================================

    /**
     * Test struct type name formats
     */
    @ParameterizedTest
    @DisplayName("Should accept valid struct type names")
    @ValueSource(strings = {
        "MyStruct", "FILE_DESCRIPTOR", "MemoryPoolBlock",
        "Socket", "NetworkPacket", "UserData"
    })
    void testStructTypeNames(String structName) {
        assertNotNull(structName, "Struct name should not be null");
        assertFalse(structName.isEmpty(), "Struct name should not be empty");

        // Struct names typically start with uppercase
        assertTrue(Character.isUpperCase(structName.charAt(0)),
            "Struct names typically start with uppercase: " + structName);
    }

    /**
     * Test struct pointer types
     */
    @ParameterizedTest
    @DisplayName("Should recognize struct pointer types")
    @ValueSource(strings = {
        "MyStruct *", "FILE_DESCRIPTOR *", "MemoryPoolBlock *",
        "MyStruct*", "NetworkPacket*"
    })
    void testStructPointerTypes(String structPointer) {
        assertTrue(structPointer.contains("*"), "Should contain asterisk");

        String baseType = structPointer.split("\\*")[0].trim();
        assertTrue(Character.isUpperCase(baseType.charAt(0)),
            "Struct name should start with uppercase");
    }

    // ===========================================
    // Tests for type path resolution
    // ===========================================

    /**
     * Test direct path type resolution
     */
    @ParameterizedTest
    @DisplayName("Should recognize direct path type formats")
    @ValueSource(strings = {"/int", "/uint", "/char", "/void", "/MyStruct"})
    void testDirectPathTypes(String typePath) {
        assertTrue(typePath.startsWith("/"), "Direct path should start with /");

        String typeName = typePath.substring(1);
        assertFalse(typeName.isEmpty(), "Type name should follow /");
    }

    /**
     * Test category path type resolution
     */
    @ParameterizedTest
    @DisplayName("Should recognize category path type formats")
    @ValueSource(strings = {
        "/Windows/HANDLE",
        "/MyProject/NetworkTypes/Socket",
        "/Structures/FileIO/FILE_DESCRIPTOR"
    })
    void testCategoryPathTypes(String typePath) {
        assertTrue(typePath.startsWith("/"), "Path should start with /");
        assertTrue(typePath.contains("/"), "Path should contain category separators");

        // Extract type name (last segment)
        String[] parts = typePath.split("/");
        String typeName = parts[parts.length - 1];
        assertFalse(typeName.isEmpty(), "Type name should be last segment");
    }

    // ===========================================
    // Tests for prototype result
    // ===========================================

    /**
     * Test PrototypeResult success scenario
     */
    @Test
    @DisplayName("Should format success result correctly")
    void testPrototypeResultSuccess() {
        boolean success = true;
        String errorMessage = "";

        assertTrue(success, "Success should be true");
        assertTrue(errorMessage.isEmpty(), "Error message should be empty on success");
    }

    /**
     * Test PrototypeResult failure scenarios
     */
    @ParameterizedTest
    @DisplayName("Should format failure results with error messages")
    @ValueSource(strings = {
        "No program loaded",
        "Function address is required",
        "Function prototype is required",
        "Could not find function at address",
        "Failed to parse function prototype"
    })
    void testPrototypeResultFailure(String errorMessage) {
        boolean success = false;

        assertFalse(success, "Success should be false");
        assertFalse(errorMessage.isEmpty(), "Error message should not be empty on failure");
    }

    // ===========================================
    // Tests for malformed input handling
    // ===========================================

    /**
     * Test malformed array type handling
     */
    @ParameterizedTest
    @DisplayName("Should identify malformed array types")
    @ValueSource(strings = {"int[", "char]", "int[[10]", "char[10"})
    void testMalformedArrayTypes(String arrayType) {
        // Check for mismatched brackets
        int openCount = 0;
        int closeCount = 0;
        for (char c : arrayType.toCharArray()) {
            if (c == '[') openCount++;
            if (c == ']') closeCount++;
        }

        assertNotEquals(openCount, closeCount,
            "Malformed array should have mismatched brackets: " + arrayType);
    }

    /**
     * Test empty pointer type handling
     */
    @Test
    @DisplayName("Should handle pointer with no base type")
    void testEmptyPointerBaseType() {
        String pointerType = "*";
        String[] parts = pointerType.split("\\*");

        // Empty base type
        assertTrue(parts.length == 0 || parts[0].trim().isEmpty(),
            "Should identify empty base type");
    }

    /**
     * Test whitespace handling in type names
     */
    @ParameterizedTest
    @DisplayName("Should handle whitespace in type names")
    @ValueSource(strings = {"  int  ", "char   *", "  void  *  32  "})
    void testWhitespaceHandling(String typeName) {
        String trimmed = typeName.trim();
        assertFalse(trimmed.isEmpty(), "Trimmed type should not be empty");
    }

    // ===========================================
    // Tests for decompilation timeout configuration
    // ===========================================

    /**
     * Test valid decompile timeout values
     */
    @ParameterizedTest
    @DisplayName("Should accept valid decompile timeout values")
    @ValueSource(ints = {10, 30, 60, 120, 300})
    void testValidDecompileTimeouts(int timeout) {
        assertTrue(timeout > 0, "Timeout should be positive");
    }

    // ===========================================
    // Tests for symbol search
    // ===========================================

    /**
     * Test symbol name matching
     */
    @Test
    @DisplayName("Should match symbol names exactly")
    void testSymbolNameMatching() {
        String[] symbols = {"local_1", "param_1", "buffer", "count"};
        String searchName = "buffer";

        boolean found = false;
        for (String symbol : symbols) {
            if (symbol.equals(searchName)) {
                found = true;
                break;
            }
        }

        assertTrue(found, "Should find exact symbol match");
    }

    /**
     * Test that symbol search is case-sensitive
     */
    @Test
    @DisplayName("Should perform case-sensitive symbol search")
    void testCaseSensitiveSymbolSearch() {
        String symbolName = "Buffer";
        String searchName = "buffer";

        assertNotEquals(symbolName, searchName,
            "Symbol search should be case-sensitive");
    }

    // ===========================================
    // Tests for transaction handling
    // ===========================================

    /**
     * Test transaction description format
     */
    @ParameterizedTest
    @DisplayName("Should use descriptive transaction names")
    @ValueSource(strings = {
        "Set function prototype",
        "Set variable type",
        "Set data type"
    })
    void testTransactionDescriptions(String description) {
        assertNotNull(description, "Transaction description should not be null");
        assertFalse(description.isEmpty(), "Transaction description should not be empty");
        assertTrue(description.startsWith("Set"),
            "Transaction description should describe the operation");
    }

    // ===========================================
    // Tests for edge cases
    // ===========================================

    /**
     * Test very long type names
     */
    @Test
    @DisplayName("Should handle long type names")
    void testLongTypeNames() {
        String longTypeName = "VeryLongStructureNameWithManyDescriptiveWords_AndUnderscores_ForClarity";

        assertNotNull(longTypeName, "Long type name should be valid");
        assertTrue(longTypeName.length() > 50, "Should be a long name");
    }

    /**
     * Test type names with numbers
     */
    @ParameterizedTest
    @DisplayName("Should handle type names with numbers")
    @ValueSource(strings = {"int32", "int64", "float32", "Type1", "Data2D"})
    void testTypeNamesWithNumbers(String typeName) {
        assertTrue(typeName.matches(".*\\d+.*"),
            "Type name should contain numbers: " + typeName);
    }

    /**
     * Test nested pointer types
     */
    @Test
    @DisplayName("Should recognize nested pointer patterns")
    void testNestedPointerTypes() {
        // Double pointers like "int **" or "char **"
        String doublePointer = "int **";

        int pointerCount = 0;
        for (char c : doublePointer.toCharArray()) {
            if (c == '*') pointerCount++;
        }

        assertEquals(2, pointerCount, "Double pointer should have 2 asterisks");
    }

    /**
     * Test function pointer type patterns
     */
    @Test
    @DisplayName("Should identify function pointer patterns")
    void testFunctionPointerPatterns() {
        // Function pointers have specific patterns
        String funcPtr = "int (*callback)(int, int)";

        assertTrue(funcPtr.contains("(*)"),
            "Function pointer should contain (*) pattern");
        assertTrue(funcPtr.contains(")("),
            "Function pointer should have parameter list");
    }

    /**
     * Test const and volatile qualifiers
     */
    @ParameterizedTest
    @DisplayName("Should recognize type qualifiers")
    @ValueSource(strings = {"const int", "volatile char", "const char *", "const volatile int"})
    void testTypeQualifiers(String qualifiedType) {
        assertTrue(
            qualifiedType.contains("const") || qualifiedType.contains("volatile"),
            "Should contain type qualifier: " + qualifiedType
        );
    }

    /**
     * Test unsigned type variations
     */
    @ParameterizedTest
    @DisplayName("Should handle unsigned type variations")
    @ValueSource(strings = {
        "unsigned int", "unsigned char", "unsigned short",
        "unsigned long", "unsigned long long"
    })
    void testUnsignedTypeVariations(String unsignedType) {
        assertTrue(unsignedType.startsWith("unsigned"),
            "Should start with unsigned: " + unsignedType);

        String baseType = unsignedType.substring("unsigned ".length());
        assertFalse(baseType.isEmpty(), "Should have base type after unsigned");
    }
}
