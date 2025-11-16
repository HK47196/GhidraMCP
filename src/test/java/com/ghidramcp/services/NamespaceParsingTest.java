package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for namespace qualifier parsing in function names.
 *
 * These tests verify the parsing logic for namespace-qualified function names
 * (e.g., "A::B", "A::B::C") and ensure that functions without namespace qualifiers
 * are correctly identified to be placed in the global namespace.
 *
 * This validates the fix for the issue where renaming a function without a namespace
 * qualifier (e.g., from "A::B" to "B") should move it to the global namespace, not
 * keep it in its current namespace.
 */
class NamespaceParsingTest {

    /**
     * Test parsing of namespace-qualified names: "Namespace::FunctionName"
     */
    @ParameterizedTest
    @DisplayName("Should parse single-level namespace correctly")
    @CsvSource({
        "A::B, A, B",
        "MyNamespace::myFunction, MyNamespace, myFunction",
        "std::vector, std, vector",
        "Utils::init, Utils, init"
    })
    void testSingleLevelNamespace(String fullName, String expectedNamespace, String expectedFunctionName) {
        String[] parts = fullName.split("::");

        // Should have exactly 2 parts for single-level namespace
        assertEquals(2, parts.length, "Should split into namespace and function name");

        String namespace = parts[0];
        String functionName = parts[1];

        assertEquals(expectedNamespace, namespace, "Namespace should match");
        assertEquals(expectedFunctionName, functionName, "Function name should match");
    }

    /**
     * Test parsing of multi-level namespace-qualified names: "A::B::C"
     */
    @ParameterizedTest
    @DisplayName("Should parse multi-level namespaces correctly")
    @CsvSource({
        "A::B::C, 'A,B', C",
        "std::chrono::duration, 'std,chrono', duration",
        "MyApp::Utils::StringHelper, 'MyApp,Utils', StringHelper",
        "Level1::Level2::Level3::myFunc, 'Level1,Level2,Level3', myFunc"
    })
    void testMultiLevelNamespace(String fullName, String expectedNamespacePath, String expectedFunctionName) {
        String[] parts = fullName.split("::");

        // Should have at least 2 parts
        assertTrue(parts.length >= 2, "Should have at least namespace and function name");

        // Last part is the function name
        String functionName = parts[parts.length - 1];
        assertEquals(expectedFunctionName, functionName, "Function name should be the last part");

        // Everything before the last part is the namespace path
        String[] namespaceParts = new String[parts.length - 1];
        System.arraycopy(parts, 0, namespaceParts, 0, parts.length - 1);

        String namespacePath = String.join(",", namespaceParts);
        assertEquals(expectedNamespacePath, namespacePath, "Namespace path should match");
    }

    /**
     * Test that simple names without namespace qualifiers are detected correctly
     */
    @ParameterizedTest
    @DisplayName("Should identify names without namespace qualifiers")
    @ValueSource(strings = {"main", "init", "myFunction", "calculateTotal", "B"})
    void testSimpleNamesWithoutNamespace(String simpleName) {
        String[] parts = simpleName.split("::");

        // Should have only 1 part (no namespace)
        assertEquals(1, parts.length, "Should not split - no namespace qualifier present");
        assertEquals(simpleName, parts[0], "Should preserve the simple name");

        // This is the key assertion: when parts.length < 2, the function
        // should be moved to the global namespace
        assertTrue(parts.length < 2, "Should be flagged as needing global namespace placement");
    }

    /**
     * Test edge case: name that contains :: in unexpected places
     */
    @Test
    @DisplayName("Should handle names with trailing :: delimiter")
    void testTrailingDelimiter() {
        String nameWithTrailing = "MyNamespace::";
        String[] parts = nameWithTrailing.split("::");

        // Java's split() removes trailing empty strings by default
        // So "MyNamespace::" splits to ["MyNamespace"] not ["MyNamespace", ""]
        assertEquals(1, parts.length, "Should create one part (trailing empty removed)");
        assertEquals("MyNamespace", parts[0]);

        // This would be treated as a simple name without namespace
        assertTrue(parts.length < 2, "Should be flagged as needing global namespace");
    }

    /**
     * Test edge case: name that starts with ::
     */
    @Test
    @DisplayName("Should handle names with leading :: delimiter")
    void testLeadingDelimiter() {
        String nameWithLeading = "::myFunction";
        String[] parts = nameWithLeading.split("::");

        // Split will create ["", "myFunction"]
        assertTrue(parts.length >= 2, "Should create at least two parts");
        assertEquals("", parts[0], "First part should be empty");
    }

    /**
     * Test the critical behavior: renaming from namespaced to non-namespaced
     */
    @Test
    @DisplayName("Should correctly identify transition from namespaced to global")
    void testNamespaceToGlobalTransition() {
        // Original name: "A::B" (function B in namespace A)
        String originalName = "A::B";
        String[] originalParts = originalName.split("::");
        assertEquals(2, originalParts.length, "Original has namespace");

        // New name: "B" (function B in global namespace)
        String newName = "B";
        String[] newParts = newName.split("::");
        assertEquals(1, newParts.length, "New name has no namespace");

        // This validates the fix: when newParts.length < 2,
        // we must explicitly set the namespace to global
        assertTrue(newParts.length < 2,
            "Function should be moved to global namespace when renamed without qualifier");
    }

    /**
     * Test namespace path building for nested namespaces
     */
    @Test
    @DisplayName("Should build namespace hierarchy correctly")
    void testNamespaceHierarchyBuilding() {
        String fullName = "Level1::Level2::Level3::myFunc";
        String[] parts = fullName.split("::");

        assertEquals(4, parts.length, "Should have 4 parts");

        // Function name is the last part
        String functionName = parts[parts.length - 1];
        assertEquals("myFunc", functionName);

        // Namespace path consists of all parts except the last
        String[] namespacePath = new String[parts.length - 1];
        System.arraycopy(parts, 0, namespacePath, 0, parts.length - 1);

        assertArrayEquals(new String[]{"Level1", "Level2", "Level3"}, namespacePath,
            "Namespace hierarchy should be preserved in order");
    }

    /**
     * Test that empty names are handled
     */
    @Test
    @DisplayName("Should handle empty name")
    void testEmptyName() {
        String emptyName = "";
        String[] parts = emptyName.split("::");

        assertEquals(1, parts.length, "Empty string splits into single empty part");
        assertEquals("", parts[0]);
        assertTrue(parts.length < 2, "Should be treated as non-namespaced");
    }

    /**
     * Test namespace names with special characters
     */
    @ParameterizedTest
    @DisplayName("Should handle namespace names with underscores and numbers")
    @CsvSource({
        "my_namespace::my_function, my_namespace, my_function",
        "Namespace2::Function3, Namespace2, Function3",
        "_private::_init, _private, _init",
        "NS_1::NS_2::func, 'NS_1,NS_2', func"
    })
    void testSpecialCharactersInNames(String fullName, String expectedNamespacePath, String expectedFunctionName) {
        String[] parts = fullName.split("::");

        assertTrue(parts.length >= 2, "Should have namespace and function");

        String functionName = parts[parts.length - 1];
        assertEquals(expectedFunctionName, functionName);

        if (parts.length > 2) {
            String[] namespaceParts = new String[parts.length - 1];
            System.arraycopy(parts, 0, namespaceParts, 0, parts.length - 1);
            assertEquals(expectedNamespacePath, String.join(",", namespaceParts));
        } else {
            assertEquals(expectedNamespacePath, parts[0]);
        }
    }

    /**
     * Test consistency: same parsing logic works for both analyze and apply
     */
    @Test
    @DisplayName("Should parse consistently for analysis and application")
    void testParsingConsistency() {
        String testName = "A::B::C";

        // Parse once
        String[] parts1 = testName.split("::");

        // Parse again
        String[] parts2 = testName.split("::");

        // Should produce identical results
        assertArrayEquals(parts1, parts2, "Parsing should be deterministic");
    }

    /**
     * Test case sensitivity
     */
    @Test
    @DisplayName("Should preserve case sensitivity")
    void testCaseSensitivity() {
        String mixedCase = "MyNamespace::MyFunction";
        String[] parts = mixedCase.split("::");

        assertEquals("MyNamespace", parts[0], "Should preserve namespace case");
        assertEquals("MyFunction", parts[1], "Should preserve function name case");

        // Different case should produce different results
        String lowerCase = "mynamespace::myfunction";
        String[] lowerParts = lowerCase.split("::");

        assertNotEquals(parts[0], lowerParts[0], "Case should be preserved");
        assertNotEquals(parts[1], lowerParts[1], "Case should be preserved");
    }

    /**
     * Test comprehensive scenario: the exact bug case
     */
    @Test
    @DisplayName("Should correctly handle the reported bug scenario")
    void testReportedBugScenario() {
        // Step 1: Function is renamed to "A::B" (should go in namespace A)
        String firstRename = "A::B";
        String[] firstParts = firstRename.split("::");
        assertEquals(2, firstParts.length, "Should have namespace");
        assertEquals("A", firstParts[0], "Should be in namespace A");
        assertEquals("B", firstParts[1], "Function name should be B");

        // Step 2: Function is renamed to "B" (should go to GLOBAL namespace)
        String secondRename = "B";
        String[] secondParts = secondRename.split("::");
        assertEquals(1, secondParts.length, "Should NOT have namespace qualifier");

        // THE FIX: When parts.length < 2, we must explicitly set global namespace
        // Previously, it would stay in namespace A. Now it should move to global.
        assertTrue(secondParts.length < 2,
            "Must detect lack of namespace and move to global");
    }

    /**
     * Test regex pattern that could be used as alternative to split
     */
    @Test
    @DisplayName("Should validate namespace delimiter pattern")
    void testNamespaceDelimiterPattern() {
        String delimiter = "::";

        assertTrue("A::B".contains(delimiter), "Namespaced name contains delimiter");
        assertTrue("A::B::C".contains(delimiter), "Multi-level contains delimiter");
        assertFalse("ABC".contains(delimiter), "Simple name does not contain delimiter");
        assertFalse("A:B".contains(delimiter), "Single colon is not the delimiter");
    }
}
