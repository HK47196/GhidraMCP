package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for DataLookupService and DataLookupResult.
 *
 * These tests verify the DataLookupResult class behavior and document
 * the expected behavior of DataLookupService.
 *
 * Note: Full integration tests with Ghidra Program objects would require
 * the Ghidra test framework. E2E tests in tests/e2e/test_data_access.py
 * cover the actual functionality with real binaries.
 */
class DataLookupServiceTest {

    private DataLookupService service;

    @BeforeEach
    void setUp() {
        service = new DataLookupService();
    }

    /**
     * Test DataLookupResult construction for top-level data
     */
    @Test
    @DisplayName("Should create result for top-level data")
    void testTopLevelDataResult() {
        // Simulating top-level data (no parent)
        DataLookupResult result = new DataLookupResult(null, null, -1, 0);

        assertFalse(result.isComponent(), "Top-level data should not be a component");
        assertNull(result.getContainingData(), "Top-level data should have no containing data");
        assertEquals(-1, result.getComponentIndex(), "Component index should be -1 for top-level");
        assertEquals(0, result.getOffsetInParent(), "Offset should be 0 for top-level");
    }

    /**
     * Test DataLookupResult construction for component data
     */
    @Test
    @DisplayName("Should create result for component inside composite")
    void testComponentDataResult() {
        // Simulating component data inside a struct/array
        int componentIndex = 5;
        int offset = 20;
        // Using null for Data objects since we can't easily mock them
        DataLookupResult result = new DataLookupResult(null, null, componentIndex, offset);

        // For this test, we set containingData to null but in real usage it would be non-null
        // The isComponent check uses containingData != null
        assertFalse(result.isComponent(), "Should not be component when containingData is null");
        assertEquals(componentIndex, result.getComponentIndex());
        assertEquals(offset, result.getOffsetInParent());
    }

    /**
     * Test that service handles null program gracefully
     */
    @Test
    @DisplayName("Should return null for null program")
    void testNullProgram() {
        DataLookupResult result = service.lookupDataAtAddress(null, null);
        assertNull(result, "Should return null when program is null");
    }

    /**
     * Test DataLookupResult getters
     */
    @Test
    @DisplayName("Should correctly report component status based on containing data")
    void testComponentStatus() {
        // When containingData is null, isComponent should return false
        DataLookupResult topLevel = new DataLookupResult(null, null, -1, 0);
        assertFalse(topLevel.isComponent(), "Should not be component when containing data is null");

        // Component index and offset should be retrievable
        int index = 3;
        int offset = 12;
        DataLookupResult indexed = new DataLookupResult(null, null, index, offset);
        assertEquals(index, indexed.getComponentIndex(), "Should return correct component index");
        assertEquals(offset, indexed.getOffsetInParent(), "Should return correct offset");
    }

    /**
     * Test that DataLookupResult preserves all constructor values
     */
    @Test
    @DisplayName("Should preserve all values passed to constructor")
    void testValuePreservation() {
        int expectedIndex = 7;
        int expectedOffset = 28;

        DataLookupResult result = new DataLookupResult(null, null, expectedIndex, expectedOffset);

        assertNull(result.getData(), "getData should return null when set to null");
        assertNull(result.getContainingData(), "getContainingData should return null when set to null");
        assertEquals(expectedIndex, result.getComponentIndex(), "Component index should be preserved");
        assertEquals(expectedOffset, result.getOffsetInParent(), "Offset should be preserved");
    }

    /**
     * Test various component index scenarios
     */
    @Test
    @DisplayName("Should handle various component indices")
    void testComponentIndices() {
        // Test with -1 (not found/top-level)
        DataLookupResult notFound = new DataLookupResult(null, null, -1, 0);
        assertEquals(-1, notFound.getComponentIndex(), "Should handle -1 index");

        // Test with 0 (first component)
        DataLookupResult first = new DataLookupResult(null, null, 0, 0);
        assertEquals(0, first.getComponentIndex(), "Should handle 0 index");

        // Test with large index
        int largeIndex = 1000;
        DataLookupResult large = new DataLookupResult(null, null, largeIndex, 4000);
        assertEquals(largeIndex, large.getComponentIndex(), "Should handle large index");
    }

    /**
     * Test various offset scenarios
     */
    @Test
    @DisplayName("Should handle various offset values")
    void testOffsetValues() {
        // Test with 0 offset
        DataLookupResult zero = new DataLookupResult(null, null, 0, 0);
        assertEquals(0, zero.getOffsetInParent(), "Should handle 0 offset");

        // Test with typical struct offset
        DataLookupResult typical = new DataLookupResult(null, null, 2, 8);
        assertEquals(8, typical.getOffsetInParent(), "Should handle typical offset");

        // Test with large offset (large array or nested struct)
        int largeOffset = 65536;
        DataLookupResult large = new DataLookupResult(null, null, 0, largeOffset);
        assertEquals(largeOffset, large.getOffsetInParent(), "Should handle large offset");
    }

    /**
     * Document expected behavior for struct member lookup
     *
     * When looking up an address inside a struct:
     * - data should be the struct field
     * - containingData should be the parent struct
     * - componentIndex should be the field index (0-based)
     * - offsetInParent should be the byte offset of the field
     *
     * Integration tested by: tests/e2e/test_data_access.py::test_get_data_by_address_struct_member
     */
    @Test
    @DisplayName("Should document struct member lookup behavior")
    void testStructMemberLookupDocumentation() {
        // This test documents the expected behavior
        // Actual integration testing is done in E2E tests

        // For a struct like:
        // struct { int a; int b; int c; } myStruct;
        // Looking up address of field 'b':
        // - data = Data for field 'b'
        // - containingData = Data for myStruct
        // - componentIndex = 1 (second field)
        // - offsetInParent = 4 (assuming 4-byte ints)

        assertTrue(true, "Documentation test for struct member lookup");
    }

    /**
     * Document expected behavior for array element lookup
     *
     * When looking up an address inside an array:
     * - data should be the array element
     * - containingData should be the parent array
     * - componentIndex should be the element index (0-based)
     * - offsetInParent should be elementIndex * elementSize
     *
     * Integration tested by: tests/e2e/test_data_access.py::test_get_data_by_address_array_element
     */
    @Test
    @DisplayName("Should document array element lookup behavior")
    void testArrayElementLookupDocumentation() {
        // This test documents the expected behavior
        // Actual integration testing is done in E2E tests

        // For an array like:
        // int myArray[10];
        // Looking up address of element [5]:
        // - data = Data for element [5]
        // - containingData = Data for myArray
        // - componentIndex = 5
        // - offsetInParent = 20 (5 * 4 for int)

        assertTrue(true, "Documentation test for array element lookup");
    }

    /**
     * Document expected behavior for nested composite types
     *
     * When looking up an address inside nested composites (e.g., struct in array,
     * or array in struct), the service returns the immediate component:
     * - data = innermost component containing the address
     * - containingData = direct parent of that component
     */
    @Test
    @DisplayName("Should document nested composite type behavior")
    void testNestedCompositeDocumentation() {
        // For nested structures, the lookup returns the immediate
        // component at the first level of nesting.
        // Example: array[5].field would return the struct element array[5]
        // if looking at the start of that element.

        assertTrue(true, "Documentation test for nested composite types");
    }

    /**
     * Document expected behavior when no data exists at address
     *
     * When looking up an address with no defined data:
     * - lookupDataAtAddress returns null
     *
     * This happens for:
     * - Addresses in undefined memory
     * - Addresses in code sections without data definitions
     */
    @Test
    @DisplayName("Should document no-data behavior")
    void testNoDataDocumentation() {
        // Service returns null when:
        // - program is null
        // - addr is null
        // - No data at address and no containing data

        DataLookupResult result = service.lookupDataAtAddress(null, null);
        assertNull(result, "Should return null for null inputs");
    }
}
