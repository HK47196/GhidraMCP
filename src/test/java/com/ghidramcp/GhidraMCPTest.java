package com.ghidramcp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic test suite for GhidraMCP project.
 *
 * This test serves as a foundation for the test suite and verifies
 * that the JUnit 5 testing framework is properly configured.
 */
class GhidraMCPTest {

    @Test
    @DisplayName("JUnit 5 should be properly configured")
    void testJUnit5Configuration() {
        assertTrue(true, "JUnit 5 is working correctly");
    }

    @Test
    @DisplayName("Basic assertions should work")
    void testBasicAssertions() {
        assertEquals(4, 2 + 2);
        assertNotNull(new Object());
        assertTrue(1 < 2);
        assertFalse(1 > 2);
    }

    @Test
    @DisplayName("String operations should work as expected")
    void testStringOperations() {
        String test = "GhidraMCP";

        assertEquals(9, test.length());
        assertTrue(test.startsWith("Ghidra"));
        assertTrue(test.endsWith("MCP"));
        assertEquals("ghidramcp", test.toLowerCase());
    }

    @Test
    @DisplayName("Exception handling should work")
    void testExceptionHandling() {
        assertThrows(ArithmeticException.class, () -> {
            int result = 10 / 0;
        });

        assertDoesNotThrow(() -> {
            int result = 10 / 2;
        });
    }
}
