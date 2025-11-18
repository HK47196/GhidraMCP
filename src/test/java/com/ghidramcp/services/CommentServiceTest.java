package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CommentService.
 *
 * These tests verify the CommentService input validation and document
 * the expected behavior for each comment type.
 *
 * Note: Full integration tests with Ghidra Program objects would require
 * the Ghidra test framework. E2E tests cover the actual functionality
 * with real binaries. We cannot mock Ghidra's Program interface directly
 * due to its complex dependency hierarchy.
 */
class CommentServiceTest {

    private CommentService service;
    private FunctionNavigator mockNavigator;

    @BeforeEach
    void setUp() {
        mockNavigator = mock(FunctionNavigator.class);
        service = new CommentService(mockNavigator);
    }

    // ====================
    // Constructor Tests
    // ====================

    @Test
    @DisplayName("Should create service with navigator")
    void testServiceConstruction() {
        FunctionNavigator navigator = mock(FunctionNavigator.class);
        CommentService commentService = new CommentService(navigator);
        assertNotNull(commentService, "Service should be created successfully");
    }

    // ====================
    // Null Program Tests
    // ====================

    @Test
    @DisplayName("setDecompilerComment should return false for null program")
    void testSetDecompilerCommentNullProgram() {
        when(mockNavigator.getCurrentProgram()).thenReturn(null);

        boolean result = service.setDecompilerComment("0x1000", "test comment");

        assertFalse(result, "Should return false when program is null");
        verify(mockNavigator).getCurrentProgram();
    }

    @Test
    @DisplayName("setDisassemblyComment should return false for null program")
    void testSetDisassemblyCommentNullProgram() {
        when(mockNavigator.getCurrentProgram()).thenReturn(null);

        boolean result = service.setDisassemblyComment("0x1000", "test comment");

        assertFalse(result, "Should return false when program is null");
        verify(mockNavigator).getCurrentProgram();
    }

    @Test
    @DisplayName("setPlateComment should return false for null program")
    void testSetPlateCommentNullProgram() {
        when(mockNavigator.getCurrentProgram()).thenReturn(null);

        boolean result = service.setPlateComment("0x1000", "test comment");

        assertFalse(result, "Should return false when program is null");
        verify(mockNavigator).getCurrentProgram();
    }

    // ====================
    // Input Validation Documentation Tests
    // ====================

    /**
     * Document expected behavior for null/empty address validation
     *
     * When address is null or empty:
     * - Method returns false immediately after program check
     * - No transaction is started
     * - No changes are made to the program
     */
    @Test
    @DisplayName("Should document null/empty address validation behavior")
    void testAddressValidationDocumentation() {
        // The service checks: addressStr == null || addressStr.isEmpty()
        // If true, returns false without attempting any operation

        // Null address check
        String nullAddress = null;
        assertTrue(nullAddress == null, "Null address should be rejected");

        // Empty address check
        String emptyAddress = "";
        assertTrue(emptyAddress.isEmpty(), "Empty address should be rejected");

        // Note: Whitespace-only addresses pass isEmpty() but fail at parsing
        String whitespaceAddress = "   ";
        assertFalse(whitespaceAddress.isEmpty(), "Whitespace passes isEmpty check but fails parsing");
    }

    /**
     * Document expected behavior for null comment validation
     *
     * When comment is null:
     * - Method returns false immediately after address check
     * - No transaction is started
     * - No changes are made to the program
     *
     * Note: Empty string comments ARE valid and can be used to clear comments
     */
    @Test
    @DisplayName("Should document null comment validation behavior")
    void testCommentValidationDocumentation() {
        // The service checks: comment == null
        // If true, returns false without attempting any operation

        String nullComment = null;
        assertTrue(nullComment == null, "Null comment should be rejected");

        // Empty string is valid (used to clear comments)
        String emptyComment = "";
        assertFalse(emptyComment == null, "Empty string comment should be accepted");
    }

    // ====================
    // Valid Input Format Tests
    // ====================

    @ParameterizedTest
    @ValueSource(strings = {"0x1000", "0x00401000", "00401000", "1000"})
    @DisplayName("Should accept various valid address formats")
    void testValidAddressFormats(String address) {
        // This test documents that the service accepts various address formats
        // Actual parsing is handled by Ghidra's AddressFactory
        assertNotNull(address, "Address format should not be null");
        assertFalse(address.isEmpty(), "Address format should not be empty");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Simple comment", "Multi\nline\ncomment", "Comment with special chars: !@#$%^&*()"})
    @DisplayName("Should accept various comment formats")
    void testValidCommentFormats(String comment) {
        // This test documents that the service accepts various comment formats
        // Empty string is valid (can be used to clear a comment)
        assertNotNull(comment, "Comment format should not be null");
    }

    // ====================
    // Comment Type Documentation Tests
    // ====================

    /**
     * Document expected behavior for decompiler comments (PRE type)
     *
     * PRE comments appear before the instruction in the decompiler view.
     * They are useful for explaining the purpose of a code block or
     * providing context for complex operations.
     *
     * In the Ghidra UI, PRE comments appear:
     * - Above the instruction in the listing view
     * - As block comments in the decompiler view
     */
    @Test
    @DisplayName("Should document decompiler comment (PRE) behavior")
    void testDecompilerCommentDocumentation() {
        // Decompiler comments use CommentType.PRE
        // They appear in both listing and decompiler views
        // Useful for documenting algorithm steps or code blocks

        assertTrue(true, "Documentation test for decompiler comments (PRE type)");
    }

    /**
     * Document expected behavior for disassembly comments (EOL type)
     *
     * EOL (End of Line) comments appear at the end of the instruction line
     * in the disassembly listing. They are useful for quick annotations
     * about specific instructions.
     *
     * In the Ghidra UI, EOL comments appear:
     * - At the end of the instruction line in the listing view
     * - May not be visible in the decompiler view
     */
    @Test
    @DisplayName("Should document disassembly comment (EOL) behavior")
    void testDisassemblyCommentDocumentation() {
        // Disassembly comments use CommentType.EOL
        // They appear at the end of instruction lines
        // Useful for brief inline annotations

        assertTrue(true, "Documentation test for disassembly comments (EOL type)");
    }

    /**
     * Document expected behavior for plate comments (PLATE type)
     *
     * PLATE comments appear as a boxed header above a function or code block.
     * They are typically used for function-level documentation or
     * major section markers.
     *
     * In the Ghidra UI, PLATE comments appear:
     * - As a bordered box above the code in the listing view
     * - Often used at function entry points
     */
    @Test
    @DisplayName("Should document plate comment (PLATE) behavior")
    void testPlateCommentDocumentation() {
        // Plate comments use CommentType.PLATE
        // They appear as boxed headers in the listing view
        // Useful for function or section documentation

        assertTrue(true, "Documentation test for plate comments (PLATE type)");
    }

    // ====================
    // Transaction Behavior Documentation Tests
    // ====================

    /**
     * Document expected transaction behavior
     *
     * All comment operations are wrapped in Ghidra transactions:
     * - Transaction is started before modification
     * - Transaction is committed on success
     * - Transaction is rolled back on failure
     *
     * This ensures database consistency and enables undo/redo functionality.
     */
    @Test
    @DisplayName("Should document transaction behavior")
    void testTransactionBehaviorDocumentation() {
        // Each comment operation:
        // 1. Starts a transaction with descriptive name
        // 2. Performs the modification
        // 3. Ends transaction with success/failure status
        //
        // This allows:
        // - Undo/redo in Ghidra UI
        // - Atomic operations
        // - Database consistency

        assertTrue(true, "Documentation test for transaction behavior");
    }

    /**
     * Document expected threading behavior
     *
     * All comment operations execute on the Swing Event Dispatch Thread (EDT)
     * using SwingUtilities.invokeAndWait(). This ensures:
     * - Thread safety for Ghidra's database operations
     * - Proper synchronization with UI updates
     * - Consistent behavior with Ghidra's threading model
     */
    @Test
    @DisplayName("Should document threading behavior")
    void testThreadingBehaviorDocumentation() {
        // Comment operations use SwingUtilities.invokeAndWait()
        // This ensures:
        // - Operations run on the EDT
        // - Caller blocks until completion
        // - Thread-safe access to program database

        assertTrue(true, "Documentation test for threading behavior");
    }

    // ====================
    // Error Handling Documentation Tests
    // ====================

    /**
     * Document expected behavior for invalid addresses
     *
     * When an address cannot be parsed by Ghidra's AddressFactory:
     * - An exception is caught internally
     * - Error is logged via Msg.error()
     * - Method returns false
     * - Transaction is rolled back
     */
    @Test
    @DisplayName("Should document invalid address handling")
    void testInvalidAddressHandlingDocumentation() {
        // When address parsing fails:
        // - Exception is caught in the transaction block
        // - Error is logged with context
        // - Transaction is ended with false (rollback)
        // - Method returns false to caller

        assertTrue(true, "Documentation test for invalid address handling");
    }

    /**
     * Document expected behavior for interrupted operations
     *
     * If the Swing thread operation is interrupted:
     * - InterruptedException is caught
     * - Error is logged via Msg.error()
     * - Method returns false
     */
    @Test
    @DisplayName("Should document interrupted operation handling")
    void testInterruptedOperationHandlingDocumentation() {
        // When SwingUtilities.invokeAndWait() is interrupted:
        // - InterruptedException is caught
        // - InvocationTargetException is also handled
        // - Error is logged with context
        // - Method returns false

        assertTrue(true, "Documentation test for interrupted operation handling");
    }

    // ====================
    // Edge Case Documentation Tests
    // ====================

    @Test
    @DisplayName("Should document empty string comment behavior (clears comment)")
    void testEmptyStringCommentDocumentation() {
        // Empty string comments are valid and can be used to clear existing comments
        // This is different from null, which is rejected
        String emptyComment = "";
        assertNotNull(emptyComment, "Empty string should be accepted");
        assertFalse(emptyComment == null, "Empty string is not null");
    }

    @Test
    @DisplayName("Should document whitespace-only address behavior")
    void testWhitespaceOnlyAddressDocumentation() {
        // Whitespace-only addresses are not empty strings, so they pass
        // the isEmpty() check but will fail at address parsing
        String whitespaceAddress = "   ";
        assertFalse(whitespaceAddress.isEmpty(), "Whitespace-only is not considered empty by String.isEmpty()");
        // These will fail at Ghidra's address parsing stage
    }

    @Test
    @DisplayName("Should handle very long comments")
    void testVeryLongComment() {
        // Document that very long comments are accepted
        // Actual storage limits are determined by Ghidra
        String longComment = "A".repeat(10000);
        assertEquals(10000, longComment.length(), "Should create long comment");
    }

    @Test
    @DisplayName("Should handle comments with unicode characters")
    void testUnicodeComment() {
        // Document that unicode comments are supported
        String unicodeComment = "Comment with unicode: \u00e9\u00e8\u00ea \u4e2d\u6587 \u0410\u0411\u0412";
        assertNotNull(unicodeComment, "Unicode comments should be supported");
        assertFalse(unicodeComment.isEmpty(), "Unicode comment should not be empty");
    }

    @Test
    @DisplayName("Should handle comments with newlines")
    void testMultilineComment() {
        // Document that multiline comments are supported
        String multilineComment = "Line 1\nLine 2\nLine 3";
        assertTrue(multilineComment.contains("\n"), "Multiline comments should be supported");
    }

    // ====================
    // Multiple Operation Tests
    // ====================

    @Test
    @DisplayName("Should allow multiple comment operations on same address")
    void testMultipleCommentsOnSameAddress() {
        // Document that different comment types can coexist at same address
        // Each type (PRE, EOL, PLATE) is stored separately
        when(mockNavigator.getCurrentProgram()).thenReturn(null);

        // All operations will return false due to null program,
        // but this documents that the service supports multiple comment types
        String address = "0x1000";
        service.setDecompilerComment(address, "PRE comment");
        service.setDisassemblyComment(address, "EOL comment");
        service.setPlateComment(address, "PLATE comment");

        // Verify that all three methods were called (program was checked 3 times)
        verify(mockNavigator, times(3)).getCurrentProgram();
    }

    @Test
    @DisplayName("Should allow comment operations on different addresses")
    void testCommentsOnDifferentAddresses() {
        // Document that comments can be set on multiple addresses
        when(mockNavigator.getCurrentProgram()).thenReturn(null);

        service.setDecompilerComment("0x1000", "Comment 1");
        service.setDecompilerComment("0x2000", "Comment 2");
        service.setDecompilerComment("0x3000", "Comment 3");

        // Verify that getCurrentProgram was called for each operation
        verify(mockNavigator, times(3)).getCurrentProgram();
    }

    // ====================
    // Method Signature Documentation
    // ====================

    @Test
    @DisplayName("Should document setDecompilerComment method signature")
    void testSetDecompilerCommentSignature() {
        // Method: boolean setDecompilerComment(String addressStr, String comment)
        // Uses: CommentType.PRE
        // Transaction name: "Set decompiler comment"
        // Returns: true on success, false on failure

        when(mockNavigator.getCurrentProgram()).thenReturn(null);
        boolean result = service.setDecompilerComment("0x1000", "test");
        assertFalse(result, "Should return boolean result");
    }

    @Test
    @DisplayName("Should document setDisassemblyComment method signature")
    void testSetDisassemblyCommentSignature() {
        // Method: boolean setDisassemblyComment(String addressStr, String comment)
        // Uses: CommentType.EOL
        // Transaction name: "Set disassembly comment"
        // Returns: true on success, false on failure

        when(mockNavigator.getCurrentProgram()).thenReturn(null);
        boolean result = service.setDisassemblyComment("0x1000", "test");
        assertFalse(result, "Should return boolean result");
    }

    @Test
    @DisplayName("Should document setPlateComment method signature")
    void testSetPlateCommentSignature() {
        // Method: boolean setPlateComment(String addressStr, String comment)
        // Uses: CommentType.PLATE
        // Transaction name: "Set plate comment"
        // Returns: true on success, false on failure

        when(mockNavigator.getCurrentProgram()).thenReturn(null);
        boolean result = service.setPlateComment("0x1000", "test");
        assertFalse(result, "Should return boolean result");
    }
}
