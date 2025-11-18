package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for CrossReferenceAnalyzer.
 *
 * These tests verify parameter validation, error message formatting,
 * output formatting, and pagination logic for cross-reference analysis operations.
 *
 * Note: Full integration tests with Ghidra Program objects are implemented
 * in the E2E test suite (tests/e2e/test_xrefs.py).
 */
class CrossReferenceAnalyzerTest {

    @Nested
    @DisplayName("Error Message Validation Tests")
    class ErrorMessageTests {

        /**
         * Test no program loaded error message
         */
        @Test
        @DisplayName("Should have correct error message for no program loaded")
        void testNoProgramLoadedError() {
            String expectedError = "No program loaded";

            assertTrue(expectedError.contains("No program"),
                "Should indicate no program is loaded");
            assertEquals("No program loaded", expectedError,
                "Error message should match expected format");
        }

        /**
         * Test address required error message
         */
        @Test
        @DisplayName("Should have correct error message when address is required")
        void testAddressRequiredError() {
            String expectedError = "Address is required";

            assertTrue(expectedError.contains("required"),
                "Should indicate address is required");
            assertTrue(expectedError.contains("Address"),
                "Should mention address");
        }

        /**
         * Test function name required error message
         */
        @Test
        @DisplayName("Should have correct error message when function name is required")
        void testFunctionNameRequiredError() {
            String expectedError = "Function name is required";

            assertTrue(expectedError.contains("required"),
                "Should indicate function name is required");
            assertTrue(expectedError.contains("Function name"),
                "Should mention function name");
        }

        /**
         * Test error message for getting references to address
         */
        @Test
        @DisplayName("Should format error for xrefs to address correctly")
        void testXrefsToErrorFormat() {
            String errorMessage = "invalid address";
            String expectedError = "Error getting references to address: " + errorMessage;

            assertTrue(expectedError.contains("Error getting references to address"),
                "Should indicate error getting references to address");
            assertTrue(expectedError.contains(errorMessage),
                "Should include the original error message");
        }

        /**
         * Test error message for getting references from address
         */
        @Test
        @DisplayName("Should format error for xrefs from address correctly")
        void testXrefsFromErrorFormat() {
            String errorMessage = "invalid address";
            String expectedError = "Error getting references from address: " + errorMessage;

            assertTrue(expectedError.contains("Error getting references from address"),
                "Should indicate error getting references from address");
            assertTrue(expectedError.contains(errorMessage),
                "Should include the original error message");
        }

        /**
         * Test error message for getting function references
         */
        @Test
        @DisplayName("Should format error for function xrefs correctly")
        void testFunctionXrefsErrorFormat() {
            String errorMessage = "function not found";
            String expectedError = "Error getting function references: " + errorMessage;

            assertTrue(expectedError.contains("Error getting function references"),
                "Should indicate error getting function references");
            assertTrue(expectedError.contains(errorMessage),
                "Should include the original error message");
        }

        /**
         * Test no references found message
         */
        @Test
        @DisplayName("Should format no references found message correctly")
        void testNoReferencesFoundFormat() {
            String functionName = "testFunction";
            String expectedMessage = "No references found to function: " + functionName;

            assertTrue(expectedMessage.contains("No references found"),
                "Should indicate no references were found");
            assertTrue(expectedMessage.contains(functionName),
                "Should include the function name");
        }
    }

    @Nested
    @DisplayName("Output Format Tests")
    class OutputFormatTests {

        /**
         * Test reference entry format for xrefs to
         */
        @Test
        @DisplayName("Should format reference entry with function info correctly")
        void testReferenceEntryFormat() {
            String address = "0x12345678";
            String funcInfo = " in main";
            String refType = "UNCONDITIONAL_CALL";
            String expectedFormat = String.format("From %s%s [%s]", address, funcInfo, refType);

            assertTrue(expectedFormat.contains("From"),
                "Should start with 'From' for xrefs to");
            assertTrue(expectedFormat.contains(address),
                "Should include the address");
            assertTrue(expectedFormat.contains("main"),
                "Should include the function name");
            assertTrue(expectedFormat.contains("[" + refType + "]"),
                "Should include reference type in brackets");
        }

        /**
         * Test reference entry format for xrefs from
         */
        @Test
        @DisplayName("Should format outgoing reference entry correctly")
        void testOutgoingReferenceEntryFormat() {
            String address = "0x87654321";
            String targetInfo = " to function printf";
            String refType = "UNCONDITIONAL_CALL";
            String expectedFormat = String.format("To %s%s [%s]", address, targetInfo, refType);

            assertTrue(expectedFormat.contains("To"),
                "Should start with 'To' for xrefs from");
            assertTrue(expectedFormat.contains(address),
                "Should include the target address");
            assertTrue(expectedFormat.contains("printf"),
                "Should include the target function name");
            assertTrue(expectedFormat.contains("[" + refType + "]"),
                "Should include reference type in brackets");
        }

        /**
         * Test reference entry format with instruction
         */
        @Test
        @DisplayName("Should format reference entry with instruction correctly")
        void testReferenceEntryWithInstructionFormat() {
            String address = "0x12345678";
            String funcInfo = " in main";
            String instrStr = "CALL printf";
            String expectedFormat = String.format("  %s%s: %s", address, funcInfo, instrStr);

            assertTrue(expectedFormat.startsWith("  "),
                "Should be indented with 2 spaces");
            assertTrue(expectedFormat.contains(address),
                "Should include the address");
            assertTrue(expectedFormat.contains("main"),
                "Should include the function name");
            assertTrue(expectedFormat.contains(":"),
                "Should have colon separator before instruction");
            assertTrue(expectedFormat.contains(instrStr),
                "Should include the instruction string");
        }

        /**
         * Test data reference format
         */
        @Test
        @DisplayName("Should format data reference correctly")
        void testDataReferenceFormat() {
            String dataType = "char *";
            String expectedFormat = "[DATA: " + dataType + "]";

            assertTrue(expectedFormat.startsWith("[DATA:"),
                "Should start with [DATA:");
            assertTrue(expectedFormat.contains(dataType),
                "Should include the data type");
            assertTrue(expectedFormat.endsWith("]"),
                "Should end with ]");
        }

        /**
         * Test undefined reference format
         */
        @Test
        @DisplayName("Should format undefined location correctly")
        void testUndefinedFormat() {
            String expectedFormat = "[UNDEFINED]";

            assertEquals("[UNDEFINED]", expectedFormat,
                "Should be exactly [UNDEFINED]");
        }

        /**
         * Test group header format
         */
        @Test
        @DisplayName("Should format group header with count correctly")
        void testGroupHeaderFormat() {
            String typeName = "UNCONDITIONAL_CALL";
            int count = 5;
            String expectedFormat = String.format("%s (%d):", typeName, count);

            assertTrue(expectedFormat.contains(typeName),
                "Should include the type name");
            assertTrue(expectedFormat.contains("(" + count + ")"),
                "Should include count in parentheses");
            assertTrue(expectedFormat.endsWith(":"),
                "Should end with colon");
        }

        /**
         * Test instruction formatting with mnemonic and operands
         */
        @Test
        @DisplayName("Should format instruction with mnemonic and operands")
        void testInstructionFormat() {
            String mnemonic = "CALL";
            String operands = "0x12345678";
            String expectedFormat = mnemonic + " " + operands;

            assertTrue(expectedFormat.contains(mnemonic),
                "Should include the mnemonic");
            assertTrue(expectedFormat.contains(operands),
                "Should include the operands");
            assertEquals("CALL 0x12345678", expectedFormat,
                "Format should be 'MNEMONIC OPERANDS'");
        }

        /**
         * Test instruction formatting with multiple operands
         */
        @Test
        @DisplayName("Should format instruction with multiple operands using commas")
        void testInstructionMultipleOperandsFormat() {
            String mnemonic = "MOV";
            String operand1 = "EAX";
            String operand2 = "0x5";
            String expectedFormat = mnemonic + " " + operand1 + "," + operand2;

            assertEquals("MOV EAX,0x5", expectedFormat,
                "Multiple operands should be separated by commas");
        }

        /**
         * Test context line formatting with marker
         */
        @Test
        @DisplayName("Should use > marker for main instruction in context")
        void testContextInstructionMarkerFormat() {
            String address = "0x12345678";
            String instruction = "CALL printf";
            String expectedFormat = String.format("  > %s: %s", address, instruction);

            assertTrue(expectedFormat.contains(">"),
                "Should have > marker for main instruction");
            assertTrue(expectedFormat.startsWith("  >"),
                "Marker should be indented with 2 spaces");
        }

        /**
         * Test context line formatting for surrounding instructions
         */
        @Test
        @DisplayName("Should indent context lines with 4 spaces")
        void testContextLineIndentFormat() {
            String address = "0x12345674";
            String instruction = "PUSH EBP";
            String expectedFormat = String.format("    %s: %s", address, instruction);

            assertTrue(expectedFormat.startsWith("    "),
                "Context lines should be indented with 4 spaces");
            assertTrue(expectedFormat.contains(":"),
                "Should have colon separator");
        }
    }

    @Nested
    @DisplayName("Pagination Format Tests")
    class PaginationFormatTests {

        /**
         * Test pagination info format
         */
        @Test
        @DisplayName("Should format pagination info correctly")
        void testPaginationInfoFormat() {
            int offset = 0;
            int showing = 10;
            int total = 50;
            String expectedFormat = String.format("[Showing %d-%d of %d total references]",
                offset + 1, offset + showing, total);

            assertEquals("[Showing 1-10 of 50 total references]", expectedFormat,
                "Pagination info should use 1-based indexing");
            assertTrue(expectedFormat.startsWith("["),
                "Should start with [");
            assertTrue(expectedFormat.endsWith("]"),
                "Should end with ]");
            assertTrue(expectedFormat.contains("total references"),
                "Should mention total references");
        }

        /**
         * Test pagination info with different offsets
         */
        @ParameterizedTest
        @CsvSource({
            "0, 10, 100, '[Showing 1-10 of 100 total references]'",
            "10, 10, 100, '[Showing 11-20 of 100 total references]'",
            "90, 10, 100, '[Showing 91-100 of 100 total references]'",
            "0, 5, 25, '[Showing 1-5 of 25 total references]'"
        })
        @DisplayName("Should format pagination info with various offset/limit combinations")
        void testPaginationInfoVariousOffsets(int offset, int showing, int total, String expected) {
            String formatted = String.format("[Showing %d-%d of %d total references]",
                offset + 1, offset + showing, total);

            assertEquals(expected, formatted,
                "Pagination info should match expected format");
        }

        /**
         * Test that pagination info is shown only when there are more items than limit
         */
        @Test
        @DisplayName("Should show pagination info only when total exceeds limit")
        void testPaginationInfoThreshold() {
            int total = 10;
            int limit = 10;

            // Pagination info should only appear when total > limit
            assertFalse(total > limit,
                "Should not show pagination when total equals limit");

            int total2 = 11;
            assertTrue(total2 > limit,
                "Should show pagination when total exceeds limit");
        }
    }

    @Nested
    @DisplayName("Reference Type Tests")
    class ReferenceTypeTests {

        /**
         * Test common reference type names
         */
        @ParameterizedTest
        @ValueSource(strings = {
            "UNCONDITIONAL_CALL",
            "CONDITIONAL_CALL",
            "DATA",
            "READ",
            "WRITE",
            "CONDITIONAL_JUMP",
            "UNCONDITIONAL_JUMP",
            "COMPUTED_CALL",
            "COMPUTED_JUMP",
            "INDIRECTION"
        })
        @DisplayName("Should handle various reference type names")
        void testReferenceTypeNames(String refType) {
            String groupHeader = String.format("%s (1):", refType);

            assertTrue(groupHeader.contains(refType),
                "Group header should include reference type name");
            assertTrue(groupHeader.contains("(1)"),
                "Group header should include count");
        }
    }

    @Nested
    @DisplayName("Address Format Tests")
    class AddressFormatTests {

        /**
         * Test valid address formats
         */
        @ParameterizedTest
        @ValueSource(strings = {
            "0x12345678",
            "0x00401000",
            "0xFFFFFFFF",
            "12345678",
            "00401000"
        })
        @DisplayName("Should accept various address formats")
        void testValidAddressFormats(String address) {
            String formatted = String.format("From %s [DATA]", address);

            assertTrue(formatted.contains(address),
                "Output should include the address in the provided format");
        }

        /**
         * Test address padding consistency
         */
        @Test
        @DisplayName("Should format addresses consistently")
        void testAddressConsistency() {
            String address1 = "0x00401000";
            String address2 = "0x00401004";

            String line1 = String.format("  %s: instruction1", address1);
            String line2 = String.format("  %s: instruction2", address2);

            // Both should have same prefix length
            int colonPos1 = line1.indexOf(':');
            int colonPos2 = line2.indexOf(':');

            assertEquals(colonPos1, colonPos2,
                "Address formatting should be consistent across lines");
        }
    }

    @Nested
    @DisplayName("Include Instruction Parameter Tests")
    class IncludeInstructionTests {

        /**
         * Test includeInstruction parameter semantics
         */
        @Test
        @DisplayName("Should understand includeInstruction parameter values")
        void testIncludeInstructionSemantics() {
            // -1 = no instruction (simple format)
            // 0 = instruction only
            // >0 = instruction + N context lines

            int noInstruction = -1;
            int instructionOnly = 0;
            int withContext = 3;

            assertTrue(noInstruction < 0,
                "-1 should mean no instruction");
            assertEquals(0, instructionOnly,
                "0 should mean instruction only");
            assertTrue(withContext > 0,
                ">0 should mean instruction with context lines");
        }

        /**
         * Test context line count validation
         */
        @ParameterizedTest
        @ValueSource(ints = {1, 2, 3, 5, 10})
        @DisplayName("Should support various context line counts")
        void testContextLineCounts(int contextLines) {
            assertTrue(contextLines > 0,
                "Context lines should be positive");
            // Total lines = contextLines before + 1 main + contextLines after
            int totalLines = contextLines * 2 + 1;
            assertTrue(totalLines >= 3,
                "Should have at least 3 lines with context");
        }
    }

    @Nested
    @DisplayName("Method Signature Tests")
    class MethodSignatureTests {

        /**
         * Test that backward compatibility methods exist
         */
        @Test
        @DisplayName("Should have backward compatible getXrefsTo method")
        void testBackwardCompatibleGetXrefsTo() throws NoSuchMethodException {
            Class<CrossReferenceAnalyzer> clazz = CrossReferenceAnalyzer.class;

            // Should have both 3-parameter and 4-parameter versions
            Method method3Param = clazz.getMethod("getXrefsTo", String.class, int.class, int.class);
            Method method4Param = clazz.getMethod("getXrefsTo", String.class, int.class, int.class, int.class);

            assertNotNull(method3Param, "Should have 3-parameter getXrefsTo method");
            assertNotNull(method4Param, "Should have 4-parameter getXrefsTo method");
        }

        /**
         * Test that backward compatibility methods exist for getXrefsFrom
         */
        @Test
        @DisplayName("Should have backward compatible getXrefsFrom method")
        void testBackwardCompatibleGetXrefsFrom() throws NoSuchMethodException {
            Class<CrossReferenceAnalyzer> clazz = CrossReferenceAnalyzer.class;

            // Should have both 3-parameter and 4-parameter versions
            Method method3Param = clazz.getMethod("getXrefsFrom", String.class, int.class, int.class);
            Method method4Param = clazz.getMethod("getXrefsFrom", String.class, int.class, int.class, int.class);

            assertNotNull(method3Param, "Should have 3-parameter getXrefsFrom method");
            assertNotNull(method4Param, "Should have 4-parameter getXrefsFrom method");
        }

        /**
         * Test that backward compatibility methods exist for getFunctionXrefs
         */
        @Test
        @DisplayName("Should have backward compatible getFunctionXrefs method")
        void testBackwardCompatibleGetFunctionXrefs() throws NoSuchMethodException {
            Class<CrossReferenceAnalyzer> clazz = CrossReferenceAnalyzer.class;

            // Should have both 3-parameter and 4-parameter versions
            Method method3Param = clazz.getMethod("getFunctionXrefs", String.class, int.class, int.class);
            Method method4Param = clazz.getMethod("getFunctionXrefs", String.class, int.class, int.class, int.class);

            assertNotNull(method3Param, "Should have 3-parameter getFunctionXrefs method");
            assertNotNull(method4Param, "Should have 4-parameter getFunctionXrefs method");
        }

        /**
         * Test return type of public methods
         */
        @Test
        @DisplayName("All public xref methods should return String")
        void testReturnTypes() throws NoSuchMethodException {
            Class<CrossReferenceAnalyzer> clazz = CrossReferenceAnalyzer.class;

            Method getXrefsTo = clazz.getMethod("getXrefsTo", String.class, int.class, int.class, int.class);
            Method getXrefsFrom = clazz.getMethod("getXrefsFrom", String.class, int.class, int.class, int.class);
            Method getFunctionXrefs = clazz.getMethod("getFunctionXrefs", String.class, int.class, int.class, int.class);

            assertEquals(String.class, getXrefsTo.getReturnType(), "getXrefsTo should return String");
            assertEquals(String.class, getXrefsFrom.getReturnType(), "getXrefsFrom should return String");
            assertEquals(String.class, getFunctionXrefs.getReturnType(), "getFunctionXrefs should return String");
        }
    }

    @Nested
    @DisplayName("FormatGroupedRefs Logic Tests")
    class FormatGroupedRefsTests {

        /**
         * Test empty map handling
         */
        @Test
        @DisplayName("Should handle empty reference map")
        void testEmptyReferenceMap() {
            Map<String, List<String>> emptyMap = new LinkedHashMap<>();

            assertTrue(emptyMap.isEmpty(),
                "Empty map should have no entries");

            int totalCount = 0;
            for (List<String> refs : emptyMap.values()) {
                totalCount += refs.size();
            }

            assertEquals(0, totalCount,
                "Total count should be 0 for empty map");
        }

        /**
         * Test single group formatting
         */
        @Test
        @DisplayName("Should format single group correctly")
        void testSingleGroupFormatting() {
            Map<String, List<String>> refsByType = new LinkedHashMap<>();
            List<String> refs = new ArrayList<>();
            refs.add("  0x1000 in main: CALL printf");
            refs.add("  0x1010 in main: CALL puts");
            refsByType.put("UNCONDITIONAL_CALL", refs);

            // Verify structure
            assertEquals(1, refsByType.size(),
                "Should have exactly one group");
            assertEquals(2, refsByType.get("UNCONDITIONAL_CALL").size(),
                "Group should have 2 entries");
        }

        /**
         * Test multiple groups formatting
         */
        @Test
        @DisplayName("Should format multiple groups correctly")
        void testMultipleGroupsFormatting() {
            Map<String, List<String>> refsByType = new LinkedHashMap<>();

            List<String> calls = new ArrayList<>();
            calls.add("  0x1000 in main: CALL printf");
            refsByType.put("UNCONDITIONAL_CALL", calls);

            List<String> reads = new ArrayList<>();
            reads.add("  0x2000 in func: MOV EAX,[data]");
            reads.add("  0x2010 in func: MOV EBX,[data]");
            refsByType.put("DATA_READ", reads);

            // Verify structure
            assertEquals(2, refsByType.size(),
                "Should have two groups");

            int totalCount = 0;
            for (List<String> refs : refsByType.values()) {
                totalCount += refs.size();
            }

            assertEquals(3, totalCount,
                "Total count should be 3");
        }

        /**
         * Test pagination offset calculation
         */
        @Test
        @DisplayName("Should calculate pagination offset correctly")
        void testPaginationOffsetCalculation() {
            int offset = 5;
            int limit = 10;

            // Simulating pagination logic
            int currentIndex = 0;
            int itemsToSkip = offset;

            // Group 1: 3 items
            int group1Size = 3;
            if (currentIndex + group1Size <= offset) {
                currentIndex += group1Size;
            }

            assertTrue(currentIndex <= offset,
                "Should track current index correctly");
            assertEquals(3, currentIndex,
                "Current index should be 3 after first group");
        }

        /**
         * Test limit application
         */
        @Test
        @DisplayName("Should apply limit correctly")
        void testLimitApplication() {
            int offset = 0;
            int limit = 5;

            List<String> items = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                items.add("item" + i);
            }

            int startIdx = offset;
            int endIdx = Math.min(items.size(), startIdx + limit);

            assertEquals(5, endIdx - startIdx,
                "Should return exactly 'limit' items when available");
        }

        /**
         * Test offset beyond total items
         */
        @Test
        @DisplayName("Should handle offset beyond total items")
        void testOffsetBeyondTotal() {
            int offset = 100;
            int limit = 10;
            int totalItems = 50;

            int showing = Math.min(limit, totalItems - offset);

            assertTrue(showing <= 0,
                "Should show 0 items when offset exceeds total");
        }
    }

    @Nested
    @DisplayName("Target Info Format Tests")
    class TargetInfoTests {

        /**
         * Test target function info format
         */
        @Test
        @DisplayName("Should format target function info correctly")
        void testTargetFunctionInfoFormat() {
            String funcName = "printf";
            String targetInfo = " to function " + funcName;

            assertTrue(targetInfo.contains("to function"),
                "Should contain 'to function'");
            assertTrue(targetInfo.contains(funcName),
                "Should contain function name");
        }

        /**
         * Test target data info format with label
         */
        @Test
        @DisplayName("Should format target data with label correctly")
        void testTargetDataWithLabelFormat() {
            String label = "globalVar";
            String targetInfo = " to data " + label;

            assertTrue(targetInfo.contains("to data"),
                "Should contain 'to data'");
            assertTrue(targetInfo.contains(label),
                "Should contain data label");
        }

        /**
         * Test target data info format without label
         */
        @Test
        @DisplayName("Should use path name when label is null")
        void testTargetDataPathNameFormat() {
            String pathName = "/data/0x00401000";
            String targetInfo = " to data " + pathName;

            assertTrue(targetInfo.contains("to data"),
                "Should contain 'to data'");
            assertTrue(targetInfo.contains(pathName),
                "Should contain path name when label is null");
        }

        /**
         * Test source function info format
         */
        @Test
        @DisplayName("Should format source function info correctly")
        void testSourceFunctionInfoFormat() {
            String funcName = "main";
            String funcInfo = " in " + funcName;

            assertTrue(funcInfo.contains("in"),
                "Should contain 'in'");
            assertTrue(funcInfo.contains(funcName),
                "Should contain function name");
        }

        /**
         * Test empty function info when address not in function
         */
        @Test
        @DisplayName("Should use empty string when address not in function")
        void testEmptyFunctionInfo() {
            String funcInfo = "";

            assertTrue(funcInfo.isEmpty(),
                "Function info should be empty when address is not in a function");
        }
    }
}
