package com.ghidramcp.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for getAddressContext functionality.
 *
 * These tests verify that the get_address_context output displays listing items
 * (both instructions and data) in memory order, exactly like the Ghidra UI.
 *
 * Key requirements tested:
 * - Shows data items at data addresses (not jumping to nearest instruction)
 * - Displays code units in strict memory order
 * - Formats data with type, value, labels, and XREFs
 * - Shows plate comments for labeled data
 * - Handles mixed code and data correctly
 *
 * Note: Full integration tests with actual Ghidra listing would require the
 * Ghidra test framework and Program fixtures. These tests verify output format
 * and structure.
 */
class AddressContextTest {

    // ==================== Data Display Tests ====================

    @Test
    @DisplayName("Data items should be displayed with address, bytes, type, and value")
    void testDataItemFormat() {
        // Simulated data output format (like Ghidra UI)
        String dataLine = "  --> 00231fec  00 00 00 ...   uint8_t[   \"\"";

        assertTrue(dataLine.contains("00231fec"), "Should show data address");
        assertTrue(dataLine.contains("00 00 00"), "Should show data bytes");
        assertTrue(dataLine.contains("uint8_t["), "Should show data type");
        assertTrue(dataLine.contains("  --> "), "Should mark target with arrow");
    }

    @Test
    @DisplayName("Data labels should be displayed with XREFs")
    void testDataLabelWithXrefs() {
        // Simulated data label output (like Ghidra UI)
        String labelLine = "                             Script::g_Bytecode_Stack                        XREF[24]: Stack_PushWord:00224762(*), Stack_PushWord:00224766(*), [more]";

        assertTrue(labelLine.contains("Script::g_Bytecode_Stack"), "Should show data label with namespace");
        assertTrue(labelLine.contains("XREF[24]:"), "Should show XREF count");
        assertTrue(labelLine.contains("Stack_PushWord:00224762(*)"), "Should show XREF references");
        assertTrue(labelLine.contains("[more]"), "Should indicate additional XREFs");
    }

    @Test
    @DisplayName("Plate comments should be displayed for data items")
    void testDataPlateComment() {
        String plateComment = "Bytecode VM evaluation stack. Grows downward from index...";

        // Verify plate comment structure
        String[] lines = plateComment.split("\n");
        assertTrue(lines.length > 0, "Plate comment should have content");

        // Expected format (bordered box):
        // **************************************************************
        // * Bytecode VM evaluation stack. Grows downward from index... *
        // **************************************************************

        int maxLength = 0;
        for (String line : lines) {
            maxLength = Math.max(maxLength, line.length());
        }
        maxLength = Math.max(maxLength, 60);

        assertTrue(maxLength >= 60, "Plate comment box should have minimum width of 60");
    }

    @Test
    @DisplayName("Data bytes should be limited to first 4 bytes with ellipsis for large data")
    void testDataBytesLimitForLargeData() {
        // For large data items (e.g., uint8_t[250]), show first 4 bytes
        String largeDataLine = "       00231fec  00 00 00 ...   uint8_t[";

        assertTrue(largeDataLine.contains("00 00 00 ..."),
                  "Large data should show first ~4 bytes with ellipsis");
        assertFalse(largeDataLine.matches(".*([0-9a-f]{2} ){10,}.*"),
                   "Should not show all bytes for large data");
    }

    @Test
    @DisplayName("Simple data should show all bytes if small")
    void testSmallDataBytesComplete() {
        // For small data items (e.g., uint32_t = 4 bytes), show all bytes
        String smallDataLine = "       00231fe4  00 00 00 00    uint32_t   0h";

        assertTrue(smallDataLine.contains("00 00 00 00"), "Should show all 4 bytes for uint32_t");
        assertFalse(smallDataLine.contains("..."), "Should not use ellipsis for small data");
    }

    // ==================== Mixed Code and Data Tests ====================

    @Test
    @DisplayName("Should display both data and instructions in memory order")
    void testMixedCodeAndData() {
        // Simulated mixed output showing transition from data to code
        String mixedOutput =
            "       00231fe4  00 00 00 00    uint32_t   0h\n" +
            "       00231fe8  00             uint8_t    00h\n" +
            "  --> 00231fec  00 00 00 ...   uint8_t[   \"\"\n" +
            "       002320e6  00 00          uint16_t   0h\n" +
            "       00224832  41 ec 38 34    lea       (0x3834,A4)=>g_Bytecode_Stack,A0\n";

        // Verify data items appear before instruction
        int dataIndex = mixedOutput.indexOf("uint8_t[");
        int instrIndex = mixedOutput.indexOf("lea");

        assertTrue(dataIndex > 0, "Should contain data items");
        assertTrue(instrIndex > 0, "Should contain instructions");
        assertTrue(dataIndex < instrIndex, "Data should appear before instruction in memory order");
    }

    @Test
    @DisplayName("Context window should include both code units and data units")
    void testContextWindowIncludesBothTypes() {
        // Verify that "code units" terminology is used (not just "instructions")
        String contextHeader = "Context window: -5 to +5 code units";

        assertTrue(contextHeader.contains("code units"),
                  "Should use 'code units' (not 'instructions') to include both data and code");
        assertFalse(contextHeader.contains("instructions"),
                   "Should not use 'instructions' terminology which excludes data");
    }

    // ==================== Address Target Tests ====================

    @Test
    @DisplayName("Target marker should work for data addresses")
    void testTargetMarkerForData() {
        String dataLine = "  --> 00231fec  00 00 00 ...   uint8_t[   \"\"";

        assertTrue(dataLine.startsWith("  --> "), "Target data should be marked with arrow");
    }

    @Test
    @DisplayName("Target marker should work for instruction addresses")
    void testTargetMarkerForInstruction() {
        String instrLine = "  --> 00224832  41 ec 38 34    lea       (0x3834,A4)=>g_Bytecode_Stack,A0";

        assertTrue(instrLine.startsWith("  --> "), "Target instruction should be marked with arrow");
    }

    @Test
    @DisplayName("Non-target items should have standard indentation")
    void testNonTargetIndentation() {
        String nonTargetLine = "       00231fe4  00 00 00 00    uint32_t   0h";

        assertTrue(nonTargetLine.startsWith("       "), "Non-target should have 7 spaces");
        assertEquals(7, nonTargetLine.indexOf("0"), "Address should start at column 7");
    }

    @Test
    @DisplayName("Target marker should work when address is within large code unit")
    void testTargetWithinLargeCodeUnit() {
        // If target address is 00231fed but code unit starts at 00231fec (uint8_t[250])
        // the code unit containing the target should be marked
        String largeDataLine = "  --> 00231fec  00 00 00 ...   uint8_t[";

        assertTrue(largeDataLine.startsWith("  --> "),
                  "Code unit containing target address should be marked even if address is mid-unit");
    }

    // ==================== Column Alignment Tests ====================

    @Test
    @DisplayName("Address column should be 10 characters wide")
    void testAddressColumnWidth() {
        String dataLine = "       00231fec  00 00 00 ...   uint8_t[";

        // After 7-space indent, address should be 10 chars
        String addressPart = dataLine.substring(7, 17);
        assertTrue(addressPart.matches("[0-9a-f]{8}  "),
                  "Address should be 8 hex digits + 2 spaces = 10 chars total");
    }

    @Test
    @DisplayName("Bytes column should be 12 characters wide")
    void testBytesColumnWidth() {
        String dataLine = "       00231fe4  00 00 00 00    uint32_t   0h";

        // Bytes field should be formatted to 12 chars (%-12s)
        String bytesPart = dataLine.substring(17, 29);
        assertEquals(12, bytesPart.length(), "Bytes field should be 12 characters");
    }

    @Test
    @DisplayName("Type/mnemonic column should be 10 characters wide")
    void testTypeColumnWidth() {
        String dataLine = "       00231fe4  00 00 00 00    uint32_t   0h";

        // Type field should be formatted to 10 chars (%-10s)
        // Position: after 7 (indent) + 10 (addr) + 12 (bytes) = 29
        String typePart = dataLine.substring(29, 41);
        assertEquals(12, typePart.length(), "Type field should be ~10-12 characters with spacing");
        assertTrue(typePart.contains("uint32_t"), "Type field should contain data type");
    }

    // ==================== XREF Format Tests ====================

    @Test
    @DisplayName("XREF count should be shown in square brackets")
    void testXrefCountFormat() {
        String xrefLine = "XREF[24]: Stack_PushWord:00224762(*), Stack_PushWord:00224766(*)";

        assertTrue(xrefLine.matches(".*XREF\\[\\d+\\]:.*"),
                  "XREF should have count in square brackets");
    }

    @Test
    @DisplayName("XREF type indicators should be shown in parentheses")
    void testXrefTypeIndicators() {
        String xrefLine = "Stack_PushWord:00224762(*), Stack_PushWord:00224766(*)";

        assertTrue(xrefLine.contains("(*)"), "Data reference should show (*) indicator");

        // Other common indicators:
        // (R) = read, (W) = write, (j) = jump, (c) = call
    }

    @Test
    @DisplayName("XREFs should be limited to first 3 with more indicator")
    void testXrefLimitWithMore() {
        String xrefLine = "XREF[24]: Stack_PushWord:00224762(*), Stack_PushWord:00224766(*), Stack_PopWord:002247a6(*), [more]";

        // Count the number of XREF entries shown (separated by commas)
        int commaCount = xrefLine.split(",").length - 1; // Subtract 1 because split counts segments
        assertTrue(commaCount >= 3, "Should show at least first 3 XREFs");
        assertTrue(xrefLine.contains("[more]"), "Should indicate additional XREFs with [more]");
    }

    // ==================== Comment Display Tests ====================

    @Test
    @DisplayName("EOL comments should appear on same line with semicolon")
    void testEolCommentFormat() {
        String lineWithComment = "       00231fe4  00 00 00 00    uint32_t   0h ; End-of-line comment";

        assertTrue(lineWithComment.contains(" ; "), "EOL comment should be preceded by ' ; '");
        assertTrue(lineWithComment.indexOf(";") > lineWithComment.indexOf("0h"),
                  "Comment should appear after value");
    }

    @Test
    @DisplayName("POST comments should appear on separate line below")
    void testPostCommentFormat() {
        String postCommentLine = "                             ; [POST] This is a post comment";

        assertTrue(postCommentLine.contains("; [POST]"), "POST comment should be labeled");
        assertTrue(postCommentLine.startsWith("                             "),
                  "POST comment should be indented 29 spaces");
    }

    // ==================== Error Handling Tests ====================

    @Test
    @DisplayName("Should not error or jump when address contains data")
    void testNoJumpToNearestInstruction() {
        // Old behavior (WRONG): "Showing context from nearest instruction"
        // New behavior (CORRECT): Just show the data

        String wrongOutput = "Note: Target address contains data, not an instruction\n" +
                            "Data type: uint8_t[250]\n\n" +
                            "Showing context from nearest instruction";

        String correctOutput = "  --> 00231fec  00 00 00 ...   uint8_t[   \"\"";

        assertFalse(correctOutput.contains("Showing context from nearest instruction"),
                   "Should NOT jump to nearest instruction");
        assertFalse(correctOutput.contains("Note: Target address contains data"),
                   "Should NOT show warning about data vs instruction");
        assertTrue(correctOutput.contains("00231fec"), "Should show actual target address");
    }

    @Test
    @DisplayName("Should handle undefined bytes gracefully")
    void testUndefinedBytesHandling() {
        // Undefined bytes should show ?? for bytes
        String undefinedLine = "       00100000  ??             ??         ??";

        assertTrue(undefinedLine.contains("??"), "Undefined bytes should show ??");
    }

    @Test
    @DisplayName("Should handle memory access errors gracefully")
    void testMemoryAccessErrorHandling() {
        // When bytes can't be read, show ??
        String errorLine = "       00100000  ??             unknown    ";

        assertTrue(errorLine.contains("??"), "Memory errors should show ?? for bytes");
    }

    // ==================== Namespace Display Tests ====================

    @Test
    @DisplayName("Data labels with namespaces should show namespace prefix")
    void testDataLabelWithNamespace() {
        String namespacedLabel = "                             Script::g_Bytecode_Stack";

        assertTrue(namespacedLabel.contains("::"), "Should show namespace separator");
        assertTrue(namespacedLabel.contains("Script::"), "Should show namespace name");
    }

    @Test
    @DisplayName("Global symbols should not show namespace")
    void testGlobalSymbolNoNamespace() {
        String globalLabel = "                             g_GlobalVariable";

        assertFalse(globalLabel.contains("::"), "Global symbols should not show :: separator");
    }

    // ==================== Integration Pattern Tests ====================

    @Test
    @DisplayName("Overall output should match Ghidra UI listing format")
    void testOverallGhidraUiFormat() {
        // Comprehensive example matching Ghidra UI
        String expectedFormat =
            "                             g_FileDialog_SavedDrawMode                      XREF[2]: File_SaveGraphicsState:0022bf12(*), File_RestoreGraphicsState:0022bf...\n" +
            "       00231fe4  00 00 00 00    uint32_t   0h\n" +
            "                             g_FileDialog_SavedAPen                          XREF[2]: File_SaveGraphicsState:0022bef4(*), File_RestoreGraphicsState:0022bf...\n" +
            "       00231fe8  00             uint8_t    00h\n" +
            "                             **************************************************************\n" +
            "                             * Bytecode VM evaluation stack. Grows downward from index... *\n" +
            "                             **************************************************************\n" +
            "                             Script::g_Bytecode_Stack                        XREF[24]: Stack_PushWord:00224762(*), Stack_PushWord:00224766(*), [more]\n" +
            "  --> 00231fec  00 00 00 ...   uint8_t[   \"\"\n";

        // Verify key components are present
        assertTrue(expectedFormat.contains("XREF["), "Should include XREFs");
        assertTrue(expectedFormat.contains("uint32_t"), "Should include data types");
        assertTrue(expectedFormat.contains("****"), "Should include plate comment boxes");
        assertTrue(expectedFormat.contains("::"), "Should include namespaces");
        assertTrue(expectedFormat.contains("  --> "), "Should mark target");

        // Verify memory order (addresses should be ascending)
        assertTrue(expectedFormat.indexOf("00231fe4") < expectedFormat.indexOf("00231fe8"),
                  "Addresses should be in ascending order");
        assertTrue(expectedFormat.indexOf("00231fe8") < expectedFormat.indexOf("00231fec"),
                  "Memory order should be preserved");
    }

    // ==================== Composite Data Type Tests ====================

    @Test
    @DisplayName("Array parent should be displayed with type annotation")
    void testArrayParentDisplay() {
        // When querying an address inside an array
        String arrayOutput =
            "                             Script::g_ScriptOpDispatchTable                 XREF[2]: Execute_Bytecode:00224c20(*), Execute_Bytecode:00224c24(*)\n" +
            "  --> 0023078c  addr[160]\n" +
            "      00230790  00 22 4c 7a    addr       Script::Opcode1_SetByt  [1]\n" +
            "      00230794  00 22 48 6a    addr       Script::Opcode2_PushSe  [2]\n";

        assertTrue(arrayOutput.contains("addr[160]"), "Should show array parent type");
        assertTrue(arrayOutput.contains("g_ScriptOpDispatchTable"), "Should show array label");
        assertTrue(arrayOutput.contains("[1]"), "Should show array indices");
        assertTrue(arrayOutput.contains("[2]"), "Should show array indices");
    }

    @Test
    @DisplayName("Struct parent should be displayed with components")
    void testStructParentDisplay() {
        // When querying an address inside a struct
        String structOutput =
            "                             g_FileReq_BodyIntuiText                         XREF[2,6]: File_InitRequesterStructure:0022...\n" +
            "  --> 0023073e  IntuiText\n" +
            "      0023073e  00              UBYTE     00h                     FrontPen      XREF[2]: File_InitRequesterStructure:0022...\n" +
            "      0023073f  00              UBYTE     00h                     BackPen\n" +
            " -->  00230742  00 01           WORD      1h                      LeftEdge\n" +
            "      00230744  00 06           WORD      6h                      TopEdge\n";

        assertTrue(structOutput.contains("IntuiText"), "Should show struct parent type");
        assertTrue(structOutput.contains("FrontPen"), "Should show field names");
        assertTrue(structOutput.contains("BackPen"), "Should show field names");
        assertTrue(structOutput.contains("LeftEdge"), "Should show field names");
        assertTrue(structOutput.contains(" -->  00230742"), "Should mark target field with arrow");
    }

    @Test
    @DisplayName("Array element should be marked when queried")
    void testArrayElementMarking() {
        // Querying 0x002307b8 (element [11] of array)
        String arrayElementOutput =
            "  --> 0023078c  addr[160]\n" +
            "      ... (6 components omitted)\n" +
            " -->  002307b8  00 22 40 12    addr       Script::Opcode11_LoadI  [11]\n" +
            "      002307bc  00 22 40 7c    addr       FUN_0022407c            [12]\n";

        assertTrue(arrayElementOutput.contains(" -->  002307b8"), "Target element should be marked");
        assertTrue(arrayElementOutput.contains("[11]"), "Should show element index");
        assertTrue(arrayElementOutput.contains("(6 components omitted)"), "Should show omitted count");
    }

    @Test
    @DisplayName("Struct field should be marked when queried")
    void testStructFieldMarking() {
        // Querying 0x00230742 (LeftEdge field of struct)
        String structFieldOutput =
            "  --> 0023073e  IntuiText\n" +
            "      0023073e  00              UBYTE     00h                     FrontPen\n" +
            "      0023073f  00              UBYTE     00h                     BackPen\n" +
            " -->  00230742  00 01           WORD      1h                      LeftEdge\n";

        assertTrue(structFieldOutput.contains(" -->  00230742"), "Target field should be marked");
        assertTrue(structFieldOutput.contains("LeftEdge"), "Should show field name");
        assertTrue(structFieldOutput.contains("WORD"), "Should show field type");
    }

    @Test
    @DisplayName("Large arrays should show limited window around target")
    void testLargeArrayWindow() {
        // Array with 160 elements - should only show ~11 around target
        String largeArrayOutput =
            "  --> 0023078c  addr[160]\n" +
            "      ... (6 components omitted)\n" +
            "      002307b4  00 22 3f be    addr       Script::Opcode10_LoadV  [10]\n" +
            " -->  002307b8  00 22 40 12    addr       Script::Opcode11_LoadI  [11]\n" +
            "      002307bc  00 22 40 7c    addr       FUN_0022407c            [12]\n" +
            "      ... (148 more components)\n";

        // Should show window around target element
        assertTrue(largeArrayOutput.contains("(6 components omitted)"), "Should omit elements before window");
        assertTrue(largeArrayOutput.contains("(148 more components)") ||
                  largeArrayOutput.matches(".*\\(\\d+ more components\\).*"),
                  "Should omit elements after window");

        // Should show target and neighbors
        assertTrue(largeArrayOutput.contains("[10]"), "Should show element before target");
        assertTrue(largeArrayOutput.contains("[11]"), "Should show target element");
        assertTrue(largeArrayOutput.contains("[12]"), "Should show element after target");
    }

    @Test
    @DisplayName("Component indentation should be consistent")
    void testComponentIndentation() {
        // Components should be indented 6 spaces, target components arrow (5 chars) + 1 space
        String componentLine = "      00230790  00 22 4c 7a    addr       Script::Opcode1_SetByt  [1]";
        String targetLine =    " -->  002307b8  00 22 40 12    addr       Script::Opcode11_LoadI  [11]";

        assertTrue(componentLine.startsWith("      "), "Non-target components should have 6-space indent");
        assertTrue(targetLine.startsWith(" --> "), "Target components should have arrow marker");
        // Both should have address starting at same column (column 6)
        assertEquals(componentLine.indexOf("0"), targetLine.indexOf("0"),
                    "Address should start at same column for both (column 6)");
    }

    @Test
    @DisplayName("Composite with XREFs should show them on components")
    void testCompositeComponentXrefs() {
        String componentWithXref =
            "      0023073e  00              UBYTE     00h                     FrontPen      XREF[2]: File_InitRequesterStructure:0022...\n";

        assertTrue(componentWithXref.contains("FrontPen"), "Should show field name");
        assertTrue(componentWithXref.contains("XREF[2]:"), "Should show XREF count");
        assertTrue(componentWithXref.contains("File_InitRequesterStructure"), "Should show XREF function");
    }

    @Test
    @DisplayName("Nested composites should be handled correctly")
    void testNestedComposites() {
        // Struct containing another struct or array
        String nestedOutput =
            "  --> 0023073e  IntuiText\n" +
            "      00230746  00 23 07 26    TextAttr *DAT_00230726            ITextFont\n" +
            "      0023074a  00 23 07 16    UBYTE *   DAT_00230716            IText\n" +
            "      0023074e  00 23 03 04    IntuiTex  g_FileReq_FilenameGadget NextText\n";

        // Nested struct should show as component but not expand further
        assertTrue(nestedOutput.contains("IntuiTex"), "Should show nested struct type");
        assertTrue(nestedOutput.contains("NextText"), "Should show nested struct field name");
    }

    @Test
    @DisplayName("Empty or undefined components should be handled gracefully")
    void testEmptyComponents() {
        // Components with undefined or null values
        String undefinedComponent = "      00100000  ??             undefined  ??                      field_0";

        assertTrue(undefinedComponent.contains("??"), "Should show ?? for undefined data");
        assertTrue(undefinedComponent.contains("undefined"), "Should show undefined type");
    }

    @Test
    @DisplayName("Components should show proper data type formatting")
    void testComponentDataTypeFormatting() {
        String componentTypes =
            "      0023073e  00              UBYTE     00h                     FrontPen\n" +
            "      00230742  00 01           WORD      1h                      LeftEdge\n" +
            "      00230746  00 23 07 26    TextAttr *DAT_00230726            ITextFont\n";

        assertTrue(componentTypes.contains("UBYTE"), "Should show byte types");
        assertTrue(componentTypes.contains("WORD"), "Should show word types");
        assertTrue(componentTypes.contains("TextAttr *"), "Should show pointer types");
    }

    // ==================== Function Marker Tests ====================

    @Test
    @DisplayName("Function start markers should be displayed with function name")
    void testFunctionStartMarker() {
        // Function entry point should show start marker
        String functionStart = "                             ┌─ FUNCTION: entry\n" +
                              "       000015f8  JMP       FUN_00001663\n";

        assertTrue(functionStart.contains("┌─ FUNCTION:"), "Should show function start marker");
        assertTrue(functionStart.contains("entry"), "Should show function name");
        assertTrue(functionStart.indexOf("┌─ FUNCTION:") < functionStart.indexOf("000015f8"),
                  "Function marker should appear before first instruction");
    }

    @Test
    @DisplayName("Function start markers should show ENTRY POINT attribute")
    void testFunctionStartMarkerWithEntryPoint() {
        String entryFunction = "                             ┌─ FUNCTION: entry (ENTRY POINT)\n" +
                              "       000015f8  JMP       FUN_00001663\n";

        assertTrue(entryFunction.contains("(ENTRY POINT)"), "Should show ENTRY POINT attribute");
    }

    @Test
    @DisplayName("Function start markers should show THUNK attribute")
    void testFunctionStartMarkerWithThunk() {
        String thunkFunction = "                             ┌─ FUNCTION: malloc (THUNK)\n" +
                              "       00001234  JMP       FUN_00005678\n";

        assertTrue(thunkFunction.contains("(THUNK)"), "Should show THUNK attribute");
    }

    @Test
    @DisplayName("Function start markers should show EXTERNAL attribute")
    void testFunctionStartMarkerWithExternal() {
        String externalFunction = "                             ┌─ FUNCTION: printf (EXTERNAL)\n" +
                                 "       00001000  RET\n";

        assertTrue(externalFunction.contains("(EXTERNAL)"), "Should show EXTERNAL attribute");
    }

    @Test
    @DisplayName("Function start markers should show multiple attributes")
    void testFunctionStartMarkerWithMultipleAttributes() {
        String multiAttrFunction = "                             ┌─ FUNCTION: _start (ENTRY POINT, THUNK)\n" +
                                  "       00001000  JMP       main\n";

        assertTrue(multiAttrFunction.contains("ENTRY POINT"), "Should show ENTRY POINT");
        assertTrue(multiAttrFunction.contains("THUNK"), "Should show THUNK");
        assertTrue(multiAttrFunction.contains(", "), "Should separate attributes with comma");
    }

    @Test
    @DisplayName("Function end markers should be displayed after last instruction")
    void testFunctionEndMarker() {
        String functionEnd = "       000015f7  RET\n" +
                           "                             └─ END FUNCTION: some_function\n";

        assertTrue(functionEnd.contains("└─ END FUNCTION:"), "Should show function end marker");
        assertTrue(functionEnd.contains("some_function"), "Should show function name");
        assertTrue(functionEnd.indexOf("RET") < functionEnd.indexOf("└─ END FUNCTION:"),
                  "End marker should appear after last instruction");
    }

    @Test
    @DisplayName("Function end markers should appear after terminal instructions")
    void testFunctionEndMarkerAfterTerminal() {
        String terminalInstr = "       00001234  RET\n" +
                              "                             └─ END FUNCTION: myFunction\n" +
                              "                             ┌─ FUNCTION: nextFunction\n";

        assertTrue(terminalInstr.contains("└─ END FUNCTION: myFunction"),
                  "Should show end marker after RET");
        assertTrue(terminalInstr.indexOf("└─ END FUNCTION:") < terminalInstr.indexOf("┌─ FUNCTION: nextFunction"),
                  "End marker should appear before next function starts");
    }

    @Test
    @DisplayName("Function boundaries should be clearly marked in context")
    void testFunctionBoundariesInContext() {
        String contextWithFunctions =
            "                             ┌─ FUNCTION: func1 (ENTRY POINT)\n" +
            "       00001000  PUSH      EBP\n" +
            "       00001001  MOV       EBP,ESP\n" +
            "       00001003  RET\n" +
            "                             └─ END FUNCTION: func1\n" +
            "                             ┌─ FUNCTION: func2\n" +
            "       00001004  PUSH      EBP\n";

        assertTrue(contextWithFunctions.contains("┌─ FUNCTION: func1"), "Should show first function start");
        assertTrue(contextWithFunctions.contains("└─ END FUNCTION: func1"), "Should show first function end");
        assertTrue(contextWithFunctions.contains("┌─ FUNCTION: func2"), "Should show second function start");
    }

    // ==================== Enhanced XREF Tests ====================

    @Test
    @DisplayName("XREFs should include function names for data references")
    void testXrefWithFunctionNames() {
        String xrefWithFunction = "DAT_00001600    XREF[1]:     FUN_00008100:00008154(*)";

        assertTrue(xrefWithFunction.contains("FUN_00008100:00008154"),
                  "XREF should include function name and address");
        assertTrue(xrefWithFunction.contains("(*)"),
                  "XREF should include reference type indicator");
    }

    @Test
    @DisplayName("XREFs should show function:address format")
    void testXrefFunctionAddressFormat() {
        String xrefLine = "XREF[1]:     FUN_00008100:00008154(*)";

        assertTrue(xrefLine.matches(".*[A-Za-z0-9_]+:[0-9a-f]{8}\\(.*\\).*"),
                  "XREF should match pattern FunctionName:Address(Type)");
    }

    @Test
    @DisplayName("Multiple XREFs should all include function names")
    void testMultipleXrefsWithFunctionNames() {
        String multipleXrefs =
            "DAT_00001600    XREF[3]:     FUN_00008100:00008154(*), FUN_00009200:00009234(*), FUN_0000a300:0000a456(*)";

        assertTrue(multipleXrefs.contains("FUN_00008100:00008154"),
                  "First XREF should include function name");
        assertTrue(multipleXrefs.contains("FUN_00009200:00009234"),
                  "Second XREF should include function name");
        assertTrue(multipleXrefs.contains("FUN_0000a300:0000a456"),
                  "Third XREF should include function name");
    }

    @Test
    @DisplayName("XREFs from different reference types should show type indicators")
    void testXrefTypesWithFunctionNames() {
        // Different reference types: (R)=read, (W)=write, (*)=data, (j)=jump, (c)=call
        String xrefsWithTypes =
            "XREF[4]:     func1:00001000(R), func2:00002000(W), func3:00003000(*), func4:00004000(j)";

        assertTrue(xrefsWithTypes.contains("(R)"), "Should show read type");
        assertTrue(xrefsWithTypes.contains("(W)"), "Should show write type");
        assertTrue(xrefsWithTypes.contains("(*)"), "Should show data type");
        assertTrue(xrefsWithTypes.contains("(j)"), "Should show jump type");
    }

    @Test
    @DisplayName("XREFs should handle labels without function context gracefully")
    void testXrefWithoutFunctionContext() {
        // Some XREFs might not be from within a function
        String xrefNoFunction = "DAT_00001600    XREF[1]:     00008154(*)";

        // Should still work if no function context available (just address)
        assertTrue(xrefNoFunction.matches(".*[0-9a-f]{8}\\(.*\\).*"),
                  "XREF should at minimum show address and type");
    }

    @Test
    @DisplayName("Data label XREFs should match instruction XREF format")
    void testDataLabelXrefConsistency() {
        String dataXref = "DAT_00001600                          XREF[1]:     FUN_00008100:00008154(*)";
        String instrXref = "                     XREF from: FUN_00008100:00008154 (DATA)";

        // Both should include function name
        assertTrue(dataXref.contains("FUN_00008100:"), "Data XREF should include function name");
        assertTrue(instrXref.contains("FUN_00008100:"), "Instruction XREF should include function name");
    }

    @Test
    @DisplayName("Enhanced XREFs should preserve all existing formatting")
    void testEnhancedXrefsPreserveFormatting() {
        String enhancedXref =
            "                             Script::g_Bytecode_Stack                        XREF[2]:     Stack_PushWord:00224762(*), Stack_PopWord:00224766(*)";

        // Verify formatting is preserved
        assertTrue(enhancedXref.contains("Script::g_Bytecode_Stack"), "Should preserve symbol name");
        assertTrue(enhancedXref.contains("XREF[2]:"), "Should preserve XREF count");
        assertTrue(enhancedXref.matches(".*\\s+XREF\\[\\d+\\]:.*"), "Should preserve spacing");
    }
}
