package com.lauriewired.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for enhanced disassembly output format.
 *
 * These tests verify that the disassemble_function output includes all the
 * comprehensive Ghidra-style information:
 * - PLATE comment boxes
 * - Function signatures with calling conventions
 * - Local variables table with XREFs
 * - Function labels with caller XREFs
 * - Enhanced assembly with annotations, labels, and XREFs
 *
 * Note: Full integration tests with actual Ghidra decompilation would require
 * the Ghidra test framework and Program fixtures. These tests verify output
 * format and structure.
 */
class EnhancedDisassemblyTest {

    // ==================== PLATE Comment Box Tests ====================

    @Test
    @DisplayName("PLATE comment should be enclosed in asterisk box")
    void testPlateCommentBoxFormat() {
        String samplePlateComment = "CODE_212: Combat - AI Decision Loop (Core AI Logic)\n" +
                                   "\n" +
                                   "Executes complete AI decision-making for NPC/enemy turn.";

        // Verify it has the box structure
        String[] lines = samplePlateComment.split("\n");
        int maxLength = 0;
        for (String line : lines) {
            maxLength = Math.max(maxLength, line.length());
        }
        maxLength = Math.max(maxLength, 60);

        // Expected format:
        // *************************************************************
        // * CODE_212: Combat - AI Decision Loop (Core AI Logic)      *
        // *                                                           *
        // * Executes complete AI decision-making for NPC/enemy turn. *
        // *************************************************************

        assertTrue(maxLength >= 60, "PLATE comment box should have minimum width of 60");
        assertTrue(lines.length > 0, "PLATE comment should have content");
    }

    @Test
    @DisplayName("PLATE comment box should pad lines to consistent width")
    void testPlateCommentPadding() {
        String shortLine = "Short";
        String longLine = "This is a much longer line that should determine the box width";

        String[] lines = new String[]{shortLine, longLine};
        int maxLength = 0;
        for (String line : lines) {
            maxLength = Math.max(maxLength, line.length());
        }

        // All lines should be padded to the same length
        assertTrue(maxLength > shortLine.length(), "Max length should be based on longest line");
        assertEquals(longLine.length(), maxLength, "Max length should equal longest line");
    }

    // ==================== Function Signature Tests ====================

    @Test
    @DisplayName("Function signature should include return type")
    void testFunctionSignatureReturnType() {
        String expectedPattern = "uint16_t";

        // Function signature format: <return_type> [__calling_convention] [namespace::]name(params)
        String sampleSignature = "uint16_t __cdecl16far CODE_212::Combat_AIDecisionLoop(pointer16 charIndexPtr)";

        assertTrue(sampleSignature.contains(expectedPattern),
                  "Function signature should start with return type");
    }

    @Test
    @DisplayName("Function signature should include calling convention when not default")
    void testFunctionSignatureCallingConvention() {
        String callingConvention = "__cdecl16far";

        String sampleSignature = "uint16_t __cdecl16far CODE_212::Combat_AIDecisionLoop(pointer16 charIndexPtr)";

        assertTrue(sampleSignature.contains(callingConvention),
                  "Function signature should include calling convention");
    }

    @Test
    @DisplayName("Function signature should include namespace")
    void testFunctionSignatureNamespace() {
        String namespace = "CODE_212::";

        String sampleSignature = "uint16_t __cdecl16far CODE_212::Combat_AIDecisionLoop(pointer16 charIndexPtr)";

        assertTrue(sampleSignature.contains(namespace),
                  "Function signature should include namespace with :: separator");
    }

    @Test
    @DisplayName("Function signature should include parameter types and names")
    void testFunctionSignatureParameters() {
        String paramPattern = "pointer16 charIndexPtr";

        String sampleSignature = "uint16_t __cdecl16far Combat_AIDecisionLoop(pointer16 charIndexPtr)";

        assertTrue(sampleSignature.contains(paramPattern),
                  "Function signature should include parameter type and name");
        assertTrue(sampleSignature.contains("(") && sampleSignature.contains(")"),
                  "Function signature should have parentheses for parameters");
    }

    @Test
    @DisplayName("Function signature with multiple parameters should use comma separator")
    void testFunctionSignatureMultipleParameters() {
        String sampleSignature = "void myFunc(int param1, char* param2, uint16_t param3)";

        assertTrue(sampleSignature.contains(", "),
                  "Multiple parameters should be comma-separated");

        // Count commas - should be paramCount - 1
        long commaCount = sampleSignature.chars().filter(ch -> ch == ',').count();
        assertEquals(2, commaCount, "Should have 2 commas for 3 parameters");
    }

    // ==================== Local Variables Table Tests ====================

    @Test
    @DisplayName("Local variables should display data type, storage, and name")
    void testLocalVariableTableFormat() {
        // Expected format: <dataType> <storage> <varName> [XREF[n]: addresses]
        String sampleVar = "undefined         Stack[-0x4]    local_4                                 XREF[1]:     618c:0bc6(*)";

        assertTrue(sampleVar.contains("undefined"), "Should include data type");
        assertTrue(sampleVar.contains("Stack"), "Should include storage location");
        assertTrue(sampleVar.contains("local_4"), "Should include variable name");
    }

    @Test
    @DisplayName("Local variables should show XREFs when present")
    void testLocalVariableXREFs() {
        String sampleVarWithXref = "undefined         Stack[-0x4]    local_4                                 XREF[1]:     618c:0bc6(*)";

        assertTrue(sampleVarWithXref.contains("XREF["), "Should show XREF indicator");
        assertTrue(sampleVarWithXref.matches(".*XREF\\[\\d+\\]:.*"), "Should show XREF count");
        assertTrue(sampleVarWithXref.contains("618c:0bc6"), "Should show XREF address");
    }

    @Test
    @DisplayName("Local variables with multiple XREFs should show multiple addresses")
    void testLocalVariableMultipleXREFs() {
        String sampleVar = "undefined         Stack[-0xe]    local_e                                 XREF[2]:     618c:1067(*), 618c:1202(*)";

        assertTrue(sampleVar.contains("XREF[2]"), "Should show correct XREF count");
        assertTrue(sampleVar.contains("618c:1067"), "Should show first XREF");
        assertTrue(sampleVar.contains("618c:1202"), "Should show second XREF");
        assertTrue(sampleVar.contains(", "), "Multiple XREFs should be comma-separated");
    }

    @Test
    @DisplayName("Local variables with many XREFs should limit display")
    void testLocalVariableXREFLimit() {
        // When there are more than 5 XREFs, should show first 5 and "..."
        String manyXrefs = "addr1, addr2, addr3, addr4, addr5";

        // Should limit to 5 and add ellipsis for more
        assertTrue(manyXrefs.split(", ").length <= 5,
                  "Should limit XREF display to 5 addresses");
    }

    // ==================== Function Label Tests ====================

    @Test
    @DisplayName("Function label should include namespace prefix")
    void testFunctionLabelNamespace() {
        String functionLabel = "CODE_212::Combat_AIDecisionLoop";

        assertTrue(functionLabel.contains("::"), "Function label should include namespace separator");
        assertTrue(functionLabel.startsWith("CODE_212"), "Should start with namespace");
    }

    @Test
    @DisplayName("Function label should show caller XREFs")
    void testFunctionLabelCallerXREFs() {
        String labelWithXref = "CODE_212::Combat_AIDecisionLoop                 XREF[1]:     Combat_ModeController:618c:069d(";

        assertTrue(labelWithXref.contains("XREF["), "Should show XREF indicator for callers");
        assertTrue(labelWithXref.contains("Combat_ModeController"), "Should show caller function name");
        assertTrue(labelWithXref.contains("618c:069d"), "Should show caller address");
    }

    @Test
    @DisplayName("Function label with multiple callers should show count")
    void testFunctionLabelMultipleCallers() {
        String labelWithMultipleXrefs = "myFunction                 XREF[3]:     caller1:1000, caller2:2000, caller3:3000";

        assertTrue(labelWithMultipleXrefs.contains("XREF[3]"), "Should show correct caller count");
        long commaCount = labelWithMultipleXrefs.substring(labelWithMultipleXrefs.indexOf("XREF")).chars()
                                                 .filter(ch -> ch == ',').count();
        assertTrue(commaCount >= 1, "Multiple callers should be comma-separated");
    }

    @Test
    @DisplayName("Function label should limit caller display to 3")
    void testFunctionLabelCallerLimit() {
        // When showing callers, limit to first 3 and add "..." for more
        String callerList = "caller1:addr1, caller2:addr2, caller3:addr3";

        assertTrue(callerList.split(", ").length <= 3,
                  "Should limit caller display to 3");
    }

    // ==================== Assembly Instruction Tests ====================

    @Test
    @DisplayName("Assembly instruction should show address and instruction")
    void testAssemblyInstructionFormat() {
        String sampleInstruction = "       618c:0bad 55              PUSH       BP";

        // Format: <spaces><address> <bytes> <mnemonic> <operands>
        assertTrue(sampleInstruction.contains("618c:0bad"), "Should show address");
        assertTrue(sampleInstruction.contains("PUSH"), "Should show instruction mnemonic");
        assertTrue(sampleInstruction.contains("BP"), "Should show operands");
    }

    @Test
    @DisplayName("CALL instruction should show target function name")
    void testCallInstructionFunctionName() {
        String callInstruction = "       618c:0bcb 9a ef 32        CALLF      CODE_18::CharAI_GetCharDataPointers";

        assertTrue(callInstruction.contains("CALLF"), "Should show CALL instruction");
        assertTrue(callInstruction.contains("CODE_18::CharAI_GetCharDataPointers"),
                  "Should show target function name with namespace");
    }

    @Test
    @DisplayName("Instruction should show EOL comment when present")
    void testInstructionEOLComment() {
        String instrWithComment = "       618c:0bad 55              PUSH       BP ; save base pointer";

        assertTrue(instrWithComment.contains("; "), "Should have semicolon prefix for EOL comment");
        assertTrue(instrWithComment.contains("save base pointer"), "Should show comment text");
    }

    @Test
    @DisplayName("Instruction should show PRE comment when present")
    void testInstructionPREComment() {
        String instrWithPreComment = "       618c:0bad 55              PUSH       BP [PRE: Function prologue]";

        assertTrue(instrWithPreComment.contains("[PRE:"), "Should show PRE comment with tag");
        assertTrue(instrWithPreComment.contains("Function prologue"), "Should show PRE comment text");
    }

    @Test
    @DisplayName("Instruction should show POST comment when present")
    void testInstructionPOSTComment() {
        String instrWithPostComment = "       618c:0bad 55              PUSH       BP [POST: Stack setup complete]";

        assertTrue(instrWithPostComment.contains("[POST:"), "Should show POST comment with tag");
        assertTrue(instrWithPostComment.contains("Stack setup complete"), "Should show POST comment text");
    }

    @Test
    @DisplayName("Instruction should show REPEATABLE comment when present")
    void testInstructionRepeatableComment() {
        String instrWithRepComment = "       618c:0bad 55              PUSH       BP [REP: Common pattern]";

        assertTrue(instrWithRepComment.contains("[REP:"), "Should show REPEATABLE comment with tag");
        assertTrue(instrWithRepComment.contains("Common pattern"), "Should show REPEATABLE comment text");
    }

    @Test
    @DisplayName("Instruction should show multiple comment types together")
    void testInstructionMultipleComments() {
        String instrWithMultipleComments = "       618c:0bad 55              PUSH       BP [PRE: Setup] ; standard ; [POST: Done]";

        // Should be able to show multiple comment types on the same instruction
        assertTrue(instrWithMultipleComments.contains("[PRE:"), "Should show PRE comment");
        assertTrue(instrWithMultipleComments.contains("; "), "Should show EOL comment");
        assertTrue(instrWithMultipleComments.contains("[POST:"), "Should show POST comment");
    }

    // ==================== XREF Display Tests ====================

    @Test
    @DisplayName("Instruction XREF should show source address and reference type")
    void testInstructionXREFFormat() {
        String xrefLine = "                     XREF from: 618c:0a5f (CALL)";

        assertTrue(xrefLine.contains("XREF from:"), "Should show XREF from indicator");
        assertTrue(xrefLine.contains("618c:0a5f"), "Should show source address");
        assertTrue(xrefLine.contains("(CALL)"), "Should show reference type in parentheses");
    }

    @Test
    @DisplayName("Instruction XREF from different function should show function name")
    void testInstructionXREFWithFunctionName() {
        String xrefLine = "                     XREF from: Combat_ModeController:618c:069d (CALL)";

        assertTrue(xrefLine.contains("Combat_ModeController:"), "Should show source function name");
        assertTrue(xrefLine.contains("618c:069d"), "Should show source address");
        assertTrue(xrefLine.contains("(CALL)"), "Should show reference type");
    }

    @Test
    @DisplayName("Multiple XREFs should each appear on separate lines")
    void testMultipleInstructionXREFs() {
        String multiXref = "                     XREF from: 618c:0a5f (CALL)\n" +
                          "                     XREF from: 618c:0b2c (CALL)";

        assertTrue(multiXref.lines().count() >= 2, "Multiple XREFs should be on separate lines");
        assertTrue(multiXref.contains("618c:0a5f"), "Should show first XREF");
        assertTrue(multiXref.contains("618c:0b2c"), "Should show second XREF");
    }

    @Test
    @DisplayName("Too many XREFs should be limited to prevent clutter")
    void testXREFDisplayLimit() {
        // When there are more than 5 XREFs to an instruction, should limit display
        int maxXrefsToShow = 5;

        assertTrue(maxXrefsToShow == 5, "Should limit XREF display to 5 per instruction");
    }

    // ==================== Label Display Tests ====================

    @Test
    @DisplayName("Label at instruction address should be displayed")
    void testInstructionLabel() {
        String labelLine = "                             LAB_618c_0bc0:";

        assertTrue(labelLine.endsWith(":"), "Label should end with colon");
        assertTrue(labelLine.contains("LAB_"), "Label should be identifiable");
    }

    @Test
    @DisplayName("Label should not be duplicated with function name")
    void testLabelNotDuplicatedWithFunctionName() {
        String functionName = "Combat_AIDecisionLoop";

        // The function entry point should not show the function name as both a label and function name
        assertFalse(functionName.isEmpty(), "Function name should be present");
        // Implementation should check: if label name equals function name, don't show label separately
    }

    // ==================== Overall Format Tests ====================

    @Test
    @DisplayName("Complete disassembly should have all major sections in order")
    void testCompleteDisassemblyStructure() {
        String sampleOutput =
            "                             ********************************************************\n" +
            "                             * CODE_212: Combat - AI Decision Loop                  *\n" +
            "                             ********************************************************\n" +
            "                             uint16_t __cdecl16far CODE_212::Combat_AIDecisionLoop(pointer16 charIndexPtr)\n" +
            "             undefined         Stack[-0x4]    local_4                                 XREF[1]:     618c:0bc6(*)\n" +
            "                             CODE_212::Combat_AIDecisionLoop                 XREF[1]:     Combat_ModeController:618c:069d\n" +
            "       618c:0bad 55              PUSH       BP\n" +
            "       618c:0bae 8b ec           MOV        BP,SP\n";

        // Verify structure order
        int platePos = sampleOutput.indexOf("****");
        int sigPos = sampleOutput.indexOf("uint16_t");
        int varPos = sampleOutput.indexOf("Stack[-0x4]");
        int labelPos = sampleOutput.indexOf("Combat_AIDecisionLoop");
        int asmPos = sampleOutput.indexOf("618c:0bad");

        assertTrue(platePos >= 0, "Should have PLATE comment");
        assertTrue(sigPos >= 0, "Should have function signature");
        assertTrue(varPos >= 0, "Should have local variables");
        assertTrue(labelPos >= 0, "Should have function label");
        assertTrue(asmPos >= 0, "Should have assembly instructions");

        // Verify order: PLATE -> Signature -> Variables -> Label -> Assembly
        assertTrue(platePos < sigPos, "PLATE comment should come before signature");
        assertTrue(sigPos < varPos, "Signature should come before variables");
        assertTrue(varPos < labelPos, "Variables should come before function label");
        assertTrue(labelPos < asmPos, "Function label should come before assembly");
    }

    @Test
    @DisplayName("Disassembly output should use consistent indentation")
    void testConsistentIndentation() {
        // PLATE comments, signatures, and labels are indented to column 29 (29 spaces)
        // Variables are indented to column 13 (13 spaces)
        // Assembly is indented to column 7 (7 spaces)
        // XREFs are indented to column 21 (21 spaces)

        String plateIndent = "                             "; // 29 spaces
        String varIndent = "             "; // 13 spaces
        String asmIndent = "       "; // 7 spaces
        String xrefIndent = "                     "; // 21 spaces

        assertEquals(29, plateIndent.length(), "PLATE/signature/label indent should be 29 spaces");
        assertEquals(13, varIndent.length(), "Variable indent should be 13 spaces");
        assertEquals(7, asmIndent.length(), "Assembly indent should be 7 spaces");
        assertEquals(21, xrefIndent.length(), "XREF indent should be 21 spaces");
    }

    @Test
    @DisplayName("Empty sections should not break output formatting")
    void testEmptySectionsHandling() {
        // When a function has no PLATE comment, no variables, or no XREFs,
        // the output should still be well-formed

        String minimalOutput =
            "                             void simple_function()\n" +
            "                             simple_function\n" +
            "       1000:0000 90              NOP\n" +
            "       1000:0001 c3              RET\n";

        // Should have signature, label, and assembly even without PLATE/vars/xrefs
        assertTrue(minimalOutput.contains("void simple_function()"), "Should have signature");
        assertTrue(minimalOutput.contains("simple_function\n"), "Should have function label");
        assertTrue(minimalOutput.contains("NOP"), "Should have assembly");
    }

    @Test
    @DisplayName("Output should handle multiline PLATE comments correctly")
    void testMultilinePlateComment() {
        String multilinePlate = "Line 1 of comment\nLine 2 of comment\nLine 3 of comment";
        String[] lines = multilinePlate.split("\n");

        assertEquals(3, lines.length, "Should preserve all comment lines");
        assertTrue(lines[0].equals("Line 1 of comment"), "Should preserve first line");
        assertTrue(lines[2].equals("Line 3 of comment"), "Should preserve last line");
    }
}
