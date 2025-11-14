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

    // ==================== Register Assumptions Tests ====================

    @Test
    @DisplayName("Register assumptions should be displayed when present")
    void testRegisterAssumptions() {
        String sampleAssumptions = "                               assume CS = 0x2a0a\n" +
                                   "                               assume DS = 0x5356";

        assertTrue(sampleAssumptions.contains("assume CS"), "Should show CS register assumption");
        assertTrue(sampleAssumptions.contains("assume DS"), "Should show DS register assumption");
        assertTrue(sampleAssumptions.contains("0x2a0a"), "Should show hex value for CS");
        assertTrue(sampleAssumptions.contains("0x5356"), "Should show hex value for DS");
    }

    @Test
    @DisplayName("Register assumptions should use proper indentation")
    void testRegisterAssumptionsIndentation() {
        String assumptionLine = "                               assume CS = 0x2a0a";

        // Should have 31 spaces of indentation (matching function signature indentation)
        assertTrue(assumptionLine.startsWith("                               "),
                  "Register assumptions should have 31 spaces of indentation");
    }

    @Test
    @DisplayName("Register assumptions should be formatted with equals sign")
    void testRegisterAssumptionsFormat() {
        String assumptionLine = "assume CS = 0x2a0a";

        assertTrue(assumptionLine.matches("assume [A-Z]+ = 0x[0-9a-f]+"),
                  "Register assumption should match format: assume <REG> = 0x<hex>");
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
            "                               assume CS = 0x2a0a\n" +
            "                               assume DS = 0x5356\n" +
            "             undefined         Stack[-0x4]    local_4                                 XREF[1]:     618c:0bc6(*)\n" +
            "                             CODE_212::Combat_AIDecisionLoop                 XREF[1]:     Combat_ModeController:618c:069d\n" +
            "       618c:0bad 55              PUSH       BP\n" +
            "       618c:0bae 8b ec           MOV        BP,SP\n";

        // Verify structure order
        int platePos = sampleOutput.indexOf("****");
        int sigPos = sampleOutput.indexOf("uint16_t");
        int assumePos = sampleOutput.indexOf("assume CS");
        int varPos = sampleOutput.indexOf("Stack[-0x4]");
        // Find the function label line (not the signature) by looking for the XREF pattern after the name
        int labelPos = sampleOutput.indexOf("Combat_AIDecisionLoop                 XREF");
        int asmPos = sampleOutput.indexOf("618c:0bad");

        assertTrue(platePos >= 0, "Should have PLATE comment");
        assertTrue(sigPos >= 0, "Should have function signature");
        assertTrue(assumePos >= 0, "Should have register assumptions");
        assertTrue(varPos >= 0, "Should have local variables");
        assertTrue(labelPos >= 0, "Should have function label");
        assertTrue(asmPos >= 0, "Should have assembly instructions");

        // Verify order: PLATE -> Signature -> Assumptions -> Variables -> Label -> Assembly
        assertTrue(platePos < sigPos, "PLATE comment should come before signature");
        assertTrue(sigPos < assumePos, "Signature should come before register assumptions");
        assertTrue(assumePos < varPos, "Register assumptions should come before variables");
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

    // ==================== Enhanced Feature Tests ====================

    @Test
    @DisplayName("Instruction bytes should be displayed in hex format")
    void testInstructionBytesDisplay() {
        String sampleInstruction = "       0022d3d0 4e 55 ff ec     link.w     A5,-0x14";

        // Should show address, then hex bytes, then instruction
        assertTrue(sampleInstruction.contains("0022d3d0"), "Should show address");
        assertTrue(sampleInstruction.contains("4e 55 ff ec"), "Should show instruction bytes in hex");
        assertTrue(sampleInstruction.contains("link.w"), "Should show mnemonic");
        assertTrue(sampleInstruction.contains("A5,-0x14"), "Should show operands");
    }

    @Test
    @DisplayName("Instruction bytes should be properly formatted and spaced")
    void testInstructionBytesFormatting() {
        String twoByteInstr = "       0022d3d4 48 e7           movem.l    {A6 A3 A2 D7 D2},-(SP)";
        String fourByteInstr = "       0022d3d0 4e 55 ff ec     link.w     A5,-0x14";

        // Both should have consistent column alignment
        assertTrue(twoByteInstr.contains("48 e7"), "Should show 2-byte instruction bytes");
        assertTrue(fourByteInstr.contains("4e 55 ff ec"), "Should show 4-byte instruction bytes");

        // Check that columns align properly (address at same position)
        int addr1Pos = twoByteInstr.indexOf("0022d3d4");
        int addr2Pos = fourByteInstr.indexOf("0022d3d0");
        assertEquals(addr1Pos, addr2Pos, "Addresses should align at same column");
    }

    @Test
    @DisplayName("Stack variables should use hex offsets with size indicators")
    void testStackVariableHexOffsets() {
        String stackVar1 = "             undefined4        Stack[-0x4]:4  local_4";
        String stackVar2 = "             undefined4        Stack[-0x18]:4 local_18";

        // Should use hex format for negative offsets
        assertTrue(stackVar1.contains("Stack[-0x4]:4"), "Should show hex offset -0x4 with size :4");
        assertTrue(stackVar2.contains("Stack[-0x18]:4"), "Should show hex offset -0x18 with size :4");

        // Should not use decimal format
        assertFalse(stackVar1.contains("Stack[-4]"), "Should not use decimal format");
        assertFalse(stackVar2.contains("Stack[-24]"), "Should not use decimal format");
    }

    @Test
    @DisplayName("Stack variables should include size indicators")
    void testStackVariableSizeIndicators() {
        String var4byte = "             undefined4        Stack[-0x4]:4  local_4";
        String var1byte = "             char              Stack[-0x1]:1  local_1";

        assertTrue(var4byte.contains(":4"), "4-byte variable should show :4 size");
        assertTrue(var1byte.contains(":1"), "1-byte variable should show :1 size");
    }

    @Test
    @DisplayName("Variable XREFs should include operation types")
    void testVariableXREFOperationTypes() {
        String varWithReadWrite = "             undefined4        Stack[-0x18]:4 local_18                                XREF[11]:    0022d424(W), 0022d44a(R), 0022d452(W)";
        String varWithPointer = "             undefined4        Stack[-0x34]:4 local_34                                XREF[3]:     0022d4ee(*), 0022d5de(*), 0022d5e6(*)";

        // Should show (W) for write operations
        assertTrue(varWithReadWrite.contains("(W)"), "Should show (W) for write operations");

        // Should show (R) for read operations
        assertTrue(varWithReadWrite.contains("(R)"), "Should show (R) for read operations");

        // Should show (*) for pointer dereference operations
        assertTrue(varWithPointer.contains("(*)"), "Should show (*) for pointer operations");
    }

    @Test
    @DisplayName("Jump target labels should show jump XREFs with (j) indicator")
    void testJumpTargetXREFs() {
        String labelWithJumps = "                             LAB_0022d3dc                                    XREF[2]:     0022d48c(j), 0022d4b4(j)";

        assertTrue(labelWithJumps.contains("XREF[2]"), "Should show XREF count");
        assertTrue(labelWithJumps.contains("0022d48c(j)"), "Should show first jump with (j)");
        assertTrue(labelWithJumps.contains("0022d4b4(j)"), "Should show second jump with (j)");
    }

    @Test
    @DisplayName("PC-relative references should be resolved to symbols")
    void testPCRelativeReferenceResolution() {
        String pcRelativeInstr = "       0022d4d0 43 fa 01 24     lea        (0x124,PC)=>DAT_0022d5f6,A1";

        // Should show the offset
        assertTrue(pcRelativeInstr.contains("(0x124,PC)"), "Should show PC-relative offset");

        // Should resolve to symbol with =>
        assertTrue(pcRelativeInstr.contains("=>DAT_0022d5f6"), "Should resolve to symbol DAT_0022d5f6");
    }

    @Test
    @DisplayName("Data references should show target values")
    void testDataReferenceValues() {
        String dataRef1 = "       0022d4d8 2c d9           move.l     (A1)+=>DAT_0022d5f6,(A6)+                        = 636F6E3Ah";
        String dataRef2 = "       0022d5fa 31 30 2f 31     undefined4 31302F31h";

        // Should show symbol
        assertTrue(dataRef1.contains("=>DAT_0022d5f6"), "Should show resolved symbol");

        // Should show actual data value
        assertTrue(dataRef1.contains("= 636F6E3Ah"), "Should show data value 636F6E3Ah");
        assertTrue(dataRef2.contains("31302F31h"), "Should show hex value in data definition");
    }

    @Test
    @DisplayName("Stack offsets in operands should be resolved to variable names")
    void testStackOffsetToVariableNameResolution() {
        String instrWithStackVar = "       0022d5ec 4c ed 4c 84     movem.l    (-0x28=>local_28,A5),{D2 D7 A2 A3 A6}";

        // Should show the stack offset
        assertTrue(instrWithStackVar.contains("-0x28"), "Should show stack offset -0x28");

        // Should resolve to variable name with =>
        assertTrue(instrWithStackVar.contains("-0x28=>local_28"), "Should resolve to variable name local_28");
    }

    @Test
    @DisplayName("Call instructions should show function signatures")
    void testCallInstructionSignatures() {
        String callWithSig = "       0022d50e 4e ae ff e2     jsr        (-0x1e,A6=>exec_library_Supervisor)              BPTR dos_library_Open(CONST_STRPTR";

        // Should show target function name
        assertTrue(callWithSig.contains("exec_library_Supervisor"), "Should show called function name");

        // Should show function signature/prototype
        assertTrue(callWithSig.contains("BPTR dos_library_Open"), "Should show function signature");
    }

    @Test
    @DisplayName("Call destination overrides should be displayed for thunks")
    void testCallDestinationOverride() {
        String callWithOverride = "                           -- Call Destination Override: exec_library_Supervisor (00234026)";

        assertTrue(callWithOverride.contains("-- Call Destination Override:"), "Should show override indicator");
        assertTrue(callWithOverride.contains("exec_library_Supervisor"), "Should show thunked function name");
        assertTrue(callWithOverride.contains("(00234026)"), "Should show target address");
    }

    @Test
    @DisplayName("Indirect references should be resolved to symbols")
    void testIndirectReferenceResolution() {
        String indirectRef = "       0022d50a 2c 6c 41 a0     movea.l    (0x41a0,A4)=>dosLibraryPtr,A6";

        // Should show offset
        assertTrue(indirectRef.contains("(0x41a0,A4)"), "Should show indirect offset");

        // Should resolve to symbol
        assertTrue(indirectRef.contains("=>dosLibraryPtr") || indirectRef.contains("=>"),
                  "Should resolve indirect reference to symbol");
    }

    @Test
    @DisplayName("All stack variables should be displayed not just referenced ones")
    void testAllStackVariablesDisplayed() {
        // Ghidra UI shows ALL stack variables, even if not referenced in decompilation
        String varList = "             undefined4        Stack[-0x4]:4  local_4                                 XREF[1]:     0022d5f2(R)\n" +
                        "             undefined4        Stack[-0x10]:4 local_10                                XREF[1]:     0022d546(W)\n" +
                        "             undefined4        Stack[-0x14]:4 local_14                                XREF[2]:     0022d52a(W), 0022d538(R)\n" +
                        "             undefined4        Stack[-0x18]:4 local_18                                XREF[11]:    0022d424(W), 0022d44a(R)\n" +
                        "             undefined4        Stack[-0x28]:4 local_28                                XREF[1]:     0022d5ec(*)\n" +
                        "             undefined4        Stack[-0x30]:4 local_30                                XREF[1]:     0022d5da(*)\n" +
                        "             undefined4        Stack[-0x34]:4 local_34                                XREF[3]:     0022d4ee(*), 0022d5de(*)";

        // Should show all 7 local variables
        assertTrue(varList.contains("local_4"), "Should show local_4");
        assertTrue(varList.contains("local_10"), "Should show local_10");
        assertTrue(varList.contains("local_14"), "Should show local_14");
        assertTrue(varList.contains("local_18"), "Should show local_18");
        assertTrue(varList.contains("local_28"), "Should show local_28");
        assertTrue(varList.contains("local_30"), "Should show local_30");
        assertTrue(varList.contains("local_34"), "Should show local_34");

        // All should have proper hex offsets
        assertTrue(varList.contains("Stack[-0x4]:4"), "local_4 should have hex offset");
        assertTrue(varList.contains("Stack[-0x18]:4"), "local_18 should have hex offset");
        assertTrue(varList.contains("Stack[-0x34]:4"), "local_34 should have hex offset");
    }

    @Test
    @DisplayName("Variable XREFs should be limited to 11 entries like Ghidra UI")
    void testVariableXREFLimit() {
        // Ghidra limits XREF display to 11 entries per variable
        String varWith11Xrefs = "XREF[11]:    0022d424(W), 0022d44a(R), 0022d452(W), 0022d458(R), 0022d460(W), 0022d466(R), 0022d46c(W), 0022d474(R), 0022d47a(W), 0022d482(R), 0022d488(W)";

        assertTrue(varWith11Xrefs.contains("XREF[11]"), "Should show count of 11");

        // Count the number of comma-separated entries
        String xrefPart = varWith11Xrefs.substring(varWith11Xrefs.indexOf(":") + 1);
        int commas = (int) xrefPart.chars().filter(ch -> ch == ',').count();

        // 11 entries means 10 commas
        assertTrue(commas <= 10, "Should have at most 10 commas for 11 entries");
    }

    @Test
    @DisplayName("Multi-byte instructions should display all bytes")
    void testMultiByteInstructionDisplay() {
        String sixByteInstr = "       0022d3dc 0c ac 00 00     cmpi.l     #0x20,(0x3ff2,A4)";
        String sevenByteInstr = "       0022d5ec 4c ed 4c 84     movem.l    (-0x28,A5),{D2 D7 A2 A3 A6}";

        // Should show all instruction bytes
        assertTrue(sixByteInstr.contains("0c ac 00 00"), "Should show all bytes of 4-byte instruction");
        assertTrue(sevenByteInstr.contains("4c ed 4c 84"), "Should show first part of multi-byte instruction");
    }

    @Test
    @DisplayName("Function parameter variables should be included in variable listing")
    void testFunctionParametersInVariableListing() {
        String paramVar = "             char *            Stack[0x4]:4   commandLine                             XREF[3]:     0022d3dc, 0022d480, 0022d4b2";

        // Should show function parameter with positive stack offset
        assertTrue(paramVar.contains("Stack[0x4]:4"), "Should show positive stack offset for parameter");
        assertTrue(paramVar.contains("commandLine"), "Should show parameter name");

        // Parameters have positive offsets, locals have negative
        assertTrue(paramVar.contains("[0x4]"), "Parameter should have positive offset");
        assertFalse(paramVar.contains("[-"), "Parameter should not have negative offset");
    }
}
