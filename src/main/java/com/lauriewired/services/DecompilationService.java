package com.lauriewired.services;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for decompilation and disassembly operations
 */
public class DecompilationService {

    private final FunctionNavigator navigator;
    private final int decompileTimeout;

    public DecompilationService(FunctionNavigator navigator, int decompileTimeout) {
        this.navigator = navigator;
        this.decompileTimeout = decompileTimeout;
    }

    /**
     * Decompile a function by name
     * @param name Function name
     * @return Decompiled C code or error message
     */
    public String decompileFunctionByName(String name) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, this.decompileTimeout, new ConsoleTaskMonitor());
                decomp.flushCache();
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    /**
     * Decompile a function by address
     * @param addressStr Address as string
     * @return Decompiled C code or error message
     */
    public String decompileFunctionByAddress(String addressStr) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = navigator.getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            String decompCode = decompileFunctionInProgram(func, program);
            return (decompCode != null && !decompCode.isEmpty())
                ? decompCode
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Disassemble a function by address
     * @param addressStr Address as string
     * @return Disassembly or error message
     */
    public String disassembleFunction(String addressStr) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = navigator.getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            return disassembleFunctionInProgram(func, program);
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }

    /**
     * Decompile a function within a program
     * @param func Function to decompile
     * @param program Program containing the function
     * @return Decompiled C code or null
     */
    public String decompileFunctionInProgram(Function func, Program program) {
        try {
            DecompInterface decomp = new DecompInterface();
            DecompileOptions options = new DecompileOptions();
            decomp.setOptions(options);
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, this.decompileTimeout, new ConsoleTaskMonitor());
            decomp.flushCache();

            if (result != null && result.decompileCompleted()) {
                return result.getDecompiledFunction().getC();
            }
        } catch (Exception e) {
            Msg.error(this, "Error decompiling function in external program", e);
        }
        return null;
    }

    /**
     * Disassemble a function within a program with comprehensive Ghidra-style information
     * @param func Function to disassemble
     * @param program Program containing the function
     * @return Enhanced disassembly or null
     */
    public String disassembleFunctionInProgram(Function func, Program program) {
        try {
            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address entryPoint = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            // 1. Add PLATE comment (function documentation box)
            appendPlateComment(result, listing, entryPoint);

            // 2. Add function signature with calling convention and parameters
            appendFunctionSignature(result, func, program);

            // 3. Add register assumptions
            appendRegisterAssumptions(result, func, program);

            // 4. Add local variables table with XREFs
            appendLocalVariables(result, func, program);

            // 5. Add function label with XREFs showing callers
            appendFunctionLabel(result, func, program);

            // 6. Add disassembly with enhanced annotations
            appendEnhancedDisassembly(result, func, program, listing, entryPoint, end);

            return result.toString();
        } catch (Exception e) {
            Msg.error(this, "Error disassembling function in external program", e);
        }
        return null;
    }

    /**
     * Append PLATE comment (function documentation box)
     */
    private void appendPlateComment(StringBuilder result, Listing listing, Address entryPoint) {
        String plateComment = listing.getComment(CodeUnit.PLATE_COMMENT, entryPoint);
        if (plateComment != null && !plateComment.isEmpty()) {
            String[] lines = plateComment.split("\n");
            int maxLength = Arrays.stream(lines).mapToInt(String::length).max().orElse(60);
            maxLength = Math.max(maxLength, 60);

            result.append("                             ");
            result.append("*".repeat(maxLength + 4)).append("\n");

            for (String line : lines) {
                result.append("                             * ");
                result.append(String.format("%-" + maxLength + "s", line));
                result.append(" *\n");
            }

            result.append("                             ");
            result.append("*".repeat(maxLength + 4)).append("\n");
        }
    }

    /**
     * Append function signature with return type, calling convention, and parameters
     */
    private void appendFunctionSignature(StringBuilder result, Function func, Program program) {
        result.append("                             ");
        result.append(func.getReturnType().getName());
        result.append(" ");

        String callingConvention = func.getCallingConventionName();
        if (callingConvention != null && !callingConvention.equals("default")) {
            result.append("__").append(callingConvention).append(" ");
        }

        // Add namespace if not global
        Namespace namespace = func.getParentNamespace();
        if (namespace != null && !namespace.isGlobal()) {
            result.append(namespace.getName()).append("::");
        }

        result.append(func.getName()).append("(");

        Parameter[] params = func.getParameters();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) result.append(", ");
            result.append(params[i].getDataType().getName()).append(" ").append(params[i].getName());
        }
        result.append(")\n");
    }

    /**
     * Append register assumptions (e.g., assume CS = 0x2a0a)
     */
    private void appendRegisterAssumptions(StringBuilder result, Function func, Program program) {
        try {
            ghidra.program.model.listing.ProgramContext programContext = program.getProgramContext();
            Address entryPoint = func.getEntryPoint();

            // Get all registers from the language
            List<Register> registers = programContext.getRegisters();

            List<String> assumptions = new ArrayList<>();
            for (Register register : registers) {
                // Skip sub-registers and only check base registers
                if (register.getBaseRegister() != register) {
                    continue;
                }

                // Get the register value at the function entry point
                RegisterValue regValue = programContext.getRegisterValue(register, entryPoint);

                if (regValue != null && regValue.hasValue()) {
                    // Format: assume <register> = <hex_value>
                    java.math.BigInteger value = regValue.getUnsignedValue();
                    if (value != null) {
                        String hexValue = "0x" + value.toString(16);
                        assumptions.add("assume " + register.getName() + " = " + hexValue);
                    }
                }
            }

            // Output assumptions with proper indentation
            for (String assumption : assumptions) {
                result.append("                               ");
                result.append(assumption);
                result.append("\n");
            }
        } catch (Exception e) {
            // Silently continue if getting register assumptions fails
            Msg.debug(this, "Could not get register assumptions: " + e.getMessage());
        }
    }

    /**
     * Append local variables table with types and XREFs
     */
    private void appendLocalVariables(StringBuilder result, Function func, Program program) {
        try {
            // Get ALL variables from the function (parameters + locals)
            Variable[] allVars = func.getAllVariables();

            // Sort by storage location for better organization
            Arrays.sort(allVars, (v1, v2) -> {
                String s1 = v1.getVariableStorage().toString();
                String s2 = v2.getVariableStorage().toString();
                return s1.compareTo(s2);
            });

            // Decompile to get XREF information
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults decompResults = decomp.decompileFunction(func, this.decompileTimeout, new ConsoleTaskMonitor());
            decomp.flushCache();

            Map<String, List<XRefInfo>> xrefMap = new HashMap<>();

            if (decompResults != null && decompResults.decompileCompleted()) {
                HighFunction highFunc = decompResults.getHighFunction();
                if (highFunc != null) {
                    // Build XREF map from high-level variables
                    LocalSymbolMap symbolMap = highFunc.getLocalSymbolMap();
                    Iterator<HighSymbol> symbols = symbolMap.getSymbols();

                    while (symbols.hasNext()) {
                        HighSymbol symbol = symbols.next();
                        HighVariable highVar = symbol.getHighVariable();
                        if (highVar != null) {
                            String varName = symbol.getName();
                            List<XRefInfo> xrefs = new ArrayList<>();

                            Varnode[] instances = highVar.getInstances();
                            for (Varnode vn : instances) {
                                // Check for definition (write)
                                PcodeOp def = vn.getDef();
                                if (def != null) {
                                    Address addr = def.getSeqnum().getTarget();
                                    if (addr != null) {
                                        xrefs.add(new XRefInfo(addr.toString(), "W"));
                                    }
                                }

                                // Check for uses (read)
                                Iterator<PcodeOp> descendants = vn.getDescendants();
                                while (descendants.hasNext()) {
                                    PcodeOp use = descendants.next();
                                    Address addr = use.getSeqnum().getTarget();
                                    if (addr != null) {
                                        // Determine if it's a pointer dereference or read
                                        String type = isPointerDeref(use) ? "*" : "R";
                                        xrefs.add(new XRefInfo(addr.toString(), type));
                                    }
                                }
                            }

                            xrefMap.put(varName, xrefs);
                        }
                    }
                }
            }

            // Output all variables in Ghidra UI format
            for (Variable var : allVars) {
                String dataType = var.getDataType().getDisplayName();
                String storage = formatVariableStorage(var);
                String varName = var.getName();

                // Format: dataType (18 chars) storage (15 chars) name (40 chars) XREF
                result.append("             ");
                result.append(String.format("%-18s", dataType));
                result.append(String.format("%-15s", storage));
                result.append(String.format("%-40s", varName));

                // Add XREFs if available
                List<XRefInfo> xrefs = xrefMap.get(varName);
                if (xrefs != null && !xrefs.isEmpty()) {
                    // Remove duplicates and sort
                    Map<String, String> uniqueXrefs = new LinkedHashMap<>();
                    for (XRefInfo xref : xrefs) {
                        uniqueXrefs.put(xref.address, xref.type);
                    }

                    result.append("XREF[").append(uniqueXrefs.size()).append("]:     ");

                    int count = 0;
                    for (Map.Entry<String, String> entry : uniqueXrefs.entrySet()) {
                        if (count > 0) result.append(", ");
                        result.append(entry.getKey()).append("(").append(entry.getValue()).append(")");
                        count++;
                        if (count >= 11) break; // Limit to 11 XREFs like Ghidra
                    }
                }

                result.append("\n");
            }
        } catch (Exception e) {
            // Silently continue if getting variable info fails
            Msg.debug(this, "Could not get variable info: " + e.getMessage());
        }
    }

    /**
     * Format variable storage location in Ghidra UI format
     */
    private String formatVariableStorage(Variable var) {
        String storage = var.getVariableStorage().toString();

        // Check if it's a stack variable
        if (var.isStackVariable()) {
            int stackOffset = var.getStackOffset();
            int size = var.getLength();
            // Format as Stack[offset]:size with hex offset
            return String.format("Stack[%s]:%d",
                stackOffset < 0 ? "-0x" + Integer.toHexString(-stackOffset) : "0x" + Integer.toHexString(stackOffset),
                size);
        } else if (var.isRegisterVariable()) {
            return "Register";
        } else if (var.isMemoryVariable()) {
            return var.getMinAddress().toString();
        }

        return storage;
    }

    /**
     * Check if a PcodeOp represents a pointer dereference
     */
    private boolean isPointerDeref(PcodeOp op) {
        int opcode = op.getOpcode();
        return opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE ||
               opcode == PcodeOp.INDIRECT || opcode == PcodeOp.PTRSUB;
    }

    /**
     * Helper class to store XREF information with address and type
     */
    private static class XRefInfo {
        String address;
        String type; // R=read, W=write, *=pointer deref, j=jump

        XRefInfo(String address, String type) {
            this.address = address;
            this.type = type;
        }
    }

    /**
     * Append function label with XREFs showing callers
     */
    private void appendFunctionLabel(StringBuilder result, Function func, Program program) {
        result.append("                             ");

        // Add namespace if not global
        Namespace namespace = func.getParentNamespace();
        if (namespace != null && !namespace.isGlobal()) {
            result.append(namespace.getName()).append("::");
        }

        result.append(func.getName());

        // Add XREFs to function (callers)
        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refIter = refManager.getReferencesTo(func.getEntryPoint());

        List<String> callers = new ArrayList<>();
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            Address fromAddr = ref.getFromAddress();
            Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
            if (fromFunc != null && !fromFunc.equals(func)) {
                String caller = fromFunc.getName() + ":" + fromAddr.toString();
                if (!callers.contains(caller)) {
                    callers.add(caller);
                }
            }
        }

        if (!callers.isEmpty()) {
            result.append("                 XREF[").append(callers.size()).append("]:     ");
            result.append(callers.stream().limit(3).collect(Collectors.joining(", ")));
            if (callers.size() > 3) {
                result.append("...");
            }
        }

        result.append("\n");
    }

    /**
     * Append enhanced disassembly with annotations
     */
    private void appendEnhancedDisassembly(StringBuilder result, Function func, Program program,
                                          Listing listing, Address start, Address end) {
        ReferenceManager refManager = program.getReferenceManager();
        SymbolTable symbolTable = program.getSymbolTable();

        InstructionIterator instructions = listing.getInstructions(start, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            Address addr = instr.getAddress();

            if (addr.compareTo(end) > 0) {
                break;
            }

            // Show label at this address if any (with XREFs for jump targets)
            Symbol primarySymbol = symbolTable.getPrimarySymbol(addr);
            if (primarySymbol != null && !primarySymbol.getName().equals(func.getName())) {
                result.append("                             ");
                result.append(primarySymbol.getName());

                // Add XREFs for labels (jump targets)
                ReferenceIterator labelXrefs = refManager.getReferencesTo(addr);
                List<String> jumpRefs = new ArrayList<>();
                while (labelXrefs.hasNext()) {
                    Reference ref = labelXrefs.next();
                    if (ref.getReferenceType().isJump() || ref.getReferenceType().isConditional()) {
                        jumpRefs.add(ref.getFromAddress().toString() + "(j)");
                    }
                }

                if (!jumpRefs.isEmpty()) {
                    result.append("                                    XREF[").append(jumpRefs.size()).append("]:     ");
                    result.append(String.join(", ", jumpRefs.stream().limit(5).collect(Collectors.toList())));
                }

                result.append("\n");
            }

            // Get instruction bytes
            byte[] bytes = null;
            try {
                bytes = instr.getBytes();
            } catch (ghidra.program.model.mem.MemoryAccessException e) {
                // Memory access failed - we'll show "??" placeholders like Ghidra UI does
            }

            StringBuilder bytesStr = new StringBuilder();
            if (bytes != null) {
                for (byte b : bytes) {
                    bytesStr.append(String.format("%02x ", b & 0xFF));
                }
            } else {
                // Show "??" to indicate bytes couldn't be read (matches Ghidra UI behavior)
                bytesStr.append("??");
            }

            // Format the bytes field (limit to ~12 chars worth of bytes to match Ghidra)
            String bytesField = String.format("%-12s", bytesStr.toString().trim());

            // Build instruction mnemonic and operands with enhanced references
            String mnemonicStr = instr.getMnemonicString();
            String enhancedOperands = buildEnhancedOperands(instr, program, func);

            // Calculate proper column widths
            result.append("       ");  // 7 spaces
            result.append(String.format("%-10s", addr.toString()));  // address (10 chars)
            result.append(bytesField);  // instruction bytes (12 chars)
            result.append(String.format("%-10s", mnemonicStr));  // mnemonic (10 chars)

            // Add operands with references and symbols
            result.append(enhancedOperands);

            // Add function names for CALL instructions with prototypes
            if (instr.getFlowType().isCall()) {
                appendCallDetails(result, instr, program, refManager);
            }

            // Add all comment types
            appendAllComments(result, listing, addr);

            result.append("\n");

            // Show XREFs TO this address (who references this instruction) - limit to 5
            ReferenceIterator xrefsTo = refManager.getReferencesTo(addr);
            List<String> xrefList = new ArrayList<>();
            while (xrefsTo.hasNext()) {
                Reference ref = xrefsTo.next();
                Address fromAddr = ref.getFromAddress();
                // Don't show sequential flow as XREF
                if (!ref.getReferenceType().isFlow()) {
                    Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                    String xrefStr = fromAddr.toString();
                    if (fromFunc != null && !fromFunc.equals(func)) {
                        xrefStr = fromFunc.getName() + ":" + xrefStr;
                    }
                    xrefStr += " (" + ref.getReferenceType().getName() + ")";
                    xrefList.add(xrefStr);
                }
            }

            if (!xrefList.isEmpty() && xrefList.size() <= 5) {
                for (String xref : xrefList) {
                    result.append("                     XREF from: ").append(xref).append("\n");
                }
            }
        }
    }

    /**
     * Build enhanced operand string with resolved references and symbols
     */
    private String buildEnhancedOperands(Instruction instr, Program program, Function func) {
        StringBuilder operands = new StringBuilder();

        int numOperands = instr.getNumOperands();
        for (int i = 0; i < numOperands; i++) {
            if (i > 0) operands.append(",");

            String opStr = instr.getDefaultOperandRepresentation(i);

            // Get references for this operand
            Reference[] refs = instr.getOperandReferences(i);
            if (refs.length > 0) {
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();

                    // Try to get symbol at target address
                    Symbol targetSymbol = program.getSymbolTable().getPrimarySymbol(toAddr);

                    // Check if it's a data reference and get the value
                    ghidra.program.model.listing.Data data = null;
                    try {
                        data = program.getListing().getDataAt(toAddr);
                    } catch (Exception e) {
                        // Ignore - data will be null
                    }

                    // Enhanced operand format: operand=>symbol
                    if (targetSymbol != null) {
                        operands.append(opStr).append("=>").append(targetSymbol.getName());

                        // Add data value if available
                        if (data != null && data.isDefined()) {
                            try {
                                Object value = data.getValue();
                                if (value != null) {
                                    operands.append("                        = ").append(value);
                                }
                            } catch (Exception e) {
                                // Ignore - just don't show value
                            }
                        }
                    } else {
                        operands.append(opStr);

                        // Just add value if no symbol
                        if (data != null && data.isDefined()) {
                            try {
                                Object value = data.getValue();
                                if (value != null) {
                                    operands.append("                        = ").append(value);
                                }
                            } catch (Exception e) {
                                // Ignore - just don't show value
                            }
                        }
                    }
                }
            } else {
                // No references, just use default operand
                operands.append(opStr);

                // Check if operand references a local variable (stack offset)
                // Try to replace stack offsets with variable names
                String withVarNames = replaceStackOffsetsWithVarNames(opStr, func);
                if (!withVarNames.equals(opStr)) {
                    operands.setLength(operands.length() - opStr.length());
                    operands.append(withVarNames);
                }
            }
        }

        return operands.toString();
    }

    /**
     * Replace stack offsets in operand strings with variable names
     */
    private String replaceStackOffsetsWithVarNames(String operandStr, Function func) {
        // Look for patterns like (-0x18,A5) or (0x10,SP) and replace with variable names
        Variable[] vars = func.getAllVariables();

        for (Variable var : vars) {
            if (var.isStackVariable()) {
                int offset = var.getStackOffset();
                String hexOffset = offset < 0 ? "-0x" + Integer.toHexString(-offset) : "0x" + Integer.toHexString(offset);

                // Try to find this offset in the operand string
                if (operandStr.contains(hexOffset) || operandStr.contains(Integer.toString(offset))) {
                    // Replace with offset=>varname
                    operandStr = operandStr.replace("(" + hexOffset, "(" + hexOffset + "=>" + var.getName());
                }
            }
        }

        return operandStr;
    }

    /**
     * Append call details including function prototypes
     */
    private void appendCallDetails(StringBuilder result, Instruction instr, Program program, ReferenceManager refManager) {
        Reference[] refs = refManager.getReferencesFrom(instr.getAddress());
        for (Reference ref : refs) {
            if (ref.getReferenceType().isCall()) {
                Function calledFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                if (calledFunc != null) {
                    // Add function name
                    result.append("              ").append(calledFunc.getName());

                    // Add function signature/prototype on next line
                    String signature = calledFunc.getSignature().toString();
                    if (signature != null && !signature.isEmpty()) {
                        result.append("\n");
                        result.append("                                                                                       ");
                        result.append(signature);
                    }

                    // Add call destination override if thunk or indirect
                    if (calledFunc.isThunk()) {
                        Function thunkedFunc = calledFunc.getThunkedFunction(true);
                        if (thunkedFunc != null) {
                            result.append("\n");
                            result.append("                           -- Call Destination Override: ");
                            result.append(thunkedFunc.getName());
                            result.append(" (").append(thunkedFunc.getEntryPoint()).append(")");
                        }
                    }
                }
            }
        }
    }

    /**
     * Append all comment types for an address
     */
    private void appendAllComments(StringBuilder result, Listing listing, Address addr) {
        List<String> comments = new ArrayList<>();

        String preComment = listing.getComment(CodeUnit.PRE_COMMENT, addr);
        if (preComment != null && !preComment.isEmpty()) {
            comments.add("[PRE: " + preComment.replace("\n", " ") + "]");
        }

        String eolComment = listing.getComment(CodeUnit.EOL_COMMENT, addr);
        if (eolComment != null && !eolComment.isEmpty()) {
            comments.add("; " + eolComment);
        }

        String postComment = listing.getComment(CodeUnit.POST_COMMENT, addr);
        if (postComment != null && !postComment.isEmpty()) {
            comments.add("[POST: " + postComment.replace("\n", " ") + "]");
        }

        String repeatableComment = listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr);
        if (repeatableComment != null && !repeatableComment.isEmpty()) {
            comments.add("[REP: " + repeatableComment.replace("\n", " ") + "]");
        }

        if (!comments.isEmpty()) {
            result.append(" ").append(String.join(" ", comments));
        }
    }

    /**
     * Helper method to decompile a function and return results
     * @param func Function to decompile
     * @param program Program containing the function
     * @return Decompilation results or null
     */
    public DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, this.decompileTimeout, new ConsoleTaskMonitor());
        decomp.flushCache();

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }
}
