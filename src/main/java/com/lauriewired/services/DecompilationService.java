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
        options.setInferConstPtr(false);
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
            options.setInferConstPtr(false);
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
            Register[] registers = programContext.getRegisters();

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
            // Decompile to get high-level variable information
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults decompResults = decomp.decompileFunction(func, this.decompileTimeout, new ConsoleTaskMonitor());
            decomp.flushCache();

            if (decompResults != null && decompResults.decompileCompleted()) {
                HighFunction highFunc = decompResults.getHighFunction();
                if (highFunc != null) {
                    LocalSymbolMap symbolMap = highFunc.getLocalSymbolMap();
                    Iterator<HighSymbol> symbols = symbolMap.getSymbols();

                    Map<String, VariableInfo> varInfoMap = new TreeMap<>();
                    while (symbols.hasNext()) {
                        HighSymbol symbol = symbols.next();
                        HighVariable highVar = symbol.getHighVariable();
                        if (highVar != null) {
                            String varName = symbol.getName();
                            String dataType = highVar.getDataType().getName();

                            // Get storage location from representative varnode
                            String storage = "";
                            Varnode rep = highVar.getRepresentative();
                            if (rep != null) {
                                if (rep.isRegister()) {
                                    storage = "Register";
                                } else if (rep.isAddress()) {
                                    storage = rep.getAddress().toString();
                                } else {
                                    storage = "Stack[" + rep.getOffset() + "]";
                                }
                            } else {
                                storage = "Unknown";
                            }

                            // Collect XREFs for this variable
                            List<String> xrefs = new ArrayList<>();
                            Varnode[] instances = highVar.getInstances();
                            for (Varnode vn : instances) {
                                PcodeOp def = vn.getDef();
                                if (def != null) {
                                    Address addr = def.getSeqnum().getTarget();
                                    if (addr != null && !xrefs.contains(addr.toString())) {
                                        xrefs.add(addr.toString());
                                    }
                                }
                            }

                            varInfoMap.put(varName, new VariableInfo(dataType, storage, xrefs));
                        }
                    }

                    // Output variable table
                    if (!varInfoMap.isEmpty()) {
                        for (Map.Entry<String, VariableInfo> entry : varInfoMap.entrySet()) {
                            String varName = entry.getKey();
                            VariableInfo info = entry.getValue();

                            result.append("             ");
                            result.append(String.format("%-18s", info.dataType));
                            result.append(String.format("%-15s", info.storage));
                            result.append(String.format("%-20s", varName));

                            if (!info.xrefs.isEmpty()) {
                                String xrefStr = info.xrefs.stream()
                                    .limit(5)
                                    .collect(Collectors.joining(", "));
                                if (info.xrefs.size() > 5) {
                                    xrefStr += "...";
                                }
                                result.append("XREF[").append(info.xrefs.size()).append("]:     ");
                                result.append(xrefStr);
                            }
                            result.append("\n");
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Silently continue if decompilation fails
            Msg.debug(this, "Could not get variable info: " + e.getMessage());
        }
    }

    /**
     * Helper class to store variable information
     */
    private static class VariableInfo {
        String dataType;
        String storage;
        List<String> xrefs;

        VariableInfo(String dataType, String storage, List<String> xrefs) {
            this.dataType = dataType;
            this.storage = storage;
            this.xrefs = xrefs;
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

            // Show label at this address if any
            Symbol primarySymbol = symbolTable.getPrimarySymbol(addr);
            if (primarySymbol != null && !primarySymbol.getName().equals(func.getName())) {
                result.append("                             ");
                result.append(primarySymbol.getName()).append(":\n");
            }

            // Format: ADDRESS: INSTRUCTION
            result.append("       ");
            result.append(String.format("%-10s", addr.toString()));
            result.append(String.format("%-40s", instr.toString()));

            // Add function name for CALL instructions
            if (instr.getFlowType().isCall()) {
                Reference[] refs = refManager.getReferencesFrom(addr);
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isCall()) {
                        Function calledFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                        if (calledFunc != null) {
                            result.append(" ").append(calledFunc.getName());
                        }
                    }
                }
            }

            // Add all comment types
            appendAllComments(result, listing, addr);

            result.append("\n");

            // Show XREFs TO this address (who references this instruction)
            ReferenceIterator xrefsTo = refManager.getReferencesTo(addr);
            List<String> xrefList = new ArrayList<>();
            while (xrefsTo.hasNext()) {
                Reference ref = xrefsTo.next();
                Address fromAddr = ref.getFromAddress();
                // Don't show sequential flow as XREF
                if (!ref.getReferenceType().isFlow() || !fromAddr.equals(addr.subtract(1))) {
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
        options.setInferConstPtr(false);
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
