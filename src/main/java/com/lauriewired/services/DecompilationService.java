package com.lauriewired.services;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

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
     * Disassemble a function within a program
     * @param func Function to disassemble
     * @param program Program containing the function
     * @return Disassembly or null
     */
    public String disassembleFunctionInProgram(Function func, Program program) {
        try {
            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break;
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n",
                    instr.getAddress(),
                    instr.toString(),
                    comment));
            }
            return result.toString();
        } catch (Exception e) {
            Msg.error(this, "Error disassembling function in external program", e);
        }
        return null;
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
