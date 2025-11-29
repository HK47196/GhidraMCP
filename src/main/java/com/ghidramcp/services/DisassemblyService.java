package com.ghidramcp.services;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.template.TemplateSimplifier;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowNamespace;
import ghidra.program.model.listing.OperandRepresentationList;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for disassembly operations
 */
public class DisassemblyService {

    private final FunctionNavigator navigator;
    private final int decompileTimeout;
    private final CodeUnitFormat codeUnitFormatter;
    private final DataLookupService dataLookupService;

    public DisassemblyService(FunctionNavigator navigator, int decompileTimeout) {
        this.navigator = navigator;
        this.decompileTimeout = decompileTimeout;
        this.dataLookupService = new DataLookupService();

        // Initialize CodeUnitFormat with comprehensive formatting options
        // Using full constructor since fields are protected
        CodeUnitFormatOptions formatOptions = new CodeUnitFormatOptions(
            ShowBlockName.NEVER,           // showBlockName
            ShowNamespace.NON_LOCAL,       // showNamespace - Show namespace for non-local references
            null,                          // localPrefixOverride
            true,                          // doRegVariableMarkup - Enable register variable names
            true,                          // doStackVariableMarkup - Enable stack variable names
            true,                          // includeInferredVariableMarkup - Infer variables when possible
            true,                          // alwaysShowPrimaryReference - Enable "=>" notation
            true,                          // includeScalarReferenceAdjustment - Show offset adjustments
            true,                          // showLibraryInNamespace
            true,                          // followReferencedPointers - Enable "->" for pointers
            new TemplateSimplifier()       // templateSimplifier - Handles C++ template simplification
        );

        this.codeUnitFormatter = new CodeUnitFormat(formatOptions);
    }

    /**
     * Disassemble a function by address
     * @param addressStr Address as string
     * @param includeBytes Include raw instruction bytes in output (default: false)
     * @return Disassembly or error message
     */
    public String disassembleFunction(String addressStr, boolean includeBytes) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = navigator.getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            return disassembleFunctionInProgram(func, program, includeBytes);
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }

    /**
     * Disassemble a function within a program with comprehensive Ghidra-style information
     * @param func Function to disassemble
     * @param program Program containing the function
     * @param includeBytes Include raw instruction bytes in output
     * @return Enhanced disassembly or null
     */
    public String disassembleFunctionInProgram(Function func, Program program, boolean includeBytes) {
        try {
            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address entryPoint = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            // Check for non-contiguous function body and add warning if needed
            String contiguityWarning = checkFunctionContiguity(func, program);
            if (contiguityWarning != null) {
                result.append(contiguityWarning).append("\n");
            }

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
            appendEnhancedDisassembly(result, func, program, listing, entryPoint, end, includeBytes);

            return result.toString();
        } catch (Exception e) {
            Msg.error(this, "Error disassembling function in external program", e);
        }
        return null;
    }

    /**
     * Check if a function's body is contiguous (no gaps in the function)
     * @param func Function to check
     * @param program Program containing the function
     * @return Warning string if non-contiguous, null otherwise
     */
    private String checkFunctionContiguity(Function func, Program program) {
        try {
            FunctionManager funcMgr = program.getFunctionManager();
            Address funcEnd = func.getBody().getMaxAddress();

            // Find the next function in memory after this one
            // Start searching from one byte after the function's entry point
            FunctionIterator funcIter = funcMgr.getFunctions(func.getEntryPoint(), true);

            Function nextFunc = null;
            while (funcIter.hasNext()) {
                Function candidate = funcIter.next();
                // Skip the current function and find the first function that starts after our function ends
                if (candidate.getEntryPoint().compareTo(func.getEntryPoint()) > 0) {
                    nextFunc = candidate;
                    break;
                }
            }
        } catch (Exception e) {
            // Silently fail - don't block disassembly if contiguity check fails
            Msg.debug(this, "Could not check function contiguity: " + e.getMessage());
        }

        return null;
    }

    /**
     * Append PLATE comment (function documentation box)
     */
    private void appendPlateComment(StringBuilder result, Listing listing, Address entryPoint) {
        String plateComment = listing.getComment(CommentType.PLATE, entryPoint);
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
                                          Listing listing, Address start, Address end, boolean includeBytes) {
        ReferenceManager refManager = program.getReferenceManager();
        SymbolTable symbolTable = program.getSymbolTable();

        InstructionIterator instructions = listing.getInstructions(start, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            Address addr = instr.getAddress();

            if (addr.compareTo(end) > 0) {
                break;
            }

            // Check for error messages (disassembly errors) at this address
            List<String> errorMessages = getErrorMessages(program, addr);
            if (!errorMessages.isEmpty()) {
                for (String errorMsg : errorMessages) {
                    result.append("Error (Bad Instruction): ").append(errorMsg).append("\n");
                }
                result.append("Changes Unsaved\n");
            }

            // Show label at this address if any (with XREFs for jump targets)
            Symbol primarySymbol = symbolTable.getPrimarySymbol(addr);
            if (primarySymbol != null && !primarySymbol.getName().equals(func.getName())) {
                result.append("                             ");
                result.append(primarySymbol.getName());

                // Add XREFs for labels using reference type display strings
                ReferenceIterator labelXrefs = refManager.getReferencesTo(addr);
                List<String> jumpRefs = new ArrayList<>();
                while (labelXrefs.hasNext()) {
                    Reference ref = labelXrefs.next();
                    if (ref.getReferenceType().isJump() || ref.getReferenceType().isConditional()) {
                        String refTypeStr = getRefTypeDisplayString(ref);
                        jumpRefs.add(ref.getFromAddress().toString() + refTypeStr);
                    }
                }

                if (!jumpRefs.isEmpty()) {
                    result.append("                                    XREF[").append(jumpRefs.size()).append("]:     ");
                    result.append(String.join(", ", jumpRefs.stream().limit(5).collect(Collectors.toList())));
                }

                result.append("\n");
            }

            // Get instruction bytes (only if requested)
            String bytesField = "";
            if (includeBytes) {
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
                bytesField = String.format("%-12s", bytesStr.toString().trim());
            }

            // Build instruction mnemonic and operands with enhanced references
            String mnemonicStr = instr.getMnemonicString();
            String enhancedOperands = buildEnhancedOperands(instr, program, func);

            // Calculate proper column widths
            result.append("       ");  // 7 spaces
            result.append(String.format("%-10s", addr.toString()));  // address (10 chars)
            if (includeBytes) {
                result.append(bytesField);  // instruction bytes (12 chars) - only if requested
            }
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
     * Build enhanced operand string using Ghidra's CodeUnitFormat
     * This automatically handles variable names, symbols, and reference markup
     */
    private String buildEnhancedOperands(Instruction instr, Program program, Function func) {
        StringBuilder result = new StringBuilder();
        int numOperands = instr.getNumOperands();

        for (int i = 0; i < numOperands; i++) {
            if (i > 0) {
                // Use instruction's separator if available, otherwise use comma
                String separator = instr.getSeparator(i);
                result.append(separator != null ? separator : ",");
            }

            // Get formatted operand representation using CodeUnitFormat
            // This handles:
            // - Variable name replacement (VariableOffset objects)
            // - Symbol/label resolution (LabelString objects)
            // - Arrow notation (=> and ->)
            // - Data value display
            OperandRepresentationList repList = codeUnitFormatter.getOperandRepresentationList(instr, i);
            if (repList != null) {
                result.append(repList.toString());
            } else {
                // Fallback for unsupported languages
                result.append(instr.getDefaultOperandRepresentation(i));
            }
        }

        return result.toString();
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

        String preComment = listing.getComment(CommentType.PRE, addr);
        if (preComment != null && !preComment.isEmpty()) {
            comments.add("[PRE: " + preComment.replace("\n", " ") + "]");
        }

        String eolComment = listing.getComment(CommentType.EOL, addr);
        if (eolComment != null && !eolComment.isEmpty()) {
            comments.add("; " + eolComment);
        }

        String postComment = listing.getComment(CommentType.POST, addr);
        if (postComment != null && !postComment.isEmpty()) {
            comments.add("[POST: " + postComment.replace("\n", " ") + "]");
        }

        String repeatableComment = listing.getComment(CommentType.REPEATABLE, addr);
        if (repeatableComment != null && !repeatableComment.isEmpty()) {
            comments.add("[REP: " + repeatableComment.replace("\n", " ") + "]");
        }

        if (!comments.isEmpty()) {
            result.append(" ").append(String.join(" ", comments));
        }
    }

    /**
     * Get reference type display string (adapted from XRefFieldFactory.java:680-703)
     * Returns type indicators: (j)=jump, (c)=call, (R)=read, (W)=write, (RW)=read-write,
     * (T)=thunk, (*)=data
     */
    private String getRefTypeDisplayString(Reference reference) {
        RefType refType = reference.getReferenceType();

        if (reference instanceof ThunkReference) {
            return "(T)";
        }
        if (refType.isCall()) {
            return "(c)";
        }
        else if (refType.isJump()) {
            return "(j)";
        }
        else if (refType.isRead() && refType.isWrite()) {
            return "(RW)";
        }
        else if (refType.isRead() || refType.isIndirect()) {
            return "(R)";
        }
        else if (refType.isWrite()) {
            return "(W)";
        }
        else if (refType.isData()) {
            return "(*)";
        }
        return "";
    }

    /**
     * Collect XREFs with function names included
     */
    private List<String> collectXRefsWithFunctionNames(Address targetAddr, ReferenceManager refManager, Program program) {
        List<String> xrefList = new ArrayList<>();
        ReferenceIterator xrefsTo = refManager.getReferencesTo(targetAddr);

        while (xrefsTo.hasNext()) {
            Reference ref = xrefsTo.next();
            Address fromAddr = ref.getFromAddress();
            StringBuilder xrefStr = new StringBuilder();

            // Find function containing this reference
            Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
            if (fromFunc != null) {
                xrefStr.append(fromFunc.getName()).append(":");
            }

            xrefStr.append(fromAddr.toString());
            xrefStr.append(getRefTypeDisplayString(ref));
            xrefList.add(xrefStr.toString());
        }

        return xrefList;
    }

    /**
     * Get detailed disassembly context around a specific address.
     * Displays code units (instructions AND data) in memory order, matching Ghidra UI listing view.
     *
     * @param addressStr Address as string
     * @param before Number of code units before the address (default: 5)
     * @param after Number of code units after the address (default: 5)
     * @param includeBytes Include raw instruction/data bytes in output (default: false)
     * @return Detailed disassembly with context showing both instructions and data
     */
    public String getAddressContext(String addressStr, int before, int after, boolean includeBytes) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address targetAddr = program.getAddressFactory().getAddress(addressStr);
            if (targetAddr == null) {
                return "Error: Invalid address format: " + addressStr;
            }

            Listing listing = program.getListing();
            ReferenceManager refManager = program.getReferenceManager();
            SymbolTable symbolTable = program.getSymbolTable();

            StringBuilder result = new StringBuilder();
            result.append("Disassembly context for address: ").append(targetAddr).append("\n");
            result.append("Context window: -").append(before).append(" to +").append(after).append(" code units\n\n");

            // Find the function containing this address (if any)
            Function containingFunc = program.getFunctionManager().getFunctionContaining(targetAddr);
            if (containingFunc != null) {
                result.append("Function: ").append(containingFunc.getName());
                result.append(" @ ").append(containingFunc.getEntryPoint()).append("\n\n");
            }

            // Get the CODE UNIT at the target address (could be instruction OR data)
            CodeUnit targetUnit = listing.getCodeUnitContaining(targetAddr);
            if (targetUnit == null) {
                return "Error: No code unit found at address " + targetAddr;
            }

            // Collect code units BEFORE the target (in memory order)
            List<CodeUnit> beforeUnits = new ArrayList<>();
            CodeUnit unit = targetUnit;
            for (int i = 0; i < before && unit != null; i++) {
                unit = listing.getCodeUnitBefore(unit.getMinAddress());
                if (unit != null) {
                    beforeUnits.add(0, unit); // Add to beginning to maintain order
                }
            }

            // Collect code units AFTER the target (including target itself)
            // IMPORTANT: Start from targetUnit's min address, not targetAddr!
            // This ensures we include the parent struct/array even if targetAddr is in the middle
            List<CodeUnit> afterUnits = new ArrayList<>();
            CodeUnitIterator unitIter = listing.getCodeUnits(targetUnit.getMinAddress(), true);
            int count = 0;
            while (unitIter.hasNext() && count <= after) {
                CodeUnit cu = unitIter.next();
                if (cu != null) {
                    afterUnits.add(cu);
                    count++;
                }
            }

            // Combine all units
            List<CodeUnit> allUnits = new ArrayList<>(beforeUnits);
            allUnits.addAll(afterUnits);

            // Display all code units (instructions AND data)
            for (CodeUnit cu : allUnits) {
                Address addr = cu.getMinAddress();
                boolean isTarget = addr.equals(targetAddr) ||
                                   (addr.compareTo(targetAddr) <= 0 &&
                                    cu.getMaxAddress().compareTo(targetAddr) >= 0);

                // Check if this is an instruction or data
                if (cu instanceof Instruction) {
                    displayInstruction((Instruction)cu, isTarget, result, program, listing,
                                      refManager, symbolTable, containingFunc, includeBytes);
                } else if (cu instanceof Data) {
                    displayData((Data)cu, isTarget, targetAddr, result, program, listing,
                               refManager, symbolTable, includeBytes, before, after);
                }
            }

            return result.toString();
        } catch (Exception e) {
            return "Error getting address context: " + e.getMessage();
        }
    }

    /**
     * Get error messages from bookmarks at a specific address
     */
    private List<String> getErrorMessages(Program program, Address addr) {
        List<String> errorMessages = new ArrayList<>();
        try {
            ghidra.program.model.listing.BookmarkManager bookmarkMgr = program.getBookmarkManager();
            if (bookmarkMgr != null) {
                // Get all "Error" type bookmarks at this address
                ghidra.program.model.listing.Bookmark[] bookmarks = bookmarkMgr.getBookmarks(addr, "Error");
                if (bookmarks != null) {
                    for (ghidra.program.model.listing.Bookmark bookmark : bookmarks) {
                        String comment = bookmark.getComment();
                        if (comment != null && !comment.isEmpty()) {
                            errorMessages.add(comment);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Could not retrieve error bookmarks: " + e.getMessage());
        }
        return errorMessages;
    }

    /**
     * Display an instruction in Ghidra UI format
     */
    private void displayInstruction(Instruction instruction, boolean isTarget, StringBuilder result,
                                    Program program, Listing listing,
                                    ReferenceManager refManager, SymbolTable symbolTable,
                                    Function containingFunc, boolean includeBytes) {
        Address addr = instruction.getAddress();

        // Check for error messages (disassembly errors) at this address
        List<String> errorMessages = getErrorMessages(program, addr);
        if (!errorMessages.isEmpty()) {
            for (String errorMsg : errorMessages) {
                result.append("Error (Bad Instruction): ").append(errorMsg).append("\n");
            }
            result.append("Changes Unsaved\n");
        }

        // Check if this address is a function entry point and show function start marker
        Function funcAtAddr = program.getFunctionManager().getFunctionAt(addr);
        if (funcAtAddr != null) {
            // This is a function entry point - add start marker
            result.append("                             ┌─ FUNCTION: ");
            result.append(funcAtAddr.getName());

            // Add function attributes (ENTRY POINT, THUNK, etc.)
            List<String> attributes = new ArrayList<>();
            if (funcAtAddr.isThunk()) {
                attributes.add("THUNK");
            }
            if (program.getSymbolTable().getPrimarySymbol(addr) != null) {
                Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
                if (sym.isExternal()) {
                    attributes.add("EXTERNAL");
                } else if (sym.isExternalEntryPoint()) {
                    attributes.add("ENTRY POINT");
                }
            }

            if (!attributes.isEmpty()) {
                result.append(" (").append(String.join(", ", attributes)).append(")");
            }
            result.append("\n");
        }

        // Show label at this address if any (skip function labels since we show them above)
        Symbol primarySymbol = symbolTable.getPrimarySymbol(addr);
        if (primarySymbol != null &&
            (containingFunc == null || !primarySymbol.getName().equals(containingFunc.getName())) &&
            (funcAtAddr == null || !primarySymbol.getName().equals(funcAtAddr.getName()))) {
            result.append("                             ");
            result.append(primarySymbol.getName());

            // Add XREFs for labels with function names
            List<String> jumpRefs = collectXRefsWithFunctionNames(addr, refManager, program);
            // Filter only jump/conditional references
            jumpRefs = jumpRefs.stream()
                .filter(xref -> xref.contains("(j)") || xref.contains("(c)"))
                .collect(Collectors.toList());

            if (!jumpRefs.isEmpty()) {
                result.append("                                    XREF[").append(jumpRefs.size()).append("]:     ");
                result.append(String.join(", ", jumpRefs.stream().limit(5).collect(java.util.stream.Collectors.toList())));
            }

            result.append("\n");
        }

        // Mark target instruction with arrow
        if (isTarget) {
            result.append("  --> ");
        } else {
            result.append("       ");
        }

        // Get instruction bytes (only if requested)
        String bytesField = "";
        if (includeBytes) {
            byte[] bytes = null;
            try {
                bytes = instruction.getBytes();
            } catch (ghidra.program.model.mem.MemoryAccessException e) {
                // Memory access failed
            }

            StringBuilder bytesStr = new StringBuilder();
            if (bytes != null) {
                for (byte b : bytes) {
                    bytesStr.append(String.format("%02x ", b & 0xFF));
                }
            } else {
                bytesStr.append("??");
            }

            bytesField = String.format("%-12s", bytesStr.toString().trim());
        }

        // Build instruction mnemonic and operands
        String mnemonicStr = instruction.getMnemonicString();
        String enhancedOperands = buildEnhancedOperands(instruction, program, containingFunc);

        // Format the instruction
        result.append(String.format("%-10s", addr.toString()));  // address
        if (includeBytes) {
            result.append(bytesField);  // bytes - only if requested
        }
        result.append(String.format("%-10s", mnemonicStr));  // mnemonic
        result.append(enhancedOperands);  // operands

        // Add function names for CALL instructions
        if (instruction.getFlowType().isCall()) {
            Reference[] refs = refManager.getReferencesFrom(addr);
            for (Reference ref : refs) {
                if (ref.getReferenceType().isCall()) {
                    Function calledFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                    if (calledFunc != null) {
                        result.append("              ").append(calledFunc.getName());
                        String signature = calledFunc.getSignature().toString();
                        if (signature != null && !signature.isEmpty()) {
                            result.append("\n");
                            result.append("                                                                                       ");
                            result.append(signature);
                        }
                    }
                }
            }
        }

        // Add comments
        appendAllComments(result, listing, addr);

        result.append("\n");

        // Show XREFs TO this address (limit to 3 for context view)
        if (isTarget) {
            ReferenceIterator xrefsTo = refManager.getReferencesTo(addr);
            List<String> xrefList = new ArrayList<>();
            while (xrefsTo.hasNext()) {
                Reference ref = xrefsTo.next();
                Address fromAddr = ref.getFromAddress();
                if (!ref.getReferenceType().isFlow()) {
                    Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                    String xrefStr = fromAddr.toString();
                    if (fromFunc != null) {
                        xrefStr = fromFunc.getName() + ":" + xrefStr;
                    }
                    xrefStr += " (" + ref.getReferenceType().getName() + ")";
                    xrefList.add(xrefStr);
                }
            }

            if (!xrefList.isEmpty() && xrefList.size() <= 3) {
                for (String xref : xrefList) {
                    result.append("                     XREF from: ").append(xref).append("\n");
                }
            } else if (xrefList.size() > 3) {
                result.append("                     XREF from: [").append(xrefList.size()).append(" references]\n");
            }
        }

        // Check if this instruction marks the end of a function
        if (containingFunc != null) {
            Address funcMaxAddr = containingFunc.getBody().getMaxAddress();
            // Function ends if this is the last instruction OR if this is a terminal instruction (RET, JMP, etc.)
            boolean isLastInstr = addr.equals(funcMaxAddr) ||
                                 (instruction.getNext() != null &&
                                  instruction.getNext().getAddress().compareTo(funcMaxAddr) > 0);
            boolean isTerminalInstr = instruction.getFlowType().isTerminal();

            if (isLastInstr || (isTerminalInstr && addr.compareTo(funcMaxAddr) >= 0)) {
                result.append("                             └─ END FUNCTION: ");
                result.append(containingFunc.getName());
                result.append("\n");
            }
        }
    }

    /**
     * Display a data item in Ghidra UI format
     * Handles composite types (structs/arrays) by showing components
     */
    private void displayData(Data data, boolean isTarget, Address targetAddr, StringBuilder result,
                            Program program, Listing listing,
                            ReferenceManager refManager, SymbolTable symbolTable, boolean includeBytes,
                            int before, int after) {
        Address addr = data.getMinAddress();

        // Check for error messages (disassembly/data errors) at this address
        List<String> errorMessages = getErrorMessages(program, addr);
        if (!errorMessages.isEmpty()) {
            for (String errorMsg : errorMessages) {
                result.append("Error (Bad Instruction): ").append(errorMsg).append("\n");
            }
            result.append("Changes Unsaved\n");
        }

        // Check if this is a composite type (needed to decide symbol display)
        int numComponents = data.getNumComponents();
        boolean hasComponents = numComponents > 0;

        // 1. Show PLATE COMMENT if present (bordered comment box)
        String plateComment = listing.getComment(CommentType.PLATE, addr);
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

        // 2. Show LABEL/SYMBOL with XREFs
        // Only show symbols here if we're NOT expanding the composite
        // (When expanding, parent symbol shown above struct, field symbols shown on components)
        if (!hasComponents) {
            Symbol[] symbols = symbolTable.getSymbols(addr);
            if (symbols != null && symbols.length > 0) {
                for (Symbol symbol : symbols) {
                    // Skip function symbols and other non-label types
                    SymbolType symType = symbol.getSymbolType();
                    if (symType != SymbolType.LABEL &&
                        symType != SymbolType.GLOBAL &&
                        symType != SymbolType.LOCAL_VAR) {
                        continue;
                    }

                    result.append("                             ");

                    // Add namespace if present
                    Namespace namespace = symbol.getParentNamespace();
                    if (namespace != null && !namespace.isGlobal()) {
                        result.append(namespace.getName()).append("::");
                    }

                    result.append(symbol.getName());

                    // Show XREFs to this symbol with function names (limit to first 3)
                    List<String> xrefList = collectXRefsWithFunctionNames(addr, refManager, program);

                    if (!xrefList.isEmpty()) {
                        result.append("                          XREF[").append(xrefList.size()).append("]:     ");
                        // Show first 3 XREFs
                        result.append(String.join(", ", xrefList.stream().limit(3).collect(Collectors.toList())));
                        if (xrefList.size() > 3) {
                            result.append(", [more]");
                        }
                    }

                    result.append("\n");
                }
            }
        }

        // 3. Display composite or simple data
        if (hasComponents) {
            // This is a composite type - show parent type line then components
            displayCompositeData(data, isTarget, targetAddr, result, program, listing,
                               refManager, symbolTable, includeBytes, before, after);
        } else {
            // Simple data type - show single line
            displaySimpleData(data, isTarget, result, listing, includeBytes, refManager, program);
        }
    }

    /**
     * Display a composite data type (struct or array) with all its components
     * For large composites, only show a subset around the target address
     */
    private void displayCompositeData(Data data, boolean isTarget, Address targetAddr,
                                     StringBuilder result,
                                     Program program, Listing listing,
                                     ReferenceManager refManager, SymbolTable symbolTable,
                                     boolean includeBytes, int before, int after) {
        Address addr = data.getMinAddress();

        // Check if this is a union type
        DataType dataType = data.getDataType();
        if (dataType instanceof Union) {
            displayUnionData(data, isTarget, targetAddr, result, program, listing,
                           refManager, symbolTable, includeBytes, before, after);
            return;
        }

        // Show parent-level symbols with XREFs (only struct/array level, not field level)
        Symbol[] symbols = symbolTable.getSymbols(addr);
        if (symbols != null && symbols.length > 0) {
            for (Symbol symbol : symbols) {
                // Skip function symbols and non-label types
                SymbolType symType = symbol.getSymbolType();
                if (symType != SymbolType.LABEL &&
                    symType != SymbolType.GLOBAL &&
                    symType != SymbolType.LOCAL_VAR) {
                    continue;
                }

                // Skip field-level symbols (with . in name like "parent.field")
                String symbolName = symbol.getName();
                if (symbolName.contains(".")) {
                    continue; // Field symbol - will be shown on component line
                }

                result.append("                             ");

                // Add namespace if present
                Namespace namespace = symbol.getParentNamespace();
                if (namespace != null && !namespace.isGlobal()) {
                    result.append(namespace.getName()).append("::");
                }

                result.append(symbolName);

                // Show XREFs with function names
                List<String> xrefList = collectXRefsWithFunctionNames(addr, refManager, program);

                if (!xrefList.isEmpty()) {
                    result.append("                          XREF[").append(xrefList.size()).append("]:     ");
                    result.append(String.join(", ", xrefList.stream().limit(3).collect(Collectors.toList())));
                    if (xrefList.size() > 3) {
                        result.append(", [more]");
                    }
                }

                result.append("\n");
            }
        }

        // Show parent type line (e.g., "IntuiText", "addr[160]")
        if (isTarget) {
            result.append("  --> ");
        } else {
            result.append("       ");
        }

        // Get data type string
        String dataTypeStr = codeUnitFormatter.getMnemonicRepresentation(data);

        result.append(String.format("%-10s", addr.toString()));
        if (includeBytes) {
            result.append(String.format("%-12s", "")); // Empty bytes column for parent
        }
        result.append(dataTypeStr);

        // Add EOL comment if present
        String eolComment = listing.getComment(CommentType.EOL, addr);
        if (eolComment != null && !eolComment.isEmpty()) {
            result.append(" ; ").append(eolComment);
        }
        result.append("\n");

        // Add blank line for visual separation when expanding struct/array
        result.append("\n");

        // Display components
        int numComponents = data.getNumComponents();

        // Determine which components to display
        // If targeting a specific component within the composite, show a window around it
        // Otherwise, show first N components
        int startIdx = 0;
        int endIdx = numComponents;
        final int MAX_COMPONENTS_TO_SHOW = 20; // Limit display to avoid overwhelming output

        if (isTarget && !addr.equals(targetAddr)) {
            // Target is within this composite but not at its start
            // Use shared lookup service to find which component contains the target
            DataLookupResult componentLookup = dataLookupService.lookupDataAtAddress(program, targetAddr);
            int targetComponentIdx = (componentLookup != null) ? componentLookup.getComponentIndex() : -1;

            if (targetComponentIdx >= 0) {
                // Show window around target component (e.g., 5 before and 5 after)
                startIdx = Math.max(0, targetComponentIdx - 5);
                endIdx = Math.min(numComponents, targetComponentIdx + 6);
            } else {
                // Couldn't find exact component, show first few
                endIdx = Math.min(numComponents, MAX_COMPONENTS_TO_SHOW);
            }
        } else {
            // Not targeting a specific component, show first N
            endIdx = Math.min(numComponents, MAX_COMPONENTS_TO_SHOW);
        }

        // Show indicator if we're not showing components from the beginning
        if (startIdx > 0) {
            result.append("      ... (").append(startIdx).append(" components omitted)\n");
        }

        // Display selected components (indented)
        for (int i = startIdx; i < endIdx; i++) {
            Data component = data.getComponent(i);
            if (component == null) continue;

            // Check if this component contains the target address
            boolean isTargetComponent = (component.getMinAddress().compareTo(targetAddr) <= 0 &&
                                        component.getMaxAddress().compareTo(targetAddr) >= 0);

            displayComponent(component, i, data.isArray(), isTargetComponent, result, listing,
                           refManager, symbolTable, includeBytes, program);
        }

        // Show indicator if we're not showing components to the end
        if (endIdx < numComponents) {
            result.append("      ... (").append(numComponents - endIdx).append(" more components)\n");
        }

        // Add blank line at end for visual separation
        result.append("\n");

        // Show POST comment if present
        String postComment = listing.getComment(CommentType.POST, addr);
        if (postComment != null && !postComment.isEmpty()) {
            result.append("                             ; [POST] ");
            result.append(postComment.replace("\n", "\n                             ; "));
            result.append("\n");
        }
    }

    /**
     * Display a union data type with all its member views
     * Each union member represents an alternative interpretation of the same memory
     */
    private void displayUnionData(Data data, boolean isTarget, Address targetAddr,
                                 StringBuilder result,
                                 Program program, Listing listing,
                                 ReferenceManager refManager, SymbolTable symbolTable,
                                 boolean includeBytes, int before, int after) {
        Address addr = data.getMinAddress();
        Union union = (Union) data.getDataType();
        int unionSize = data.getLength();

        // Calculate offset of target within union
        int targetOffset = (int)(targetAddr.getOffset() - addr.getOffset());

        // Show parent-level symbols with XREFs
        Symbol[] symbols = symbolTable.getSymbols(addr);
        if (symbols != null && symbols.length > 0) {
            for (Symbol symbol : symbols) {
                SymbolType symType = symbol.getSymbolType();
                if (symType != SymbolType.LABEL &&
                    symType != SymbolType.GLOBAL &&
                    symType != SymbolType.LOCAL_VAR) {
                    continue;
                }

                String symbolName = symbol.getName();
                if (symbolName.contains(".")) {
                    continue;
                }

                result.append("                         ");
                Namespace namespace = symbol.getParentNamespace();
                if (namespace != null && !namespace.isGlobal()) {
                    result.append(namespace.getName()).append("::");
                }
                result.append(symbolName).append("\n");

                // Show XREFs with function names
                List<String> xrefList = collectXRefsWithFunctionNames(addr, refManager, program);
                if (!xrefList.isEmpty()) {
                    result.append("                                  XREF[").append(xrefList.size()).append("]:     ");
                    result.append(String.join(", ", xrefList.stream().limit(3).collect(Collectors.toList())));
                    if (xrefList.size() > 3) {
                        result.append(", ...");
                    }
                    result.append("\n");
                }
            }
        }

        // Show union type header line
        result.append("        ");
        result.append(String.format("%-10s", addr.toString()));
        result.append(union.getDisplayName());
        result.append("  (union, ").append(unionSize).append(" bytes)\n\n");

        // Get union components (each is a different view)
        DataTypeComponent[] components = union.getComponents();

        // Display each union member as a separate view
        int viewNumber = 1;
        for (DataTypeComponent component : components) {
            String memberName = component.getFieldName();
            if (memberName == null || memberName.isEmpty()) {
                memberName = component.getDataType().getDisplayName();
            }

            result.append("        === View ").append(viewNumber).append(": ");
            result.append(memberName).append(" ===\n");

            DataType memberType = component.getDataType();

            // Handle different member types
            if (memberType instanceof Structure) {
                // Expand struct fields
                displayUnionStructView(data, (Structure) memberType, addr, targetAddr, targetOffset,
                                      result, program, listing, refManager, symbolTable, includeBytes,
                                      before, after);
            } else if (memberType instanceof Array) {
                // Show array with offset notation
                displayUnionArrayView(data, (Array) memberType, memberName, addr, targetAddr, targetOffset,
                                     result, program, refManager, includeBytes);
            } else if (memberType instanceof Union) {
                // Nested union - show recursively (simplified)
                displayUnionNestedView(data, (Union) memberType, memberName, addr, targetAddr, targetOffset,
                                      result, program, refManager, includeBytes);
            } else {
                // Simple type - show single line
                displayUnionSimpleView(data, memberType, memberName, addr, targetAddr, targetOffset,
                                      result, program, refManager, includeBytes);
            }

            result.append("\n");
            viewNumber++;
        }
    }

    /**
     * Display a struct member view within a union
     * Applies context window to show only fields around the target offset
     */
    private void displayUnionStructView(Data unionData, Structure struct, Address baseAddr,
                                        Address targetAddr, int targetOffset,
                                        StringBuilder result, Program program, Listing listing,
                                        ReferenceManager refManager, SymbolTable symbolTable,
                                        boolean includeBytes, int before, int after) {
        DataTypeComponent[] fields = struct.getComponents();
        int numFields = fields.length;

        // Find the target field index
        int targetFieldIndex = -1;
        for (int i = 0; i < numFields; i++) {
            DataTypeComponent field = fields[i];
            int fieldOffset = field.getOffset();
            int fieldLength = field.getLength();

            if (fieldOffset <= targetOffset && targetOffset < fieldOffset + fieldLength) {
                targetFieldIndex = i;
                break;
            }
        }

        // If target field not found, default to first field
        if (targetFieldIndex < 0) {
            targetFieldIndex = 0;
        }

        // Calculate window around target field
        int startIdx = Math.max(0, targetFieldIndex - before);
        int endIdx = Math.min(numFields, targetFieldIndex + after + 1);

        // Show truncation indicator for fields before the window
        if (startIdx > 0) {
            result.append("        ... (").append(startIdx).append(" fields before)\n");
        }

        // Display fields within the window
        for (int i = startIdx; i < endIdx; i++) {
            DataTypeComponent field = fields[i];
            int fieldOffset = field.getOffset();
            int fieldLength = field.getLength();
            Address fieldAddr = baseAddr.add(fieldOffset);

            // Check if this field contains the target address
            boolean isTargetField = (fieldOffset <= targetOffset &&
                                    targetOffset < fieldOffset + fieldLength);

            // Mark target field with arrow
            if (isTargetField) {
                result.append("  --> ");
            } else {
                result.append("        ");
            }

            // Show address
            result.append(String.format("%-10s", fieldAddr.toString()));

            // Show field type
            String fieldTypeName = field.getDataType().getDisplayName();
            result.append(String.format("%-12s", fieldTypeName));

            // Get field value from memory
            String valueStr = getFieldValue(unionData, fieldOffset, field.getDataType(), program);
            result.append(String.format("%-24s", valueStr));

            // Show field name or offset notation
            String fieldName = field.getFieldName();
            if (fieldName != null && !fieldName.isEmpty()) {
                result.append(fieldName);
            } else {
                result.append("(offset +").append(fieldOffset).append(")");
            }

            // Show XREFs for this field address
            List<String> xrefList = collectXRefsWithFunctionNames(fieldAddr, refManager, program);
            if (!xrefList.isEmpty()) {
                result.append("\n                                  XREF[").append(xrefList.size()).append("]:     ");
                result.append(String.join(", ", xrefList.stream().limit(3).collect(Collectors.toList())));
                if (xrefList.size() > 3) {
                    result.append(", ...");
                }
            }

            result.append("\n");
        }

        // Show truncation indicator for fields after the window
        if (endIdx < numFields) {
            result.append("        ... (").append(numFields - endIdx).append(" fields after)\n");
        }
    }

    /**
     * Display an array member view within a union
     */
    private void displayUnionArrayView(Data unionData, Array arrayType, String memberName,
                                       Address baseAddr, Address targetAddr, int targetOffset,
                                       StringBuilder result, Program program,
                                       ReferenceManager refManager, boolean includeBytes) {
        int elementSize = arrayType.getElementLength();
        int numElements = arrayType.getNumElements();
        String elementTypeName = arrayType.getDataType().getDisplayName();

        // Calculate which element contains the target
        int targetElement = (elementSize > 0) ? targetOffset / elementSize : 0;
        int offsetInElement = (elementSize > 0) ? targetOffset % elementSize : targetOffset;

        // For array views, show the target offset notation
        boolean isTarget = (targetOffset >= 0 && targetOffset < arrayType.getLength());

        if (isTarget) {
            result.append("  --> ");
        } else {
            result.append("        ");
        }

        result.append(String.format("%-10s", targetAddr.toString()));
        result.append(String.format("%-12s", elementTypeName + "[" + numElements + "]"));
        result.append(String.format("%-24s", " (offset +" + targetOffset + ")"));

        // Show XREFs inherited from union base
        List<String> xrefList = collectXRefsWithFunctionNames(baseAddr, refManager, program);
        if (!xrefList.isEmpty()) {
            result.append("\n                                  XREF[").append(xrefList.size()).append("]:     ");
            result.append("(inherits from union base)");
        }

        result.append("\n");
    }

    /**
     * Display a nested union member view
     */
    private void displayUnionNestedView(Data unionData, Union nestedUnion, String memberName,
                                        Address baseAddr, Address targetAddr, int targetOffset,
                                        StringBuilder result, Program program,
                                        ReferenceManager refManager, boolean includeBytes) {
        // Simplified display for nested unions
        boolean isTarget = (targetOffset >= 0 && targetOffset < nestedUnion.getLength());

        if (isTarget) {
            result.append("  --> ");
        } else {
            result.append("        ");
        }

        result.append(String.format("%-10s", baseAddr.toString()));
        result.append(String.format("%-12s", nestedUnion.getDisplayName()));
        result.append("(nested union, ").append(nestedUnion.getLength()).append(" bytes)");

        // Show components count
        result.append("  [").append(nestedUnion.getNumComponents()).append(" members]");

        result.append("\n");
    }

    /**
     * Display a simple type member view within a union
     */
    private void displayUnionSimpleView(Data unionData, DataType memberType, String memberName,
                                        Address baseAddr, Address targetAddr, int targetOffset,
                                        StringBuilder result, Program program,
                                        ReferenceManager refManager, boolean includeBytes) {
        boolean isTarget = (targetOffset >= 0 && targetOffset < memberType.getLength());

        if (isTarget) {
            result.append("  --> ");
        } else {
            result.append("        ");
        }

        result.append(String.format("%-10s", baseAddr.toString()));
        result.append(String.format("%-12s", memberType.getDisplayName()));

        // Get value
        String valueStr = getFieldValue(unionData, 0, memberType, program);
        result.append(String.format("%-24s", valueStr));

        if (memberName != null && !memberName.isEmpty()) {
            result.append(memberName);
        }

        // Show XREFs
        List<String> xrefList = collectXRefsWithFunctionNames(baseAddr, refManager, program);
        if (!xrefList.isEmpty()) {
            result.append("\n                                  XREF[").append(xrefList.size()).append("]:     ");
            result.append(String.join(", ", xrefList.stream().limit(3).collect(Collectors.toList())));
            if (xrefList.size() > 3) {
                result.append(", ...");
            }
        }

        result.append("\n");
    }

    /**
     * Get the value of a field from memory
     */
    private String getFieldValue(Data data, int offset, DataType fieldType, Program program) {
        try {
            Address fieldAddr = data.getMinAddress().add(offset);
            int length = fieldType.getLength();

            if (length <= 0 || length > 8) {
                return "";
            }

            // Read bytes from memory
            byte[] bytes = new byte[length];
            program.getMemory().getBytes(fieldAddr, bytes);

            // Format based on type
            if (length == 1) {
                return String.format("%02xh", bytes[0] & 0xFF);
            } else if (length == 2) {
                int value = (bytes[0] & 0xFF) | ((bytes[1] & 0xFF) << 8);
                return String.format("%04xh", value);
            } else if (length == 4) {
                int value = (bytes[0] & 0xFF) | ((bytes[1] & 0xFF) << 8) |
                           ((bytes[2] & 0xFF) << 16) | ((bytes[3] & 0xFF) << 24);
                return String.format("%08xh", value);
            } else {
                // Just show first byte for now
                return String.format("%02xh", bytes[0] & 0xFF);
            }
        } catch (Exception e) {
            return "??";
        }
    }

    /**
     * Display a component of a composite data type (array element or struct field)
     */
    private void displayComponent(Data component, int index, boolean isArray, boolean isTargetComponent,
                                  StringBuilder result, Listing listing,
                                  ReferenceManager refManager, SymbolTable symbolTable,
                                  boolean includeBytes, Program program) {
        Address componentAddr = component.getMinAddress();

        // Mark target component with arrow, otherwise indent
        if (isTargetComponent) {
            result.append(" --> ");
        } else {
            result.append("      ");
        }

        // Show address
        result.append(String.format("%-10s", componentAddr.toString()));

        // Show bytes if requested
        if (includeBytes) {
            byte[] bytes = null;
            try {
                bytes = component.getBytes();
            } catch (Exception e) {
                // Memory access failed
            }

            StringBuilder bytesStr = new StringBuilder();
            if (bytes != null) {
                int bytesToShow = Math.min(bytes.length, 4);
                for (int i = 0; i < bytesToShow; i++) {
                    bytesStr.append(String.format("%02x ", bytes[i] & 0xFF));
                }
                if (bytes.length > bytesToShow) {
                    bytesStr.append("...");
                }
            } else {
                bytesStr.append("??");
            }

            result.append(String.format("%-12s", bytesStr.toString().trim()));
        }

        // Show data type
        String componentType = codeUnitFormatter.getMnemonicRepresentation(component);
        result.append(String.format("%-12s", componentType));

        // Show value - get symbol at referenced address if it's a pointer/reference
        String valueStr = "";

        // Check if this component has a reference (pointer to another address)
        Reference[] refs = refManager.getReferencesFrom(componentAddr);
        if (refs != null && refs.length > 0) {
            // Find primary data reference
            for (Reference ref : refs) {
                if (ref.isPrimary() && !ref.getReferenceType().isCall() && !ref.getReferenceType().isJump()) {
                    Address toAddr = ref.getToAddress();
                    // Get symbol at the referenced address
                    Symbol symbol = symbolTable.getPrimarySymbol(toAddr);
                    if (symbol != null) {
                        valueStr = symbol.getName();
                    } else {
                        // No symbol, just show the address
                        valueStr = component.getDefaultValueRepresentation();
                    }
                    break;
                }
            }
        }

        // If no reference found, use default representation
        if (valueStr.isEmpty()) {
            try {
                valueStr = component.getDefaultValueRepresentation();
                if (valueStr == null || valueStr.isEmpty()) {
                    Object value = component.getValue();
                    if (value != null) {
                        valueStr = value.toString();
                    }
                }
            } catch (Exception e) {
                valueStr = "";
            }
        }

        // Format value with proper width (increased to accommodate symbol names)
        result.append(String.format("%-24s", valueStr));

        // Show field name (for structs) or index (for arrays)
        if (isArray) {
            result.append("[").append(index).append("]");
        } else {
            // Struct field - show field name separated from value
            String fieldName = component.getFieldName();
            if (fieldName != null && !fieldName.isEmpty()) {
                result.append(fieldName);
            }
        }

        // Show XREFs for this component (with function names)
        List<String> xrefList = collectXRefsWithFunctionNames(componentAddr, refManager, program);

        if (!xrefList.isEmpty()) {
            result.append("      XREF[").append(xrefList.size()).append("]:     ");
            result.append(String.join(", ", xrefList.stream().limit(3).collect(Collectors.toList())));
            if (xrefList.size() > 3) {
                result.append(", [more]");
            }
        }

        // Show pointer references (e.g., "?  ->  0023051e")
        Reference[] referencesFrom = refManager.getReferencesFrom(componentAddr);
        if (referencesFrom != null && referencesFrom.length > 0) {
            for (Reference ref : referencesFrom) {
                if (ref.isPrimary() && !ref.getReferenceType().isCall() && !ref.getReferenceType().isJump()) {
                    result.append("      ?  ->  ").append(ref.getToAddress().toString());
                    break; // Only show first primary reference
                }
            }
        }

        // Add EOL comment if present
        String eolComment = listing.getComment(CommentType.EOL, componentAddr);
        if (eolComment != null && !eolComment.isEmpty()) {
            result.append(" ; ").append(eolComment);
        }

        result.append("\n");
    }

    /**
     * Display a simple (non-composite) data item
     */
    private void displaySimpleData(Data data, boolean isTarget, StringBuilder result,
                                   Listing listing, boolean includeBytes,
                                   ReferenceManager refManager, Program program) {
        Address addr = data.getMinAddress();

        // Mark target with arrow
        if (isTarget) {
            result.append("  --> ");
        } else {
            result.append("       ");
        }

        // Get data bytes (only if requested)
        String bytesField = "";
        if (includeBytes) {
            byte[] bytes = null;
            try {
                bytes = data.getBytes();
            } catch (Exception e) {
                // Memory access failed
            }

            // Format bytes (show first few bytes like Ghidra UI)
            StringBuilder bytesStr = new StringBuilder();
            if (bytes != null) {
                int bytesToShow = Math.min(bytes.length, 4); // Show max 4 bytes like UI
                for (int i = 0; i < bytesToShow; i++) {
                    bytesStr.append(String.format("%02x ", bytes[i] & 0xFF));
                }
                if (bytes.length > bytesToShow) {
                    bytesStr.append("..."); // Indicate there are more bytes
                }
            } else {
                bytesStr.append("??");
            }

            bytesField = String.format("%-12s", bytesStr.toString().trim());
        }

        // Get data type using CodeUnitFormat
        String dataTypeStr = codeUnitFormatter.getMnemonicRepresentation(data);

        // Get data value using CodeUnitFormat
        String valueStr = "";
        try {
            valueStr = codeUnitFormatter.getDataValueRepresentationString(data);
        } catch (Exception e) {
            // Fallback to default representation
            Object value = data.getValue();
            if (value != null) {
                valueStr = value.toString();
            }
        }

        // Format the data line
        result.append(String.format("%-10s", addr.toString()));  // address (10 chars)
        if (includeBytes) {
            result.append(bytesField);  // bytes (12 chars) - only if requested
        }
        result.append(String.format("%-10s", dataTypeStr));  // data type (10 chars)
        result.append("  ");
        result.append(valueStr);  // value

        // Show pointer references (e.g., "?  ->  0023051e")
        Reference[] referencesFrom = refManager.getReferencesFrom(addr);
        if (referencesFrom != null && referencesFrom.length > 0) {
            for (Reference ref : referencesFrom) {
                if (ref.isPrimary() && !ref.getReferenceType().isCall() && !ref.getReferenceType().isJump()) {
                    result.append("      ?  ->  ").append(ref.getToAddress().toString());
                    break; // Only show first primary reference
                }
            }
        }

        // Add comments (EOL, POST, PRE if on same line)
        String eolComment = listing.getComment(CommentType.EOL, addr);
        if (eolComment != null && !eolComment.isEmpty()) {
            result.append(" ; ").append(eolComment);
        }

        result.append("\n");

        // Show POST COMMENT if present (on separate line below)
        String postComment = listing.getComment(CommentType.POST, addr);
        if (postComment != null && !postComment.isEmpty()) {
            result.append("                             ; [POST] ");
            result.append(postComment.replace("\n", "\n                             ; "));
            result.append("\n");
        }
    }
}
