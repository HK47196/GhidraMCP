package com.lauriewired.services;

import com.lauriewired.util.PluginUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Service for analyzing cross-references in Ghidra programs
 */
public class CrossReferenceAnalyzer {

    private final FunctionNavigator navigator;

    public CrossReferenceAnalyzer(FunctionNavigator navigator) {
        this.navigator = navigator;
    }

    /**
     * Get references to a given address
     * @param addressStr Address as string
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @param includeInstruction Whether to include instruction text
     * @param includeIndirect Whether to track pointer-based accesses
     * @param analysisDepth Max depth for pointer chain tracing
     * @return Formatted string of references
     */
    public String getXrefsTo(String addressStr, int offset, int limit, boolean includeInstruction,
                             boolean includeIndirect, int analysisDepth) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        // Validate analysis depth
        if (analysisDepth < 1 || analysisDepth > 50) {
            return "Error: analysis_depth must be between 1 and 50";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            StringBuilder result = new StringBuilder();

            // Get direct references (existing logic)
            String directRefs = getDirectReferences(addr, offset, limit, includeInstruction);
            result.append(directRefs);

            // Get indirect references (new logic)
            if (includeIndirect) {
                String indirectRefs = getIndirectReferences(addr, analysisDepth, includeInstruction);
                if (!indirectRefs.isEmpty()) {
                    result.append("\n\n").append(indirectRefs);
                }
            }

            return result.toString();
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get references to a given address (backward compatibility method)
     * @param addressStr Address as string
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @param includeInstruction Whether to include instruction text at each xref location
     * @return Formatted string of references
     */
    public String getXrefsTo(String addressStr, int offset, int limit, boolean includeInstruction) {
        return getXrefsTo(addressStr, offset, limit, includeInstruction, true, 10);
    }

    /**
     * Get references to a given address (backward compatibility method)
     * @param addressStr Address as string
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Formatted string of references
     */
    public String getXrefsTo(String addressStr, int offset, int limit) {
        return getXrefsTo(addressStr, offset, limit, false, true, 10);
    }

    /**
     * Get direct references to an address (refactored from original getXrefsTo)
     * @param addr Address to get references to
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @param includeInstruction Whether to include instruction text
     * @return Formatted string of direct references
     */
    private String getDirectReferences(Address addr, int offset, int limit, boolean includeInstruction) {
        Program program = navigator.getCurrentProgram();
        ReferenceManager refManager = program.getReferenceManager();
        Listing listing = program.getListing();

        ReferenceIterator refIter = refManager.getReferencesTo(addr);

        if (includeInstruction) {
            // Use grouped format when instructions are included
            Map<String, List<String>> refsByType = new LinkedHashMap<>();

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                String typeName = refType.getName();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                String instrStr = getInstructionString(listing, fromAddr);

                String refEntry = String.format("  %s%s: %s", fromAddr, funcInfo, instrStr);

                refsByType.computeIfAbsent(typeName, k -> new ArrayList<>()).add(refEntry);
            }

            return formatGroupedRefs(refsByType, offset, limit);
        } else {
            // Use simple list format when instructions are not included
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            return PluginUtils.paginateList(refs, offset, limit);
        }
    }

    /**
     * Get references from a given address
     * @param addressStr Address as string
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @param includeInstruction Whether to include instruction text at the source address
     * @return Formatted string of references
     */
    public String getXrefsFrom(String addressStr, int offset, int limit, boolean includeInstruction) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            Listing listing = program.getListing();

            Reference[] references = refManager.getReferencesFrom(addr);

            if (includeInstruction) {
                // Use grouped format when instructions are included
                Map<String, List<String>> refsByType = new LinkedHashMap<>();

                for (Reference ref : references) {
                    Address toAddr = ref.getToAddress();
                    RefType refType = ref.getReferenceType();
                    String typeName = refType.getName();

                    String targetInfo = "";
                    Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                    if (toFunc != null) {
                        targetInfo = " to function " + toFunc.getName();
                    } else {
                        Data data = listing.getDataAt(toAddr);
                        if (data != null) {
                            targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                        }
                    }

                    String instrStr = getInstructionString(listing, addr);
                    String refEntry = String.format("  %s%s: %s", toAddr, targetInfo, instrStr);

                    refsByType.computeIfAbsent(typeName, k -> new ArrayList<>()).add(refEntry);
                }

                return formatGroupedRefs(refsByType, offset, limit);
            } else {
                // Use simple list format when instructions are not included
                List<String> refs = new ArrayList<>();
                for (Reference ref : references) {
                    Address toAddr = ref.getToAddress();
                    RefType refType = ref.getReferenceType();

                    String targetInfo = "";
                    Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                    if (toFunc != null) {
                        targetInfo = " to function " + toFunc.getName();
                    } else {
                        Data data = listing.getDataAt(toAddr);
                        if (data != null) {
                            targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                        }
                    }

                    refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
                }
                return PluginUtils.paginateList(refs, offset, limit);
            }
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get references from a given address (backward compatibility method)
     * @param addressStr Address as string
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Formatted string of references
     */
    public String getXrefsFrom(String addressStr, int offset, int limit) {
        return getXrefsFrom(addressStr, offset, limit, false);
    }

    /**
     * Get all cross-references to a function by name
     * @param functionName Name of the function
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @param includeInstruction Whether to include instruction text at each xref location
     * @return Formatted string of references
     */
    public String getFunctionXrefs(String functionName, int offset, int limit, boolean includeInstruction) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            FunctionManager funcManager = program.getFunctionManager();
            Listing listing = program.getListing();

            if (includeInstruction) {
                // Use grouped format when instructions are included
                Map<String, List<String>> refsByType = new LinkedHashMap<>();

                for (Function function : funcManager.getFunctions(true)) {
                    if (function.getName().equals(functionName)) {
                        Address entryPoint = function.getEntryPoint();
                        ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);

                        while (refIter.hasNext()) {
                            Reference ref = refIter.next();
                            Address fromAddr = ref.getFromAddress();
                            RefType refType = ref.getReferenceType();
                            String typeName = refType.getName();

                            Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                            String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                            String instrStr = getInstructionString(listing, fromAddr);

                            String refEntry = String.format("  %s%s: %s", fromAddr, funcInfo, instrStr);
                            refsByType.computeIfAbsent(typeName, k -> new ArrayList<>()).add(refEntry);
                        }
                    }
                }

                if (refsByType.isEmpty()) {
                    return "No references found to function: " + functionName;
                }

                return formatGroupedRefs(refsByType, offset, limit);
            } else {
                // Use simple list format when instructions are not included
                List<String> refs = new ArrayList<>();
                for (Function function : funcManager.getFunctions(true)) {
                    if (function.getName().equals(functionName)) {
                        Address entryPoint = function.getEntryPoint();
                        ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);

                        while (refIter.hasNext()) {
                            Reference ref = refIter.next();
                            Address fromAddr = ref.getFromAddress();
                            RefType refType = ref.getReferenceType();

                            Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                            String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                            refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                        }
                    }
                }

                if (refs.isEmpty()) {
                    return "No references found to function: " + functionName;
                }

                return PluginUtils.paginateList(refs, offset, limit);
            }
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

    /**
     * Get all cross-references to a function by name (backward compatibility method)
     * @param functionName Name of the function
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Formatted string of references
     */
    public String getFunctionXrefs(String functionName, int offset, int limit) {
        return getFunctionXrefs(functionName, offset, limit, false);
    }

    /**
     * Helper method to get the instruction string at a given address
     * @param listing Program listing
     * @param addr Address to get instruction from
     * @return Formatted instruction string
     */
    private String getInstructionString(Listing listing, Address addr) {
        Instruction instr = listing.getInstructionAt(addr);
        if (instr != null) {
            // Build instruction string: mnemonic + operands
            String mnemonic = instr.getMnemonicString();
            String operands = "";
            int numOperands = instr.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                if (i > 0) {
                    operands += ",";
                }
                operands += instr.getDefaultOperandRepresentation(i);
            }
            return mnemonic + " " + operands;
        } else {
            // Not an instruction, might be data
            Data data = listing.getDataAt(addr);
            if (data != null) {
                return "[DATA: " + data.getDataType().getDisplayName() + "]";
            }
            return "[UNDEFINED]";
        }
    }

    /**
     * Format references grouped by type
     * @param refsByType Map of reference type to list of reference entries
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Formatted string with grouped references
     */
    private String formatGroupedRefs(Map<String, List<String>> refsByType, int offset, int limit) {
        StringBuilder result = new StringBuilder();

        // Calculate total count
        int totalCount = 0;
        for (List<String> refs : refsByType.values()) {
            totalCount += refs.size();
        }

        // Apply pagination to groups
        int currentIndex = 0;
        int itemsAdded = 0;

        for (Map.Entry<String, List<String>> entry : refsByType.entrySet()) {
            String typeName = entry.getKey();
            List<String> refs = entry.getValue();

            // Skip entries before offset
            if (currentIndex + refs.size() <= offset) {
                currentIndex += refs.size();
                continue;
            }

            // Calculate how many items from this group to include
            int startIdx = Math.max(0, offset - currentIndex);
            int endIdx = Math.min(refs.size(), startIdx + (limit - itemsAdded));

            if (startIdx >= refs.size()) {
                currentIndex += refs.size();
                continue;
            }

            // Add group header
            int groupCount = refs.size();
            if (result.length() > 0) {
                result.append("\n");
            }
            result.append(String.format("%s (%d):\n", typeName, groupCount));

            // Add references from this group
            for (int i = startIdx; i < endIdx; i++) {
                result.append(refs.get(i)).append("\n");
                itemsAdded++;
            }

            currentIndex += refs.size();

            // Stop if we've reached the limit
            if (itemsAdded >= limit) {
                break;
            }
        }

        // Add pagination info
        if (totalCount > limit) {
            int showing = Math.min(limit, totalCount - offset);
            result.append(String.format("\n[Showing %d-%d of %d total references]",
                offset + 1, offset + showing, totalCount));
        }

        return result.toString().trim();
    }

    /**
     * Get indirect references via pointers
     * @param targetAddr Target address to find pointer-based accesses for
     * @param analysisDepth Max depth for pointer chain tracing
     * @param includeInstruction Whether to include instruction context
     * @return Formatted string of indirect references
     */
    private String getIndirectReferences(Address targetAddr, int analysisDepth, boolean includeInstruction) {
        Program program = navigator.getCurrentProgram();
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();

        // Find all pointers to target
        List<PointerInfo> pointers = findPointersTo(targetAddr);
        if (pointers.isEmpty()) {
            return "";
        }

        // Group results by pointer name
        Map<String, List<IndirectAccess>> accessesByPointer = new LinkedHashMap<>();

        for (PointerInfo pointer : pointers) {
            if (pointer.chainDepth > analysisDepth) {
                continue; // Skip if chain too deep
            }

            // Find all functions that reference this pointer
            ReferenceIterator refsToPointer = refManager.getReferencesTo(pointer.pointerAddress);

            while (refsToPointer.hasNext()) {
                Reference ref = refsToPointer.next();
                Address fromAddr = ref.getFromAddress();

                // Get containing function
                Function func = funcManager.getFunctionContaining(fromAddr);
                if (func == null) {
                    continue;
                }

                // Scan function for pointer dereferences
                List<IndirectAccess> accesses = findPointerDereferencesInFunction(
                    func, pointer, includeInstruction);

                for (IndirectAccess access : accesses) {
                    accessesByPointer
                        .computeIfAbsent(pointer.pointerName, k -> new ArrayList<>())
                        .add(access);
                }
            }
        }

        // Format results
        return formatIndirectAccesses(accessesByPointer);
    }

    /**
     * Find pointer variables that point to the target address
     * @param targetAddr Address to find pointers to
     * @return List of pointer information
     */
    private List<PointerInfo> findPointersTo(Address targetAddr) {
        List<PointerInfo> pointers = new ArrayList<>();
        Program program = navigator.getCurrentProgram();
        Listing listing = program.getListing();
        ReferenceManager refManager = program.getReferenceManager();

        // Strategy 1: Find pointer-type data that references target
        ReferenceIterator refsToTarget = refManager.getReferencesTo(targetAddr);
        while (refsToTarget.hasNext()) {
            Reference ref = refsToTarget.next();
            Address fromAddr = ref.getFromAddress();

            // Check if the reference comes from a data location
            Data data = listing.getDataContaining(fromAddr);
            if (data != null && data.isPointer()) {
                // This is a pointer variable
                String pointerName = getDataLabel(data);
                Address pointerAddr = data.getAddress();
                pointers.add(new PointerInfo(pointerAddr, pointerName, targetAddr, 1));
            }
        }

        // Strategy 2: Look for symbols with "Ptr" in name near target
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbols = symbolTable.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            String name = symbol.getName();

            // Heuristic: names like "g_BufferPtr", "pData", etc.
            if (name.toLowerCase().contains("ptr") ||
                name.toLowerCase().contains("pointer") ||
                name.startsWith("p") && name.length() > 1 && Character.isUpperCase(name.charAt(1))) {

                Address symbolAddr = symbol.getAddress();
                Data data = listing.getDataAt(symbolAddr);

                if (data != null && data.isPointer()) {
                    try {
                        Address target = (Address) data.getValue();
                        // Check if this pointer could reference our target range
                        if (target != null && target.equals(targetAddr)) {
                            pointers.add(new PointerInfo(symbolAddr, name, target, 1));
                        }
                    } catch (Exception e) {
                        // Not a valid pointer, skip
                    }
                }
            }
        }

        return pointers;
    }

    /**
     * Get label for a data item, with fallback
     * @param data Data item to get label for
     * @return Label name or generated name
     */
    private String getDataLabel(Data data) {
        Symbol primary = data.getPrimarySymbol();
        if (primary != null) {
            return primary.getName();
        }
        // Fallback to address-based name
        return "PTR_" + data.getAddress().toString();
    }

    /**
     * Find where a pointer is dereferenced in a function
     * @param func Function to scan
     * @param pointer Pointer information
     * @param includeInstruction Whether to include instruction context
     * @return List of indirect accesses
     */
    private List<IndirectAccess> findPointerDereferencesInFunction(
            Function func, PointerInfo pointer, boolean includeInstruction) {

        List<IndirectAccess> accesses = new ArrayList<>();
        Program program = navigator.getCurrentProgram();
        Listing listing = program.getListing();

        // Iterate through all instructions in function
        InstructionIterator instructions = listing.getInstructions(func.getBody(), true);

        // Track which registers might hold the pointer
        Set<String> pointerRegisters = new HashSet<>();
        List<String> contextInstructions = new ArrayList<>();

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();

            // Check if instruction loads the pointer into a register
            if (referencesAddress(instr, pointer.pointerAddress)) {
                // This instruction loads our pointer
                String destReg = getDestinationRegister(instr);
                if (destReg != null) {
                    pointerRegisters.add(destReg);
                    contextInstructions.clear();
                    contextInstructions.add(formatInstruction(instr));
                }
            }

            // Check if instruction dereferences a pointer register
            if (!pointerRegisters.isEmpty() && isMemoryDereference(instr, pointerRegisters)) {
                // Found a dereference!
                IndirectAccess access = new IndirectAccess();
                access.accessAddress = instr.getAddress();
                access.function = func;
                access.instruction = formatInstruction(instr);
                access.contextLines = new ArrayList<>(contextInstructions);
                access.contextLines.add(access.instruction);

                accesses.add(access);

                // Reset context for next access
                contextInstructions.clear();
            }

            // Keep last few instructions as context
            if (pointerRegisters.isEmpty() || contextInstructions.size() < 5) {
                if (!contextInstructions.isEmpty() || referencesAddress(instr, pointer.pointerAddress)) {
                    contextInstructions.add(formatInstruction(instr));
                    if (contextInstructions.size() > 5) {
                        contextInstructions.remove(0);
                    }
                }
            }
        }

        return accesses;
    }

    /**
     * Check if instruction references a specific address
     * @param instr Instruction to check
     * @param targetAddr Target address
     * @return True if instruction references the address
     */
    private boolean referencesAddress(Instruction instr, Address targetAddr) {
        Reference[] refs = instr.getReferencesFrom();
        for (Reference ref : refs) {
            if (ref.getToAddress().equals(targetAddr)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get destination register from instruction
     * @param instr Instruction to analyze
     * @return Register name or null
     */
    private String getDestinationRegister(Instruction instr) {
        // For move/load instructions, first operand is usually destination
        int numOperands = instr.getNumOperands();
        if (numOperands >= 1) {
            Object[] opObjs = instr.getOpObjects(0);
            for (Object obj : opObjs) {
                if (obj instanceof ghidra.program.model.lang.Register) {
                    return obj.toString();
                }
            }
        }
        return null;
    }

    /**
     * Check if instruction dereferences memory via pointer register
     * @param instr Instruction to check
     * @param pointerRegisters Set of registers that may contain pointers
     * @return True if instruction dereferences via pointer register
     */
    private boolean isMemoryDereference(Instruction instr, Set<String> pointerRegisters) {
        // Check each operand for indirect addressing using our tracked registers
        int numOperands = instr.getNumOperands();

        for (int i = 0; i < numOperands; i++) {
            int opType = instr.getOperandType(i);

            // Check if operand is indirect (memory access)
            if ((opType & OperandType.INDIRECT) != 0) {
                // Check if it uses one of our pointer registers
                Object[] opObjs = instr.getOpObjects(i);
                for (Object obj : opObjs) {
                    if (obj instanceof ghidra.program.model.lang.Register) {
                        String reg = obj.toString();
                        if (pointerRegisters.contains(reg)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * Format instruction with address
     * @param instr Instruction to format
     * @return Formatted instruction string
     */
    private String formatInstruction(Instruction instr) {
        return String.format("%s: %s", instr.getAddress(), instr.toString());
    }

    /**
     * Format indirect accesses by pointer
     * @param accessesByPointer Map of pointer name to list of accesses
     * @return Formatted string
     */
    private String formatIndirectAccesses(Map<String, List<IndirectAccess>> accessesByPointer) {
        StringBuilder result = new StringBuilder();

        int totalIndirect = 0;
        for (List<IndirectAccess> accesses : accessesByPointer.values()) {
            totalIndirect += accesses.size();
        }

        for (Map.Entry<String, List<IndirectAccess>> entry : accessesByPointer.entrySet()) {
            String pointerName = entry.getKey();
            List<IndirectAccess> accesses = entry.getValue();

            result.append(String.format("INDIRECT ACCESS via %s (%d):\n", pointerName, accesses.size()));

            for (IndirectAccess access : accesses) {
                result.append(String.format("\n  %s in %s:\n",
                    access.accessAddress, access.function.getName()));

                for (String contextLine : access.contextLines) {
                    result.append("    ").append(contextLine).append("\n");
                }

                result.append("    [Pointer-based access - inspect this function manually]\n");
            }
        }

        result.append(String.format("\nTotal indirect accesses: %d", totalIndirect));

        return result.toString();
    }

    /**
     * Simple struct to hold pointer information
     */
    private static class PointerInfo {
        Address pointerAddress;
        String pointerName;
        Address targetAddress;
        int chainDepth;

        PointerInfo(Address pointerAddress, String pointerName, Address targetAddress, int chainDepth) {
            this.pointerAddress = pointerAddress;
            this.pointerName = pointerName;
            this.targetAddress = targetAddress;
            this.chainDepth = chainDepth;
        }
    }

    /**
     * Simple struct for indirect access info
     */
    private static class IndirectAccess {
        Address accessAddress;
        Function function;
        String instruction;
        List<String> contextLines;
    }
}
