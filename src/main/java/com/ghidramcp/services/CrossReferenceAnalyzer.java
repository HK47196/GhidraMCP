package com.ghidramcp.services;

import com.ghidramcp.util.PluginUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
     * @param includeInstruction Instruction context: -1 or false = none, 0 or true = instruction only, >0 = instruction + N context lines
     * @return Formatted string of references
     */
    public String getXrefsTo(String addressStr, int offset, int limit, int includeInstruction) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            Listing listing = program.getListing();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);

            if (includeInstruction >= 0) {
                // Use grouped format when instructions are included
                Map<String, List<String>> refsByType = new LinkedHashMap<>();

                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    Address fromAddr = ref.getFromAddress();
                    RefType refType = ref.getReferenceType();
                    String typeName = refType.getName();

                    Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                    String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                    String instrStr = getInstructionString(listing, fromAddr, includeInstruction);

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
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get references to a given address (backward compatibility method)
     * @param addressStr Address as string
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Formatted string of references
     */
    public String getXrefsTo(String addressStr, int offset, int limit) {
        return getXrefsTo(addressStr, offset, limit, -1);
    }

    /**
     * Get references from a given address
     * @param addressStr Address as string
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @param includeInstruction Instruction context: -1 or false = none, 0 or true = instruction only, >0 = instruction + N context lines
     * @return Formatted string of references
     */
    public String getXrefsFrom(String addressStr, int offset, int limit, int includeInstruction) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            Listing listing = program.getListing();

            Reference[] references = refManager.getReferencesFrom(addr);

            if (includeInstruction >= 0) {
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

                    String instrStr = getInstructionString(listing, addr, includeInstruction);
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
        return getXrefsFrom(addressStr, offset, limit, -1);
    }

    /**
     * Get all cross-references to a function by name
     * @param functionName Name of the function
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @param includeInstruction Instruction context: -1 or false = none, 0 or true = instruction only, >0 = instruction + N context lines
     * @return Formatted string of references
     */
    public String getFunctionXrefs(String functionName, int offset, int limit, int includeInstruction) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            FunctionManager funcManager = program.getFunctionManager();
            Listing listing = program.getListing();

            if (includeInstruction >= 0) {
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
                            String instrStr = getInstructionString(listing, fromAddr, includeInstruction);

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
        return getFunctionXrefs(functionName, offset, limit, -1);
    }

    /**
     * Helper method to get the instruction string at a given address
     * @param listing Program listing
     * @param addr Address to get instruction from
     * @param contextLines Number of context lines to include before and after (0 for just the instruction)
     * @return Formatted instruction string with optional context
     */
    private String getInstructionString(Listing listing, Address addr, int contextLines) {
        Instruction instr = listing.getInstructionAt(addr);
        if (instr != null) {
            if (contextLines <= 0) {
                // Just return the instruction at this address
                return formatSingleInstruction(instr);
            } else {
                // Include context lines before and after
                StringBuilder result = new StringBuilder();

                // Get context before
                Address currentAddr = addr;
                List<String> beforeLines = new ArrayList<>();
                for (int i = 0; i < contextLines; i++) {
                    Instruction prevInstr = listing.getInstructionBefore(currentAddr);
                    if (prevInstr == null) break;
                    beforeLines.add(0, String.format("    %s: %s",
                        prevInstr.getAddress(), formatSingleInstruction(prevInstr)));
                    currentAddr = prevInstr.getAddress();
                }

                // Add context before
                for (String line : beforeLines) {
                    result.append(line).append("\n");
                }

                // Add the main instruction (highlighted with >)
                result.append(String.format("  > %s: %s", addr, formatSingleInstruction(instr)));

                // Get context after
                currentAddr = addr;
                for (int i = 0; i < contextLines; i++) {
                    Instruction nextInstr = listing.getInstructionAfter(currentAddr);
                    if (nextInstr == null) break;
                    result.append("\n");
                    result.append(String.format("    %s: %s",
                        nextInstr.getAddress(), formatSingleInstruction(nextInstr)));
                    currentAddr = nextInstr.getAddress();
                }

                return result.toString();
            }
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
     * Format a single instruction as mnemonic + operands
     * @param instr Instruction to format
     * @return Formatted instruction string
     */
    private String formatSingleInstruction(Instruction instr) {
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
}
