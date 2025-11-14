package com.lauriewired.services;

import com.lauriewired.util.PluginUtils;
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
import java.util.List;

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
     * @param includeInstruction Whether to include instruction text at each xref location
     * @return Formatted string of references
     */
    public String getXrefsTo(String addressStr, int offset, int limit, boolean includeInstruction) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            Listing listing = program.getListing();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);

            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                if (includeInstruction) {
                    String instrStr = getInstructionString(listing, fromAddr);
                    refs.add(String.format("From %s%s [%s] %s", fromAddr, funcInfo, refType.getName(), instrStr));
                } else {
                    refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                }
            }

            return PluginUtils.paginateList(refs, offset, limit);
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
        return getXrefsTo(addressStr, offset, limit, false);
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

                if (includeInstruction) {
                    String instrStr = getInstructionString(listing, addr);
                    refs.add(String.format("To %s%s [%s] %s", toAddr, targetInfo, refType.getName(), instrStr));
                } else {
                    refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
                }
            }

            return PluginUtils.paginateList(refs, offset, limit);
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
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            Listing listing = program.getListing();
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

                        if (includeInstruction) {
                            String instrStr = getInstructionString(listing, fromAddr);
                            refs.add(String.format("From %s%s [%s] %s", fromAddr, funcInfo, refType.getName(), instrStr));
                        } else {
                            refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                        }
                    }
                }
            }

            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }

            return PluginUtils.paginateList(refs, offset, limit);
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
}
