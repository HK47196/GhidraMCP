package com.lauriewired.services;

import com.lauriewired.util.PluginUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
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
     * @return Formatted string of references
     */
    public String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);

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
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get references from a given address
     * @param addressStr Address as string
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Formatted string of references
     */
    public String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();

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
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }

                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }

            return PluginUtils.paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all cross-references to a function by name
     * @param functionName Name of the function
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Formatted string of references
     */
    public String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
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
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }
}
