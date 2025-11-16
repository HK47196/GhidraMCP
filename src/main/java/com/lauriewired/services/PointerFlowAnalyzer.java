package com.lauriewired.services;

import com.lauriewired.model.AnalysisStats;
import com.lauriewired.model.XRefThrough;
import com.lauriewired.model.XRefThroughResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.util.*;

/**
 * Analyzes pointer flow to find dereferences using raw PCode (no decompiler).
 * Phase 1 MVP: Intra-procedural analysis within functions that access the pointer.
 */
public class PointerFlowAnalyzer {

    private final Program program;
    private final DereferenceDetector dereferenceDetector;
    private final int maxResults;

    public PointerFlowAnalyzer(Program program, int maxResults) {
        this.program = program;
        this.dereferenceDetector = new DereferenceDetector(program);
        this.maxResults = maxResults;
    }

    /**
     * Analyze pointer dereferences starting from a given address.
     *
     * @param addressStr Address or symbol name
     * @param maxDepth Currently only 1 supported (intra-procedural)
     * @param accessType Filter: "all", "read", or "write"
     * @param followAliases Whether to track pointer copies
     * @return Analysis result
     */
    public XRefThroughResult analyzePointerFlow(String addressStr, int maxDepth,
                                                  String accessType, boolean followAliases) {
        long startTime = System.currentTimeMillis();
        AnalysisStats.Builder statsBuilder = new AnalysisStats.Builder();
        List<XRefThrough> allXRefs = new ArrayList<>();

        try {
            // Parse address
            Address pointerAddr = parseAddress(addressStr);
            if (pointerAddr == null) {
                return new XRefThroughResult.Builder()
                    .errorMessage("Invalid address: " + addressStr)
                    .build();
            }

            // Get pointer symbol and data type
            String symbolName = getSymbolName(pointerAddr);
            String dataTypeName = getDataTypeName(pointerAddr);

            // Find all functions that reference this pointer
            Set<Function> functionsToAnalyze = findFunctionsReferencingPointer(pointerAddr);

            if (functionsToAnalyze.isEmpty()) {
                statsBuilder.addWarning("No functions found that reference this address");
            }

            int instructionsExamined = 0;

            // Analyze each function
            for (Function function : functionsToAnalyze) {
                if (allXRefs.size() >= maxResults) {
                    statsBuilder.stoppedEarly(true);
                    break;
                }

                List<XRefThrough> functionXRefs = analyzeFunctionForPointer(
                    function, pointerAddr, followAliases);

                // Filter by access type
                for (XRefThrough xref : functionXRefs) {
                    if (matchesAccessType(xref, accessType)) {
                        allXRefs.add(xref);
                        if (allXRefs.size() >= maxResults) {
                            break;
                        }
                    }
                }

                instructionsExamined += function.getBody().getNumAddresses();
            }

            long analysisTime = System.currentTimeMillis() - startTime;

            AnalysisStats stats = statsBuilder
                .functionsAnalyzed(functionsToAnalyze.size())
                .instructionsExamined(instructionsExamined)
                .analysisTimeMs(analysisTime)
                .build();

            return new XRefThroughResult.Builder()
                .success(true)
                .pointerAddress(pointerAddr.toString())
                .pointerSymbol(symbolName)
                .dataType(dataTypeName)
                .xrefs(allXRefs)
                .analysisStats(stats)
                .build();

        } catch (Exception e) {
            long analysisTime = System.currentTimeMillis() - startTime;
            statsBuilder.analysisTimeMs(analysisTime);

            return new XRefThroughResult.Builder()
                .errorMessage("Analysis failed: " + e.getMessage())
                .analysisStats(statsBuilder.build())
                .build();
        }
    }

    /**
     * Analyze a single function for dereferences of a pointer.
     * Uses raw PCode from instructions - NO DECOMPILER.
     */
    private List<XRefThrough> analyzeFunctionForPointer(Function function, Address pointerAddr,
                                                          boolean followAliases) {
        // Track which varnodes contain the pointer value
        Set<Varnode> pointerVarnodes = trackPointerVarnodes(function, pointerAddr, followAliases);

        // Find all LOAD/STORE operations that use those varnodes
        return dereferenceDetector.findDereferences(function, pointerVarnodes);
    }

    /**
     * Track which varnodes contain the pointer value within a function.
     * This is a simplified version for MVP - tracks direct loads and copies.
     */
    private Set<Varnode> trackPointerVarnodes(Function function, Address pointerAddr,
                                                boolean followAliases) {
        Set<Varnode> pointerVarnodes = new HashSet<>();

        // Iterate through instructions in the function
        InstructionIterator instIter = program.getListing().getInstructions(function.getBody(), true);

        while (instIter.hasNext()) {
            Instruction instr = instIter.next();

            // Check if this instruction references the pointer address
            if (referencesAddress(instr, pointerAddr)) {
                // Get PCode ops for this instruction
                PcodeOp[] pcodeOps = instr.getPcode();

                if (pcodeOps != null) {
                    for (PcodeOp op : pcodeOps) {
                        // Find operations that load the pointer value
                        Varnode loaded = findPointerLoad(op, pointerAddr);
                        if (loaded != null) {
                            pointerVarnodes.add(loaded);
                        }
                    }
                }
            }
        }

        // If followAliases, track through COPY operations
        if (followAliases && !pointerVarnodes.isEmpty()) {
            Set<Varnode> aliases = trackAliases(function, pointerVarnodes);
            pointerVarnodes.addAll(aliases);
        }

        return pointerVarnodes;
    }

    /**
     * Check if an instruction references a specific address.
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
     * Find varnode that receives the pointer value from a PCode operation.
     */
    private Varnode findPointerLoad(PcodeOp op, Address pointerAddr) {
        if (op == null) {
            return null;
        }

        // Check for LOAD operation from the pointer address
        if (op.getOpcode() == PcodeOp.LOAD && op.getNumInputs() >= 2) {
            Varnode addressVn = op.getInput(1);
            if (addressVn != null && addressVn.isConstant() &&
                addressVn.getOffset() == pointerAddr.getOffset()) {
                return op.getOutput();
            }
        }

        // Check for COPY of constant address
        if (op.getOpcode() == PcodeOp.COPY && op.getNumInputs() >= 1) {
            Varnode input = op.getInput(0);
            if (input != null && input.isConstant() &&
                input.getOffset() == pointerAddr.getOffset()) {
                return op.getOutput();
            }
        }

        return null;
    }

    /**
     * Track aliases through COPY operations (simplified version).
     */
    private Set<Varnode> trackAliases(Function function, Set<Varnode> initialVarnodes) {
        Set<Varnode> aliases = new HashSet<>();
        Set<Varnode> worklist = new HashSet<>(initialVarnodes);
        Set<Varnode> processed = new HashSet<>();

        InstructionIterator instIter = program.getListing().getInstructions(function.getBody(), true);
        List<PcodeOp> allOps = new ArrayList<>();

        // Collect all PCode operations
        while (instIter.hasNext()) {
            Instruction instr = instIter.next();
            PcodeOp[] ops = instr.getPcode();
            if (ops != null) {
                allOps.addAll(Arrays.asList(ops));
            }
        }

        // Simple forward propagation through COPY operations
        while (!worklist.isEmpty()) {
            Varnode current = worklist.iterator().next();
            worklist.remove(current);
            processed.add(current);

            for (PcodeOp op : allOps) {
                if (op.getOpcode() == PcodeOp.COPY && op.getNumInputs() >= 1) {
                    Varnode input = op.getInput(0);
                    if (input != null && varnodeMatches(input, current)) {
                        Varnode output = op.getOutput();
                        if (output != null && !processed.contains(output)) {
                            aliases.add(output);
                            worklist.add(output);
                        }
                    }
                }
            }
        }

        return aliases;
    }

    /**
     * Check if two varnodes represent the same value (considering size and location).
     */
    private boolean varnodeMatches(Varnode vn1, Varnode vn2) {
        if (vn1 == null || vn2 == null) {
            return false;
        }
        return vn1.equals(vn2);
    }

    /**
     * Find all functions that reference the pointer address.
     */
    private Set<Function> findFunctionsReferencingPointer(Address pointerAddr) {
        Set<Function> functions = new HashSet<>();
        FunctionManager funcManager = program.getFunctionManager();
        ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(pointerAddr);

        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            Function func = funcManager.getFunctionContaining(ref.getFromAddress());
            if (func != null) {
                functions.add(func);
            }
        }

        return functions;
    }

    /**
     * Parse address string (can be hex address or symbol name).
     */
    private Address parseAddress(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) {
            return null;
        }

        try {
            // Try parsing as direct address
            return program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            // Try as symbol name
            SymbolIterator symbols = program.getSymbolTable().getSymbols(addressStr);
            if (symbols != null && symbols.hasNext()) {
                return symbols.next().getAddress();
            }
        }

        return null;
    }

    /**
     * Get symbol name at address.
     */
    private String getSymbolName(Address addr) {
        SymbolIterator symbols = program.getSymbolTable().getSymbolsAsIterator(addr);
        if (symbols != null && symbols.hasNext()) {
            return symbols.next().getName();
        }
        return null;
    }

    /**
     * Get data type at address.
     */
    private String getDataTypeName(Address addr) {
        Data data = program.getListing().getDataAt(addr);
        if (data != null) {
            DataType dt = data.getDataType();
            if (dt != null) {
                return dt.getDisplayName();
            }
        }
        return null;
    }

    /**
     * Check if an XRef matches the requested access type filter.
     */
    private boolean matchesAccessType(XRefThrough xref, String accessType) {
        if ("all".equalsIgnoreCase(accessType)) {
            return true;
        } else if ("read".equalsIgnoreCase(accessType)) {
            return xref.getAccessType() == XRefThrough.AccessType.READ;
        } else if ("write".equalsIgnoreCase(accessType)) {
            return xref.getAccessType() == XRefThrough.AccessType.WRITE;
        }
        return true;
    }
}
