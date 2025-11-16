package com.lauriewired.services;

import com.lauriewired.model.AnalysisStats;
import com.lauriewired.model.TraceStep;
import com.lauriewired.model.XRefThrough;
import com.lauriewired.model.XRefThroughResult;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Main analyzer for tracking pointer flow and finding dereferences.
 * Phase 1 (MVP): Intra-procedural analysis within functions that access the pointer.
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

            // Check if it's actually a pointer
            if (dataTypeName != null && !dataTypeName.contains("*") && !dataTypeName.equals("pointer")) {
                statsBuilder.addWarning("Address may not contain a pointer type: " + dataTypeName);
            }

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
     */
    private List<XRefThrough> analyzeFunctionForPointer(Function function, Address pointerAddr,
                                                          boolean followAliases) {
        List<XRefThrough> xrefs = new ArrayList<>();

        try {
            // Get high-level PCode from decompiler
            DecompInterface decompiler = new DecompInterface();
            DecompileOptions options = new DecompileOptions();
            decompiler.setOptions(options);
            decompiler.openProgram(program);

            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);

            if (results != null && results.decompileCompleted()) {
                HighFunction highFunc = results.getHighFunction();

                if (highFunc != null) {
                    xrefs.addAll(analyzeHighFunction(highFunc, pointerAddr, function, followAliases));
                }
            } else {
                // Decompiler failed, fall back to PCode from raw instructions
                xrefs.addAll(analyzeWithRawPCode(function, pointerAddr));
            }

            decompiler.dispose();

        } catch (Exception e) {
            // If analysis fails for this function, continue with others
        }

        return xrefs;
    }

    /**
     * Analyze using high-level PCode from decompiler.
     */
    private List<XRefThrough> analyzeHighFunction(HighFunction highFunc, Address pointerAddr,
                                                    Function function, boolean followAliases) {
        List<XRefThrough> xrefs = new ArrayList<>();

        // Find varnodes that represent loads from the pointer address
        Iterator<PcodeOpAST> opcodeIter = highFunc.getPcodeOps();

        Set<Varnode> pointerVarnodes = new HashSet<>();

        while (opcodeIter.hasNext()) {
            PcodeOpAST op = opcodeIter.next();

            // Find LOAD operations from the pointer address
            if (op.getOpcode() == PcodeOp.LOAD) {
                Varnode addressVn = op.getInput(1);
                if (addressVn != null && addressVn.isAddress() &&
                    addressVn.getAddress().equals(pointerAddr)) {

                    // This loads the pointer value
                    Varnode pointerValue = op.getOutput();
                    if (pointerValue != null) {
                        pointerVarnodes.add(pointerValue);

                        // Create initial trace
                        List<TraceStep> trace = new ArrayList<>();
                        trace.add(new TraceStep(
                            op.getSeqnum().getTarget().toString(),
                            "loaded from " + pointerAddr,
                            formatVarnode(pointerValue)
                        ));

                        // Find dereferences of this varnode
                        List<XRefThrough> dereferences = dereferenceDetector.findDereferencesOf(
                            pointerValue, function, trace);
                        xrefs.addAll(dereferences);
                    }
                }
            }

            // Also check for direct addressing (constant address equals pointerAddr)
            if (op.getOpcode() == PcodeOp.COPY) {
                Varnode input = op.getInput(0);
                if (input != null && input.isAddress() && input.getAddress().equals(pointerAddr)) {
                    Varnode pointerValue = op.getOutput();
                    if (pointerValue != null) {
                        pointerVarnodes.add(pointerValue);

                        List<TraceStep> trace = new ArrayList<>();
                        trace.add(new TraceStep(
                            op.getSeqnum().getTarget().toString(),
                            "loaded constant pointer " + pointerAddr,
                            formatVarnode(pointerValue)
                        ));

                        List<XRefThrough> dereferences = dereferenceDetector.findDereferencesOf(
                            pointerValue, function, trace);
                        xrefs.addAll(dereferences);
                    }
                }
            }
        }

        return xrefs;
    }

    /**
     * Analyze using raw PCode from instructions (fallback when decompiler fails).
     */
    private List<XRefThrough> analyzeWithRawPCode(Function function, Address pointerAddr) {
        List<XRefThrough> xrefs = new ArrayList<>();

        // For MVP, we'll skip raw PCode analysis as it's more complex
        // This would be implemented in Phase 4

        return xrefs;
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

    /**
     * Format a varnode for display.
     */
    private String formatVarnode(Varnode vn) {
        if (vn == null) {
            return "null";
        }

        if (vn.isRegister()) {
            return vn.getAddress().toString() + ":" + vn.getSize();
        } else if (vn.isConstant()) {
            return "const:0x" + Long.toHexString(vn.getOffset());
        } else if (vn.isAddress()) {
            return vn.getAddress().toString();
        } else {
            return vn.toString();
        }
    }
}
