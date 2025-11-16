package com.lauriewired.services;

import com.lauriewired.model.TraceStep;
import com.lauriewired.model.XRefThrough;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Detects dereferences (LOAD/STORE operations) of tracked pointer values.
 * This is the core component that finds where pointers are actually accessed.
 */
public class DereferenceDetector {

    private final Program program;
    private final Listing listing;

    public DereferenceDetector(Program program) {
        this.program = program;
        this.listing = program.getListing();
    }

    /**
     * Find all dereferences of a specific varnode (representing a pointer value).
     *
     * @param pointerVarnode The varnode containing the pointer value
     * @param function The function being analyzed
     * @param trace The trace showing how we got to this varnode
     * @return List of dereference XRefs
     */
    public List<XRefThrough> findDereferencesOf(Varnode pointerVarnode, Function function,
                                                  List<TraceStep> trace) {
        List<XRefThrough> results = new ArrayList<>();
        Set<Varnode> visited = new HashSet<>();

        findDereferencesRecursive(pointerVarnode, function, trace, results, visited);

        return results;
    }

    /**
     * Recursively find dereferences, tracking through pointer arithmetic.
     */
    private void findDereferencesRecursive(Varnode pointerVarnode, Function function,
                                           List<TraceStep> trace, List<XRefThrough> results,
                                           Set<Varnode> visited) {
        if (pointerVarnode == null || visited.contains(pointerVarnode)) {
            return;
        }
        visited.add(pointerVarnode);

        Iterator<PcodeOp> descendants = pointerVarnode.getDescendants();
        if (descendants == null) {
            return;
        }

        while (descendants.hasNext()) {
            PcodeOp op = descendants.next();
            if (op == null || op.getSeqnum() == null) {
                continue;
            }

            int opcode = op.getOpcode();

            // Direct LOAD operation (memory read)
            if (opcode == PcodeOp.LOAD) {
                if (isPointerUsedAsAddress(op, pointerVarnode, 1)) {
                    XRefThrough xref = createXRefFromOp(op, XRefThrough.AccessType.READ,
                        function, trace, null);
                    if (xref != null) {
                        results.add(xref);
                    }
                }
            }

            // Direct STORE operation (memory write)
            else if (opcode == PcodeOp.STORE) {
                if (isPointerUsedAsAddress(op, pointerVarnode, 1)) {
                    XRefThrough xref = createXRefFromOp(op, XRefThrough.AccessType.WRITE,
                        function, trace, null);
                    if (xref != null) {
                        results.add(xref);
                    }
                }
            }

            // Pointer arithmetic - track through offsets
            else if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.PTRADD ||
                     opcode == PcodeOp.INT_SUB || opcode == PcodeOp.PTRSUB) {
                Varnode output = op.getOutput();
                if (output != null) {
                    // Calculate offset if possible
                    Integer offset = calculateOffset(op, pointerVarnode);

                    // Create new trace with offset operation
                    List<TraceStep> newTrace = new ArrayList<>(trace);
                    String offsetStr = (offset != null) ? "+" + offset : "+?";
                    newTrace.add(new TraceStep(
                        formatAddress(op.getSeqnum().getTarget()),
                        "offset calculation " + offsetStr,
                        formatVarnode(output)
                    ));

                    // Recursively check dereferences of the offset pointer
                    findDereferencesRecursive(output, function, newTrace, results, visited);
                }
            }

            // COPY operation - pointer alias
            else if (opcode == PcodeOp.COPY) {
                Varnode output = op.getOutput();
                if (output != null) {
                    // Create new trace showing the copy
                    List<TraceStep> newTrace = new ArrayList<>(trace);
                    newTrace.add(new TraceStep(
                        formatAddress(op.getSeqnum().getTarget()),
                        "copied to",
                        formatVarnode(output)
                    ));

                    // Follow the copy
                    findDereferencesRecursive(output, function, newTrace, results, visited);
                }
            }

            // CALL/CALLIND - pointer passed to function
            // For MVP, we'll mark these but not follow into the called function
            else if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
                // Check if pointer is used as a parameter
                int paramIndex = findPointerAsParameter(op, pointerVarnode);
                if (paramIndex >= 0) {
                    XRefThrough xref = createCallXRef(op, function, trace, paramIndex);
                    if (xref != null) {
                        results.add(xref);
                    }
                }
            }
        }
    }

    /**
     * Check if a pointer varnode is used as the address in a LOAD/STORE operation.
     *
     * @param op The LOAD or STORE operation
     * @param pointer The pointer varnode to check
     * @param addrInputIndex Index of the address input (1 for both LOAD and STORE)
     * @return true if the pointer is used as the address
     */
    private boolean isPointerUsedAsAddress(PcodeOp op, Varnode pointer, int addrInputIndex) {
        if (op.getNumInputs() <= addrInputIndex) {
            return false;
        }

        Varnode addrVarnode = op.getInput(addrInputIndex);
        if (addrVarnode == null) {
            return false;
        }

        // Direct match
        if (addrVarnode.equals(pointer)) {
            return true;
        }

        // Check if address is derived from pointer (simple offset)
        PcodeOp addrDef = addrVarnode.getDef();
        if (addrDef != null && isOffsetOf(addrDef, pointer)) {
            return true;
        }

        return false;
    }

    /**
     * Check if a PcodeOp computes an offset from a pointer.
     */
    private boolean isOffsetOf(PcodeOp op, Varnode pointer) {
        if (op == null) {
            return false;
        }

        int opcode = op.getOpcode();
        if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.PTRADD ||
            opcode == PcodeOp.INT_SUB || opcode == PcodeOp.PTRSUB) {
            // Check if any input is our pointer
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode input = op.getInput(i);
                if (input != null && input.equals(pointer)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Calculate the offset being added/subtracted in pointer arithmetic.
     */
    private Integer calculateOffset(PcodeOp op, Varnode pointer) {
        if (op.getNumInputs() < 2) {
            return null;
        }

        // Find which input is the pointer and which is the offset
        Varnode offsetVn = null;
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode input = op.getInput(i);
            if (input != null && !input.equals(pointer) && input.isConstant()) {
                offsetVn = input;
                break;
            }
        }

        if (offsetVn != null && offsetVn.isConstant()) {
            long offset = offsetVn.getOffset();
            // Handle subtraction
            if (op.getOpcode() == PcodeOp.INT_SUB || op.getOpcode() == PcodeOp.PTRSUB) {
                offset = -offset;
            }
            return (int) offset;
        }

        return null;
    }

    /**
     * Find if a pointer is used as a parameter to a call.
     */
    private int findPointerAsParameter(PcodeOp callOp, Varnode pointer) {
        // Input 0 is the call destination, parameters start at index 1
        for (int i = 1; i < callOp.getNumInputs(); i++) {
            Varnode input = callOp.getInput(i);
            if (input != null && input.equals(pointer)) {
                return i - 1; // Parameter index (0-based)
            }
        }
        return -1;
    }

    /**
     * Create an XRefThrough from a LOAD/STORE PcodeOp.
     */
    private XRefThrough createXRefFromOp(PcodeOp op, XRefThrough.AccessType accessType,
                                          Function function, List<TraceStep> trace,
                                          Integer offset) {
        Address addr = op.getSeqnum().getTarget();
        Instruction instr = listing.getInstructionAt(addr);

        if (instr == null) {
            return null;
        }

        String instruction = formatInstruction(instr);
        String funcName = (function != null) ? function.getName() : null;

        // Confidence: HIGH for direct dereferences in same basic block
        XRefThrough.Confidence confidence = determineConfidence(trace);

        String pcodeOpName = (op.getOpcode() == PcodeOp.LOAD) ? "LOAD" : "STORE";

        return new XRefThrough.Builder()
            .fromAddress(formatAddress(addr))
            .accessType(accessType)
            .instruction(instruction)
            .functionName(funcName)
            .confidence(confidence)
            .trace(trace)
            .pcodeOp(pcodeOpName)
            .offset(offset)
            .size(getSizeFromOp(op))
            .build();
    }

    /**
     * Create an XRefThrough for a call passing the pointer as parameter.
     */
    private XRefThrough createCallXRef(PcodeOp callOp, Function function,
                                        List<TraceStep> trace, int paramIndex) {
        Address addr = callOp.getSeqnum().getTarget();
        Instruction instr = listing.getInstructionAt(addr);

        if (instr == null) {
            return null;
        }

        String instruction = formatInstruction(instr);
        String funcName = (function != null) ? function.getName() : null;

        // Lower confidence for calls since we don't know what happens inside
        XRefThrough.Confidence confidence = XRefThrough.Confidence.MEDIUM;

        return new XRefThrough.Builder()
            .fromAddress(formatAddress(addr))
            .accessType(XRefThrough.AccessType.WRITE) // Assume write for now
            .instruction(instruction + " [passed as param " + paramIndex + "]")
            .functionName(funcName)
            .confidence(confidence)
            .trace(trace)
            .build();
    }

    /**
     * Determine confidence level based on trace complexity.
     */
    private XRefThrough.Confidence determineConfidence(List<TraceStep> trace) {
        if (trace.size() <= 1) {
            return XRefThrough.Confidence.HIGH;
        } else if (trace.size() <= 3) {
            return XRefThrough.Confidence.MEDIUM;
        } else {
            return XRefThrough.Confidence.LOW;
        }
    }

    /**
     * Get the size of data being accessed from a LOAD/STORE operation.
     */
    private Integer getSizeFromOp(PcodeOp op) {
        Varnode output = op.getOutput();
        if (output != null) {
            return output.getSize();
        }

        // For STORE, check the value being stored
        if (op.getOpcode() == PcodeOp.STORE && op.getNumInputs() > 2) {
            Varnode value = op.getInput(2);
            if (value != null) {
                return value.getSize();
            }
        }

        return null;
    }

    /**
     * Format an instruction for display.
     */
    private String formatInstruction(Instruction instr) {
        if (instr == null) {
            return "[UNKNOWN]";
        }

        StringBuilder sb = new StringBuilder();
        sb.append(instr.getMnemonicString());

        int numOperands = instr.getNumOperands();
        if (numOperands > 0) {
            sb.append(" ");
            for (int i = 0; i < numOperands; i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append(instr.getDefaultOperandRepresentation(i));
            }
        }

        return sb.toString();
    }

    /**
     * Format an address as a string.
     */
    private String formatAddress(Address addr) {
        if (addr == null) {
            return "null";
        }
        return addr.toString();
    }

    /**
     * Format a varnode for display in trace.
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
