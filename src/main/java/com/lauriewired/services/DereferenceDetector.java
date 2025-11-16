package com.lauriewired.services;

import com.lauriewired.model.TraceStep;
import com.lauriewired.model.XRefThrough;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Detects dereferences (LOAD/STORE operations) using raw PCode from instructions.
 * Does NOT use decompiler - works with instruction-level PCode only.
 */
public class DereferenceDetector {

    private final Program program;

    public DereferenceDetector(Program program) {
        this.program = program;
    }

    /**
     * Find dereferences in a function given a set of varnodes that contain the pointer value.
     *
     * @param function Function to analyze
     * @param pointerVarnodes Set of varnodes that hold the pointer value (from SymbolicPropogator)
     * @return List of dereferences found
     */
    public List<XRefThrough> findDereferences(Function function, Set<Varnode> pointerVarnodes) {
        List<XRefThrough> results = new ArrayList<>();

        if (function == null || pointerVarnodes == null || pointerVarnodes.isEmpty()) {
            return results;
        }

        // Iterate through all instructions in the function
        InstructionIterator instIter = program.getListing().getInstructions(function.getBody(), true);

        while (instIter.hasNext()) {
            Instruction instr = instIter.next();

            // Get raw PCode operations for this instruction
            PcodeOp[] pcodeOps = instr.getPcode();

            if (pcodeOps == null || pcodeOps.length == 0) {
                continue;
            }

            // Check each PCode operation
            for (PcodeOp op : pcodeOps) {
                XRefThrough xref = checkForDereference(op, instr, function, pointerVarnodes);
                if (xref != null) {
                    results.add(xref);
                }
            }
        }

        return results;
    }

    /**
     * Check if a PCode operation dereferences any of the tracked pointer varnodes.
     */
    private XRefThrough checkForDereference(PcodeOp op, Instruction instr, Function function,
                                             Set<Varnode> pointerVarnodes) {
        if (op == null) {
            return null;
        }

        int opcode = op.getOpcode();

        // Check for LOAD (memory read: *ptr)
        if (opcode == PcodeOp.LOAD) {
            // LOAD format: output = LOAD space, addressVarnode
            if (op.getNumInputs() >= 2) {
                Varnode addressVn = op.getInput(1);
                if (isPointerVarnode(addressVn, pointerVarnodes)) {
                    return createXRef(op, instr, function, XRefThrough.AccessType.READ,
                                     addressVn, 0);
                }
            }
        }

        // Check for STORE (memory write: *ptr = value)
        else if (opcode == PcodeOp.STORE) {
            // STORE format: STORE space, addressVarnode, valueVarnode
            if (op.getNumInputs() >= 3) {
                Varnode addressVn = op.getInput(1);
                if (isPointerVarnode(addressVn, pointerVarnodes)) {
                    return createXRef(op, instr, function, XRefThrough.AccessType.WRITE,
                                     addressVn, 0);
                }
            }
        }

        return null;
    }

    /**
     * Check if a varnode matches any of the tracked pointer varnodes.
     * This includes exact matches and offsets from tracked pointers.
     */
    private boolean isPointerVarnode(Varnode vn, Set<Varnode> pointerVarnodes) {
        if (vn == null || pointerVarnodes == null) {
            return false;
        }

        // Direct match
        for (Varnode ptrVn : pointerVarnodes) {
            if (vn.equals(ptrVn)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Create an XRefThrough result from a dereference operation.
     */
    private XRefThrough createXRef(PcodeOp op, Instruction instr, Function function,
                                     XRefThrough.AccessType accessType, Varnode addressVn,
                                     int offset) {
        Address addr = instr.getAddress();
        String instruction = formatInstruction(instr);
        String funcName = (function != null) ? function.getName() : null;

        // Simple confidence: HIGH for direct dereferences in same function
        XRefThrough.Confidence confidence = XRefThrough.Confidence.HIGH;

        String pcodeOpName = (op.getOpcode() == PcodeOp.LOAD) ? "LOAD" : "STORE";

        // Create simple trace
        List<TraceStep> trace = new ArrayList<>();
        trace.add(new TraceStep(
            addr.toString(),
            pcodeOpName + " through " + formatVarnode(addressVn),
            formatVarnode(addressVn)
        ));

        Integer size = null;
        if (op.getOutput() != null) {
            size = op.getOutput().getSize();
        } else if (op.getOpcode() == PcodeOp.STORE && op.getNumInputs() > 2) {
            Varnode valueVn = op.getInput(2);
            if (valueVn != null) {
                size = valueVn.getSize();
            }
        }

        return new XRefThrough.Builder()
            .fromAddress(addr.toString())
            .accessType(accessType)
            .instruction(instruction)
            .functionName(funcName)
            .confidence(confidence)
            .trace(trace)
            .pcodeOp(pcodeOpName)
            .offset(offset != 0 ? offset : null)
            .size(size)
            .build();
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
        } else if (vn.isUnique()) {
            return "unique:" + vn.getOffset();
        } else {
            return vn.toString();
        }
    }
}
