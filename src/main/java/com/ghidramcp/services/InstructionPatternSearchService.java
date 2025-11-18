package com.ghidramcp.services;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Service for searching instruction patterns using regex over disassembly text
 */
public class InstructionPatternSearchService {

    private final FunctionNavigator navigator;

    public InstructionPatternSearchService(FunctionNavigator navigator) {
        this.navigator = navigator;
    }

    /**
     * Search for instructions matching a regex pattern
     *
     * @param searchPattern Regex pattern to match against disassembly text
     * @param segmentName Optional segment name to restrict search
     * @param startAddress Optional start address of range to search
     * @param endAddress Optional end address of range to search
     * @param offset Pagination offset
     * @param limit Maximum number of results
     * @return Formatted list of matching addresses
     */
    public String searchInstructionPattern(
            String searchPattern,
            String segmentName,
            String startAddress,
            String endAddress,
            int offset,
            int limit) {

        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        if (searchPattern == null || searchPattern.trim().isEmpty()) {
            return "Error: Search pattern is required";
        }

        // Compile regex pattern (case insensitive)
        Pattern pattern;
        try {
            pattern = Pattern.compile(searchPattern, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            return "Error: Invalid regex pattern - " + e.getMessage();
        }

        // Determine search range
        Address rangeStart;
        Address rangeEnd;

        try {
            if (segmentName != null && !segmentName.isEmpty()) {
                // Search within specific segment
                MemoryBlock segment = null;
                for (MemoryBlock block : program.getMemory().getBlocks()) {
                    if (block.getName().equals(segmentName)) {
                        segment = block;
                        break;
                    }
                }

                if (segment == null) {
                    return "Error: Segment not found: " + segmentName;
                }

                rangeStart = segment.getStart();
                rangeEnd = segment.getEnd();
            } else if (startAddress != null && endAddress != null) {
                // Search within specified address range
                rangeStart = program.getAddressFactory().getAddress(startAddress);
                rangeEnd = program.getAddressFactory().getAddress(endAddress);

                if (rangeStart == null) {
                    return "Error: Invalid start address: " + startAddress;
                }
                if (rangeEnd == null) {
                    return "Error: Invalid end address: " + endAddress;
                }

                if (rangeStart.compareTo(rangeEnd) > 0) {
                    return "Error: Start address must be less than or equal to end address";
                }
            } else {
                // Search entire program
                rangeStart = program.getMinAddress();
                rangeEnd = program.getMaxAddress();
            }
        } catch (Exception e) {
            return "Error parsing addresses: " + e.getMessage();
        }

        // Search for matching instructions
        List<MatchResult> results = new ArrayList<>();
        InstructionIterator instructions = program.getListing().getInstructions(rangeStart, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            Address addr = instr.getAddress();

            // Check if we've gone past the end address
            if (addr.compareTo(rangeEnd) > 0) {
                break;
            }

            // Build disassembly string for this instruction
            String disassembly = formatInstruction(instr);

            // Check if pattern matches
            if (pattern.matcher(disassembly).find()) {
                MemoryBlock block = program.getMemory().getBlock(addr);
                String blockName = block != null ? block.getName() : "unknown";
                results.add(new MatchResult(addr, disassembly, blockName));
            }
        }

        if (results.isEmpty()) {
            return "Pattern compiled successfully. No matches found for: " + searchPattern;
        }

        // Format and paginate results
        return formatResults(results, searchPattern, offset, limit);
    }

    /**
     * Format an instruction as disassembly text
     */
    private String formatInstruction(Instruction instr) {
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
     * Format search results with pagination
     */
    private String formatResults(List<MatchResult> results, String pattern, int offset, int limit) {
        StringBuilder sb = new StringBuilder();

        sb.append(String.format("Found %d matches for pattern: %s\n", results.size(), pattern));
        sb.append(String.format("Showing results %d to %d\n\n",
                                offset + 1,
                                Math.min(offset + limit, results.size())));

        // Apply pagination
        int endIndex = Math.min(offset + limit, results.size());
        for (int i = offset; i < endIndex; i++) {
            MatchResult match = results.get(i);
            sb.append(String.format("%s: %s (segment: %s)\n",
                                   match.address.toString(),
                                   match.disassembly,
                                   match.segmentName));
        }

        if (endIndex < results.size()) {
            sb.append(String.format("\n... %d more match(es). Use offset parameter to see more.\n",
                                   results.size() - endIndex));
        }

        return sb.toString();
    }

    /**
     * Simple class to hold match results
     */
    private static class MatchResult {
        final Address address;
        final String disassembly;
        final String segmentName;

        MatchResult(Address address, String disassembly, String segmentName) {
            this.address = address;
            this.disassembly = disassembly;
            this.segmentName = segmentName;
        }
    }
}
