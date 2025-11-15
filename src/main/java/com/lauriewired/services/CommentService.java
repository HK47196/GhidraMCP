package com.lauriewired.services;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service for managing comments and annotations in Ghidra programs
 */
public class CommentService {

    private final FunctionNavigator navigator;

    public CommentService(FunctionNavigator navigator) {
        this.navigator = navigator;
    }

    /**
     * Set a decompiler comment (PRE comment) at the specified address
     * @param addressStr Address as string
     * @param comment Comment text
     * @return true if successful
     */
    public boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CommentType.PRE, "Set decompiler comment");
    }

    /**
     * Set a disassembly comment (EOL comment) at the specified address
     * @param addressStr Address as string
     * @param comment Comment text
     * @return true if successful
     */
    public boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CommentType.EOL, "Set disassembly comment");
    }

    /**
     * Set a plate comment at the specified address
     * @param addressStr Address as string
     * @param comment Comment text
     * @return true if successful
     */
    public boolean setPlateComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CommentType.PLATE, "Set plate comment");
    }

    /**
     * Core method to set a comment at an address with specified comment type
     * @param addressStr Address as string
     * @param comment Comment text
     * @param commentType Type of comment (PRE, EOL, PLATE, etc.)
     * @param transactionName Name for the transaction
     * @return true if successful
     */
    private boolean setCommentAtAddress(String addressStr, String comment, CommentType commentType, String transactionName) {
        Program program = navigator.getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }
}
