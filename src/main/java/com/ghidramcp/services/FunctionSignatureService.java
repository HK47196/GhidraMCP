package com.ghidramcp.services;

import com.ghidramcp.model.PrototypeResult;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service for managing function signatures and variable types
 */
public class FunctionSignatureService {

    // Pattern for pointer types: "BaseType*", "BaseType *", "BaseType *32", etc.
    // Group 1: base type name, Group 2: optional size in bits (for far pointers)
    private static final Pattern POINTER_PATTERN = Pattern.compile("^(.+?)\\s*\\*\\s*(\\d*)\\s*$");

    private final FunctionNavigator navigator;
    private final DecompilationService decompilationService;
    private final PluginTool tool;
    private final int decompileTimeout;

    public FunctionSignatureService(FunctionNavigator navigator, DecompilationService decompilationService, PluginTool tool, int decompileTimeout) {
        this.navigator = navigator;
        this.decompilationService = decompilationService;
        this.tool = tool;
        this.decompileTimeout = decompileTimeout;
    }

    /**
     * Set function prototype/signature
     * @param functionAddrStr Function address as string
     * @param prototype Function prototype string (e.g., "int foo(char* str, int len)")
     * @return PrototypeResult containing success status and error message if any
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = navigator.getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() ->
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Set local variable type
     * @param functionAddrStr Function address as string
     * @param variableName Variable name
     * @param newType New type name
     * @return true if successful
     */
    public boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = navigator.getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() ->
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set data type at a specific address
     * @param addressStr Address as string
     * @param typeName Type name (e.g., "int", "dword", "byte[20]")
     * @return true if successful
     */
    public boolean setDataType(String addressStr, String typeName) {
        // Input validation
        Program program = navigator.getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() ||
            typeName == null || typeName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() ->
                applyDataType(program, addressStr, typeName, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set data type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Apply function prototype in a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype,
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = navigator.getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Parse and apply function signature
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            DataTypeManagerService dtms = tool.getService(DataTypeManagerService.class);

            // Create function signature parser
            FunctionSignatureParser parser = new FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ApplyFunctionSignatureCmd cmd =
                new ApplyFunctionSignatureCmd(addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Apply variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr,
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = navigator.getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompilationService.decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName +
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Apply data type change at address
     */
    private void applyDataType(Program program, String addressStr, String typeName, AtomicBoolean success) {
        int tx = program.startTransaction("Set data type");
        try {
            // Parse the address
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                Msg.error(this, "Invalid address: " + addressStr);
                return;
            }

            // Resolve the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, typeName);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + typeName);
                return;
            }

            Msg.info(this, "Setting data type " + dataType.getName() + " at address " + addressStr);

            // Clear any existing code units at this address
            Listing listing = program.getListing();
            listing.clearCodeUnits(addr, addr.add(dataType.getLength() - 1), false);

            // Create the data with the specified type
            listing.createData(addr, dataType);

            success.set(true);
            Msg.info(this, "Successfully set data type at address " + addressStr);

        } catch (Exception e) {
            Msg.error(this, "Error setting data type: " + e.getMessage(), e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Resolve a data type name to a DataType object
     */
    public DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for array types (e.g., "int[10]", "char[256]", "int[10][20]")
        if (typeName.contains("[") && typeName.endsWith("]")) {
            int openBracket = typeName.indexOf('[');

            if (openBracket > 0) {
                String baseTypeName = typeName.substring(0, openBracket).trim();
                String dimensionsStr = typeName.substring(openBracket);

                // Parse all array dimensions from right to left for proper nesting
                // e.g., "int[10][20]" becomes ArrayDataType(ArrayDataType(int, 20), 10)
                List<Integer> dimensions = new ArrayList<>();
                int pos = 0;
                while (pos < dimensionsStr.length()) {
                    if (dimensionsStr.charAt(pos) == '[') {
                        int closeBracket = dimensionsStr.indexOf(']', pos);
                        if (closeBracket == -1) {
                            Msg.warn(this, "Malformed array type: " + typeName);
                            return null;
                        }
                        String sizeStr = dimensionsStr.substring(pos + 1, closeBracket).trim();
                        try {
                            int size = Integer.parseInt(sizeStr);
                            if (size <= 0) {
                                Msg.warn(this, "Invalid array size in type: " + typeName);
                                return null;
                            }
                            dimensions.add(size);
                        } catch (NumberFormatException e) {
                            Msg.warn(this, "Invalid array size in type: " + typeName);
                            return null;
                        }
                        pos = closeBracket + 1;
                    } else {
                        pos++;
                    }
                }

                if (!dimensions.isEmpty()) {
                    // Resolve base type
                    DataType baseType = resolveDataType(dtm, baseTypeName);
                    if (baseType == null) {
                        return null;
                    }

                    // Build array from innermost (rightmost) to outermost (leftmost)
                    DataType currentType = baseType;
                    for (int i = dimensions.size() - 1; i >= 0; i--) {
                        currentType = new ArrayDataType(currentType, dimensions.get(i), currentType.getLength());
                    }
                    return currentType;
                }
            }
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Check for pointer types: "BaseType*", "BaseType *", "BaseType *32" (far pointer)
        // Uses regex to handle all whitespace variations correctly
        Matcher pointerMatcher = POINTER_PATTERN.matcher(typeName);
        if (pointerMatcher.matches()) {
            String baseTypeName = pointerMatcher.group(1).trim();
            String sizeStr = pointerMatcher.group(2);  // Already just digits or empty

            // Check if we have a size specification (e.g., "32", "16") for far pointers
            if (!sizeStr.isEmpty()) {
                try {
                    int pointerSizeBits = Integer.parseInt(sizeStr);
                    int pointerSizeBytes = pointerSizeBits / 8;

                    if (pointerSizeBytes <= 0) {
                        Msg.warn(this, "Invalid pointer size in type: " + typeName);
                        return null;
                    }

                    // Resolve base type
                    DataType baseType = resolveDataType(dtm, baseTypeName);
                    if (baseType == null) {
                        // Default to void* with specified size
                        baseType = dtm.getDataType("/void");
                    }

                    // Create pointer with specified size
                    return new PointerDataType(baseType, pointerSizeBytes, dtm);
                } catch (NumberFormatException e) {
                    Msg.warn(this, "Invalid pointer size in type: " + typeName);
                    return null;
                }
            }
            // No size specified, treat as regular pointer
            else {
                DataType baseType = resolveDataType(dtm, baseTypeName);
                if (baseType != null) {
                    return new PointerDataType(baseType);
                }
                // Default to void*
                return new PointerDataType(dtm.getDataType("/void"));
            }
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        DataType fuzzyCandidate = null;
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive)
            if (dt.getName().equals(name)) {
                return dt;
            } else if (fuzzyCandidate == null && dt.getName().equalsIgnoreCase(name)) {
                // For case-insensitive, we want an exact match except for case
                // We want to check ALL types for exact matches, not just the first one
                // We want to stop on the very first match for fuzzy matching
                fuzzyCandidate = dt;
            }
        }

        return fuzzyCandidate;
    }
}
