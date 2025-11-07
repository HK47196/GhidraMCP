package com.lauriewired.services;

import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for managing structure data types in Ghidra
 */
public class StructService {

    private final FunctionNavigator navigator;

    public StructService(FunctionNavigator navigator) {
        this.navigator = navigator;
    }

    // ==================== PHASE 1: BASIC STRUCT CREATION ====================

    /**
     * Create a new empty struct with a given name and optional size
     * @param name Struct name
     * @param size Initial size in bytes (0 for empty/auto-sized)
     * @param categoryPath Category path like "/MyStructs" (default: "/")
     * @return JSON string with struct details
     */
    public String createStruct(String name, int size, String categoryPath) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }
        if (name == null || name.isEmpty()) {
            return createErrorJson("Struct name is required");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int txId = dtm.startTransaction("Create struct");
                try {
                    // Parse category path
                    CategoryPath path = categoryPath != null && !categoryPath.isEmpty()
                        ? new CategoryPath(categoryPath)
                        : new CategoryPath("/");

                    // Create struct
                    StructureDataType struct = new StructureDataType(path, name, size, dtm);

                    // Add to manager
                    Structure addedStruct = (Structure) dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);

                    dtm.endTransaction(txId, true);

                    // Build response JSON
                    result.set(String.format(
                        "{\"success\": true, \"name\": \"%s\", \"size\": %d, \"category\": \"%s\", \"path\": \"%s\"}",
                        addedStruct.getName(),
                        addedStruct.getLength(),
                        addedStruct.getCategoryPath().getPath(),
                        addedStruct.getPathName()
                    ));

                    Msg.info(this, "Created struct: " + addedStruct.getPathName());

                } catch (Exception e) {
                    dtm.endTransaction(txId, false);
                    result.set(createErrorJson("Failed to create struct: " + e.getMessage()));
                    Msg.error(this, "Error creating struct", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    /**
     * Parse C struct definition from text and add to program
     * @param cCode C struct definition
     * @param categoryPath Where to place the struct
     * @return JSON string with parsed struct names and details
     */
    public String parseCStruct(String cCode, String categoryPath) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }
        if (cCode == null || cCode.isEmpty()) {
            return createErrorJson("C code is required");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int txId = dtm.startTransaction("Parse C struct");
                try {
                    // Create parser
                    CParser parser = new CParser(dtm);

                    // Parse the code
                    parser.parse(cCode);

                    // Retrieve parsed composites
                    Map<String, DataType> composites = parser.getComposites();

                    if (composites.isEmpty()) {
                        dtm.endTransaction(txId, false);
                        result.set(createErrorJson("No struct definitions found in C code"));
                        return;
                    }

                    // Add each composite to the data type manager
                    List<String> structInfo = new ArrayList<>();
                    for (Map.Entry<String, DataType> entry : composites.entrySet()) {
                        DataType dt = entry.getValue();

                        // Add to manager
                        DataType addedType = dtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);

                        if (addedType instanceof Structure) {
                            Structure struct = (Structure) addedType;
                            structInfo.add(String.format(
                                "{\"name\": \"%s\", \"size\": %d, \"path\": \"%s\", \"numFields\": %d}",
                                struct.getName(),
                                struct.getLength(),
                                struct.getPathName(),
                                struct.getNumComponents()
                            ));
                        }
                    }

                    dtm.endTransaction(txId, true);

                    result.set(String.format(
                        "{\"success\": true, \"structs\": [%s]}",
                        String.join(", ", structInfo)
                    ));

                    Msg.info(this, "Parsed " + composites.size() + " struct(s) from C code");

                } catch (Exception e) {
                    dtm.endTransaction(txId, false);
                    result.set(createErrorJson("Failed to parse C struct: " + e.getMessage()));
                    Msg.error(this, "Error parsing C code", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    // ==================== PHASE 2: STRUCT MODIFICATION ====================

    /**
     * Add a field to an existing struct
     * @param structName Name of struct to modify
     * @param fieldType Data type name (e.g., "int", "char", "void*")
     * @param fieldName Name of new field
     * @param length Size in bytes (-1 for default)
     * @param comment Field comment
     * @return JSON string with field details
     */
    public String addStructField(String structName, String fieldType, String fieldName, int length, String comment) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }
        if (structName == null || structName.isEmpty()) {
            return createErrorJson("Struct name is required");
        }
        if (fieldType == null || fieldType.isEmpty()) {
            return createErrorJson("Field type is required");
        }
        if (fieldName == null || fieldName.isEmpty()) {
            return createErrorJson("Field name is required");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int txId = dtm.startTransaction("Add struct field");
                try {
                    // Get the struct
                    DataType dt = findDataType(dtm, structName);
                    if (dt == null) {
                        result.set(createErrorJson("Struct not found: " + structName));
                        dtm.endTransaction(txId, false);
                        return;
                    }
                    if (!(dt instanceof Structure)) {
                        result.set(createErrorJson("Data type is not a structure: " + structName));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    Structure struct = (Structure) dt;

                    // Get the field data type
                    DataType fieldDataType = resolveDataType(dtm, fieldType);
                    if (fieldDataType == null) {
                        result.set(createErrorJson("Could not resolve field type: " + fieldType));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    // Add field
                    int fieldLength = length > 0 ? length : -1;
                    DataTypeComponent component = struct.add(
                        fieldDataType,
                        fieldLength,
                        fieldName,
                        comment
                    );

                    dtm.endTransaction(txId, true);

                    result.set(String.format(
                        "{\"success\": true, \"offset\": %d, \"size\": %d, \"type\": \"%s\", \"name\": \"%s\"}",
                        component.getOffset(),
                        component.getLength(),
                        component.getDataType().getName(),
                        component.getFieldName()
                    ));

                    Msg.info(this, "Added field '" + fieldName + "' to struct " + structName);

                } catch (Exception e) {
                    dtm.endTransaction(txId, false);
                    result.set(createErrorJson("Failed to add field: " + e.getMessage()));
                    Msg.error(this, "Error adding field", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    /**
     * Insert a field at a specific offset in the struct
     * @param structName Name of struct
     * @param offset Byte offset for insertion
     * @param fieldType Data type name
     * @param fieldName Name of field
     * @param length Size in bytes (-1 for default)
     * @param comment Field comment
     * @return JSON string with field details
     */
    public String insertStructFieldAtOffset(String structName, int offset, String fieldType, String fieldName, int length, String comment) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }
        if (structName == null || structName.isEmpty()) {
            return createErrorJson("Struct name is required");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int txId = dtm.startTransaction("Insert struct field");
                try {
                    Structure struct = (Structure) findDataType(dtm, structName);
                    if (struct == null) {
                        result.set(createErrorJson("Struct not found: " + structName));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    DataType fieldDataType = resolveDataType(dtm, fieldType);
                    if (fieldDataType == null) {
                        result.set(createErrorJson("Could not resolve field type: " + fieldType));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    // Insert at specific offset
                    int fieldLength = length > 0 ? length : -1;
                    DataTypeComponent component = struct.insertAtOffset(
                        offset,
                        fieldDataType,
                        fieldLength,
                        fieldName,
                        comment
                    );

                    dtm.endTransaction(txId, true);

                    result.set(String.format(
                        "{\"success\": true, \"offset\": %d, \"size\": %d, \"type\": \"%s\", \"name\": \"%s\"}",
                        component.getOffset(),
                        component.getLength(),
                        component.getDataType().getName(),
                        component.getFieldName()
                    ));

                    Msg.info(this, "Inserted field '" + fieldName + "' at offset " + offset + " in struct " + structName);

                } catch (Exception e) {
                    dtm.endTransaction(txId, false);
                    result.set(createErrorJson("Failed to insert field: " + e.getMessage()));
                    Msg.error(this, "Error inserting field", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    /**
     * Replace an existing field at a given ordinal position
     * @param structName Name of struct
     * @param ordinal Component index (0-based)
     * @param fieldType Data type name
     * @param fieldName Field name (null to keep existing)
     * @param length Size in bytes (-1 for default)
     * @param comment Field comment (null to keep existing)
     * @return JSON string with field details
     */
    public String replaceStructField(String structName, int ordinal, String fieldType, String fieldName, int length, String comment) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int txId = dtm.startTransaction("Replace struct field");
                try {
                    Structure struct = (Structure) findDataType(dtm, structName);
                    if (struct == null) {
                        result.set(createErrorJson("Struct not found: " + structName));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    if (ordinal < 0 || ordinal >= struct.getNumComponents()) {
                        result.set(createErrorJson("Invalid ordinal: " + ordinal));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    DataType fieldDataType = resolveDataType(dtm, fieldType);
                    if (fieldDataType == null) {
                        result.set(createErrorJson("Could not resolve field type: " + fieldType));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    // Get existing component for name/comment if not provided
                    DataTypeComponent existing = struct.getComponent(ordinal);
                    String finalFieldName = fieldName != null && !fieldName.isEmpty() ? fieldName : existing.getFieldName();
                    String finalComment = comment != null ? comment : existing.getComment();
                    int fieldLength = length > 0 ? length : -1;

                    DataTypeComponent component = struct.replace(
                        ordinal,
                        fieldDataType,
                        fieldLength,
                        finalFieldName,
                        finalComment
                    );

                    dtm.endTransaction(txId, true);

                    result.set(String.format(
                        "{\"success\": true, \"ordinal\": %d, \"offset\": %d, \"size\": %d, \"type\": \"%s\", \"name\": \"%s\"}",
                        ordinal,
                        component.getOffset(),
                        component.getLength(),
                        component.getDataType().getName(),
                        component.getFieldName()
                    ));

                    Msg.info(this, "Replaced field at ordinal " + ordinal + " in struct " + structName);

                } catch (Exception e) {
                    dtm.endTransaction(txId, false);
                    result.set(createErrorJson("Failed to replace field: " + e.getMessage()));
                    Msg.error(this, "Error replacing field", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    /**
     * Delete a field from a struct
     * @param structName Name of struct
     * @param ordinal Component index (0-based, -1 if using offset)
     * @param offset Byte offset (-1 if using ordinal)
     * @return JSON string with result
     */
    public String deleteStructField(String structName, int ordinal, int offset) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }
        if (ordinal == -1 && offset == -1) {
            return createErrorJson("Must specify either ordinal or offset");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int txId = dtm.startTransaction("Delete struct field");
                try {
                    Structure struct = (Structure) findDataType(dtm, structName);
                    if (struct == null) {
                        result.set(createErrorJson("Struct not found: " + structName));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    if (ordinal >= 0) {
                        // Delete by ordinal
                        if (ordinal >= struct.getNumComponents()) {
                            result.set(createErrorJson("Invalid ordinal: " + ordinal));
                            dtm.endTransaction(txId, false);
                            return;
                        }
                        struct.delete(ordinal);
                        result.set(String.format(
                            "{\"success\": true, \"message\": \"Deleted field at ordinal %d\"}",
                            ordinal
                        ));
                    } else {
                        // Delete at offset
                        struct.deleteAtOffset(offset);
                        result.set(String.format(
                            "{\"success\": true, \"message\": \"Deleted field(s) at offset %d\"}",
                            offset
                        ));
                    }

                    dtm.endTransaction(txId, true);
                    Msg.info(this, "Deleted field from struct " + structName);

                } catch (Exception e) {
                    dtm.endTransaction(txId, false);
                    result.set(createErrorJson("Failed to delete field: " + e.getMessage()));
                    Msg.error(this, "Error deleting field", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    /**
     * Clear a field (keeps struct size, fills with undefined)
     * @param structName Name of struct
     * @param ordinal Component index (0-based, -1 if using offset)
     * @param offset Byte offset (-1 if using ordinal)
     * @return JSON string with result
     */
    public String clearStructField(String structName, int ordinal, int offset) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }
        if (ordinal == -1 && offset == -1) {
            return createErrorJson("Must specify either ordinal or offset");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int txId = dtm.startTransaction("Clear struct field");
                try {
                    Structure struct = (Structure) findDataType(dtm, structName);
                    if (struct == null) {
                        result.set(createErrorJson("Struct not found: " + structName));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    if (ordinal >= 0) {
                        // Clear by ordinal
                        if (ordinal >= struct.getNumComponents()) {
                            result.set(createErrorJson("Invalid ordinal: " + ordinal));
                            dtm.endTransaction(txId, false);
                            return;
                        }
                        struct.clearComponent(ordinal);
                        result.set(String.format(
                            "{\"success\": true, \"message\": \"Cleared field at ordinal %d\"}",
                            ordinal
                        ));
                    } else {
                        // Clear at offset
                        struct.clearAtOffset(offset);
                        result.set(String.format(
                            "{\"success\": true, \"message\": \"Cleared field(s) at offset %d\"}",
                            offset
                        ));
                    }

                    dtm.endTransaction(txId, true);
                    Msg.info(this, "Cleared field from struct " + structName);

                } catch (Exception e) {
                    dtm.endTransaction(txId, false);
                    result.set(createErrorJson("Failed to clear field: " + e.getMessage()));
                    Msg.error(this, "Error clearing field", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    // ==================== PHASE 3: STRUCT INFORMATION & MANAGEMENT ====================

    /**
     * Get detailed information about a struct
     * @param structName Name of struct
     * @return JSON string with complete struct details including all fields
     */
    public String getStructInfo(String structName) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataType(dtm, structName);

                    if (dt == null) {
                        result.set(createErrorJson("Struct not found: " + structName));
                        return;
                    }
                    if (!(dt instanceof Structure)) {
                        result.set(createErrorJson("Data type is not a structure: " + structName));
                        return;
                    }

                    Structure struct = (Structure) dt;

                    // Gather info
                    int length = struct.getLength();
                    int numComponents = struct.getNumComponents();
                    int numDefined = struct.getNumDefinedComponents();
                    boolean isPacked = struct.isPackingEnabled();
                    int alignment = struct.getAlignment();

                    // Get components
                    List<String> componentsList = new ArrayList<>();
                    DataTypeComponent[] components = struct.getComponents();
                    for (DataTypeComponent comp : components) {
                        String name = comp.getFieldName() != null ? comp.getFieldName() : "";
                        DataType type = comp.getDataType();
                        int compOffset = comp.getOffset();
                        int size = comp.getLength();
                        String commentStr = comp.getComment() != null ? comp.getComment() : "";

                        componentsList.add(String.format(
                            "{\"name\": \"%s\", \"type\": \"%s\", \"offset\": %d, \"size\": %d, \"comment\": \"%s\"}",
                            escapeJson(name),
                            escapeJson(type.getName()),
                            compOffset,
                            size,
                            escapeJson(commentStr)
                        ));
                    }

                    result.set(String.format(
                        "{\"success\": true, \"name\": \"%s\", \"path\": \"%s\", \"size\": %d, " +
                        "\"numComponents\": %d, \"numDefined\": %d, \"isPacked\": %b, \"alignment\": %d, " +
                        "\"components\": [%s]}",
                        struct.getName(),
                        struct.getPathName(),
                        length,
                        numComponents,
                        numDefined,
                        isPacked,
                        alignment,
                        String.join(", ", componentsList)
                    ));

                } catch (Exception e) {
                    result.set(createErrorJson("Failed to get struct info: " + e.getMessage()));
                    Msg.error(this, "Error getting struct info", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    /**
     * List all struct types in the program
     * @param categoryPath Filter by category (null for all)
     * @param offset Pagination offset
     * @param limit Max results
     * @return JSON string with array of struct summaries
     */
    public String listStructs(String categoryPath, int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Iterator<DataType> allTypes = dtm.getAllDataTypes();

                    List<String> structs = new ArrayList<>();
                    int count = 0;
                    int index = 0;

                    while (allTypes.hasNext() && count < limit) {
                        DataType dt = allTypes.next();
                        if (dt instanceof Structure) {
                            // Filter by category if specified
                            if (categoryPath != null && !categoryPath.isEmpty() &&
                                !dt.getCategoryPath().getPath().startsWith(categoryPath)) {
                                continue;
                            }

                            // Apply offset
                            if (index < offset) {
                                index++;
                                continue;
                            }

                            Structure struct = (Structure) dt;
                            structs.add(String.format(
                                "{\"name\": \"%s\", \"path\": \"%s\", \"size\": %d, \"numFields\": %d}",
                                struct.getName(),
                                struct.getPathName(),
                                struct.getLength(),
                                struct.getNumComponents()
                            ));

                            count++;
                            index++;
                        }
                    }

                    result.set(String.format(
                        "{\"success\": true, \"offset\": %d, \"limit\": %d, \"count\": %d, \"structs\": [%s]}",
                        offset,
                        limit,
                        count,
                        String.join(", ", structs)
                    ));

                } catch (Exception e) {
                    result.set(createErrorJson("Failed to list structs: " + e.getMessage()));
                    Msg.error(this, "Error listing structs", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    /**
     * Rename a struct
     * @param oldName Current struct name
     * @param newName New struct name
     * @return JSON string with result
     */
    public String renameStruct(String oldName, String newName) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }
        if (oldName == null || oldName.isEmpty() || newName == null || newName.isEmpty()) {
            return createErrorJson("Both old and new names are required");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int txId = dtm.startTransaction("Rename struct");
                try {
                    Structure struct = (Structure) findDataType(dtm, oldName);
                    if (struct == null) {
                        result.set(createErrorJson("Struct not found: " + oldName));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    struct.setName(newName);
                    dtm.endTransaction(txId, true);

                    result.set(String.format(
                        "{\"success\": true, \"message\": \"Renamed struct from '%s' to '%s'\"}",
                        oldName,
                        newName
                    ));

                    Msg.info(this, "Renamed struct: " + oldName + " -> " + newName);

                } catch (Exception e) {
                    dtm.endTransaction(txId, false);
                    result.set(createErrorJson("Failed to rename struct: " + e.getMessage()));
                    Msg.error(this, "Error renaming struct", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    /**
     * Delete a struct from the program
     * @param structName Name of struct to delete
     * @return JSON string with result
     */
    public String deleteStruct(String structName) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return createErrorJson("No program loaded");
        }

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int txId = dtm.startTransaction("Delete struct");
                try {
                    DataType struct = findDataType(dtm, structName);
                    if (struct == null) {
                        result.set(createErrorJson("Struct not found: " + structName));
                        dtm.endTransaction(txId, false);
                        return;
                    }

                    dtm.remove(struct, TaskMonitor.DUMMY);
                    dtm.endTransaction(txId, true);

                    result.set(String.format(
                        "{\"success\": true, \"message\": \"Deleted struct '%s'\"}",
                        structName
                    ));

                    Msg.info(this, "Deleted struct: " + structName);

                } catch (Exception e) {
                    dtm.endTransaction(txId, false);
                    result.set(createErrorJson("Failed to delete struct: " + e.getMessage()));
                    Msg.error(this, "Error deleting struct", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(createErrorJson("Failed to execute on Swing thread: " + e.getMessage()));
            Msg.error(this, "Thread error", e);
        }

        return result.get();
    }

    // ==================== HELPER METHODS ====================

    /**
     * Find a data type by name, searching all categories
     */
    private DataType findDataType(DataTypeManager dtm, String typeName) {
        // Try exact match first with path
        if (typeName.startsWith("/")) {
            DataType dt = dtm.getDataType(typeName);
            if (dt != null) return dt;
        }

        // Search all data types
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(typeName)) {
                return dt;
            }
        }

        // Try with leading slash
        return dtm.getDataType("/" + typeName);
    }

    /**
     * Resolve a data type name to a DataType object
     * Similar to FunctionSignatureService.resolveDataType but simplified
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match
        DataType dataType = findDataType(dtm, typeName);
        if (dataType != null) {
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

        // Check for pointer types (ending with *)
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();
            DataType baseType = resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }
            // Default to void*
            return new PointerDataType(dtm.getDataType("/void"));
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
            case "float":
                return dtm.getDataType("/float");
            case "double":
                return dtm.getDataType("/double");
            default:
                // Default to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }

    /**
     * Create an error JSON response
     */
    private String createErrorJson(String message) {
        return String.format("{\"success\": false, \"error\": \"%s\"}", escapeJson(message));
    }

    /**
     * Escape special characters for JSON
     */
    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
}
