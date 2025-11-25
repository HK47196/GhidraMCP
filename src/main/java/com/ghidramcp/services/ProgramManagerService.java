package com.ghidramcp.services;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;

import javax.swing.SwingUtilities;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for managing programs in Ghidra - listing, switching, and importing.
 * Used by test infrastructure for multi-binary support.
 */
public class ProgramManagerService {

    private final PluginTool tool;

    public ProgramManagerService(PluginTool tool) {
        this.tool = tool;
    }

    /**
     * Get the ProgramManager service
     */
    private ProgramManager getProgramManager() {
        return tool.getService(ProgramManager.class);
    }

    /**
     * Get the current project
     */
    private Project getProject() {
        return tool.getProject();
    }

    /**
     * List all programs available in the current project
     * @return JSON array of program info
     */
    public String listPrograms() {
        Project project = getProject();
        if (project == null) {
            return "{\"error\": \"No project open\"}";
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        List<String> programs = new ArrayList<>();
        collectPrograms(rootFolder, programs, "");

        ProgramManager pm = getProgramManager();
        Program currentProgram = pm != null ? pm.getCurrentProgram() : null;
        String currentName = currentProgram != null ? currentProgram.getName() : null;

        StringBuilder json = new StringBuilder();
        json.append("{\"programs\": [");

        for (int i = 0; i < programs.size(); i++) {
            if (i > 0) json.append(", ");
            String progName = programs.get(i);
            boolean isCurrent = progName.equals(currentName);
            json.append(String.format("{\"name\": \"%s\", \"current\": %s}",
                escapeJson(progName), isCurrent));
        }

        json.append("], \"current\": ");
        json.append(currentName != null ? "\"" + escapeJson(currentName) + "\"" : "null");
        json.append("}");

        return json.toString();
    }

    /**
     * Recursively collect program names from folders
     */
    private void collectPrograms(DomainFolder folder, List<String> programs, String prefix) {
        // Get files in this folder
        for (DomainFile file : folder.getFiles()) {
            String contentType = file.getContentType();
            if ("Program".equals(contentType)) {
                programs.add(prefix + file.getName());
            }
        }

        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            collectPrograms(subfolder, programs, prefix + subfolder.getName() + "/");
        }
    }

    /**
     * Switch to a different program by name
     * @param programName Name of the program to switch to
     * @return JSON result
     */
    public String switchProgram(String programName) {
        if (programName == null || programName.isEmpty()) {
            return "{\"error\": \"Program name is required\"}";
        }

        Project project = getProject();
        if (project == null) {
            return "{\"error\": \"No project open\"}";
        }

        ProgramManager pm = getProgramManager();
        if (pm == null) {
            return "{\"error\": \"ProgramManager service not available\"}";
        }

        // Check if already current
        Program currentProgram = pm.getCurrentProgram();
        if (currentProgram != null && currentProgram.getName().equals(programName)) {
            return "{\"success\": true, \"message\": \"Already on program: " + escapeJson(programName) + "\"}";
        }

        // Find the program in the project
        ProjectData projectData = project.getProjectData();
        DomainFile domainFile = findProgramFile(projectData.getRootFolder(), programName);

        if (domainFile == null) {
            return "{\"error\": \"Program not found: " + escapeJson(programName) + "\"}";
        }

        try {
            // Open the program (this must be done on Swing thread)
            AtomicReference<String> result = new AtomicReference<>();
            CountDownLatch latch = new CountDownLatch(1);

            SwingUtilities.invokeLater(() -> {
                try {
                    // Open the domain file as a program
                    Program program = (Program) domainFile.getDomainObject(
                        this, true, false, TaskMonitor.DUMMY);

                    if (program != null) {
                        pm.openProgram(program);
                        pm.setCurrentProgram(program);
                        result.set("{\"success\": true, \"message\": \"Switched to: " +
                            escapeJson(programName) + "\"}");
                    } else {
                        result.set("{\"error\": \"Failed to open program: " +
                            escapeJson(programName) + "\"}");
                    }
                } catch (Exception e) {
                    result.set("{\"error\": \"Failed to switch program: " +
                        escapeJson(e.getMessage()) + "\"}");
                } finally {
                    latch.countDown();
                }
            });

            // Wait for the switch to complete
            if (!latch.await(30, TimeUnit.SECONDS)) {
                return "{\"error\": \"Timeout waiting for program switch\"}";
            }

            return result.get();

        } catch (Exception e) {
            Msg.error(this, "Failed to switch program", e);
            return "{\"error\": \"Failed to switch program: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Find a domain file by program name
     */
    private DomainFile findProgramFile(DomainFolder folder, String programName) {
        // Check files in this folder
        for (DomainFile file : folder.getFiles()) {
            if (file.getName().equals(programName) && "Program".equals(file.getContentType())) {
                return file;
            }
        }

        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            DomainFile found = findProgramFile(subfolder, programName);
            if (found != null) {
                return found;
            }
        }

        return null;
    }

    /**
     * Import a binary file into the project
     * @param filePath Path to the binary file
     * @return JSON result with program name
     */
    public String importBinary(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            return "{\"error\": \"File path is required\"}";
        }

        File file = new File(filePath);
        if (!file.exists()) {
            return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";
        }

        Project project = getProject();
        if (project == null) {
            return "{\"error\": \"No project open\"}";
        }

        ProgramManager pm = getProgramManager();
        if (pm == null) {
            return "{\"error\": \"ProgramManager service not available\"}";
        }

        // Check if already imported
        String programName = file.getName();
        ProjectData projectData = project.getProjectData();
        DomainFile existingFile = findProgramFile(projectData.getRootFolder(), programName);

        if (existingFile != null) {
            return "{\"success\": true, \"message\": \"Program already imported\", \"program_name\": \"" +
                escapeJson(programName) + "\", \"already_exists\": true}";
        }

        try {
            // Import must be done on Swing thread
            AtomicReference<String> result = new AtomicReference<>();
            CountDownLatch latch = new CountDownLatch(1);

            SwingUtilities.invokeLater(() -> {
                LoadResults<Program> loadResults = null;
                try {
                    MessageLog messageLog = new MessageLog();
                    DomainFolder rootFolder = projectData.getRootFolder();

                    // Use AutoImporter to import the file
                    loadResults = AutoImporter.importByUsingBestGuess(
                        file, project, rootFolder.getPathname(),
                        this, messageLog, TaskMonitor.DUMMY);

                    if (loadResults != null && loadResults.getPrimaryDomainObject() != null) {
                        Program importedProgram = loadResults.getPrimaryDomainObject();
                        String importedName = importedProgram.getName();

                        result.set("{\"success\": true, \"message\": \"Imported successfully\", \"program_name\": \"" +
                            escapeJson(importedName) + "\"}");
                    } else {
                        String errors = messageLog.toString();
                        if (errors.isEmpty()) {
                            errors = "Unknown import error";
                        }
                        result.set("{\"error\": \"Import failed: " + escapeJson(errors) + "\"}");
                    }
                } catch (Exception e) {
                    Msg.error(this, "Import failed", e);
                    result.set("{\"error\": \"Import failed: " + escapeJson(e.getMessage()) + "\"}");
                } finally {
                    // Always release LoadResults to free resources
                    if (loadResults != null) {
                        loadResults.release(this);
                    }
                    latch.countDown();
                }
            });

            // Wait for import to complete (can take a while for large binaries)
            if (!latch.await(120, TimeUnit.SECONDS)) {
                return "{\"error\": \"Timeout waiting for import\"}";
            }

            return result.get();

        } catch (Exception e) {
            Msg.error(this, "Failed to import binary", e);
            return "{\"error\": \"Failed to import binary: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get the name of the currently active program
     * @return JSON with current program info
     */
    public String getCurrentProgramInfo() {
        ProgramManager pm = getProgramManager();
        if (pm == null) {
            return "{\"error\": \"ProgramManager service not available\"}";
        }

        Program currentProgram = pm.getCurrentProgram();
        if (currentProgram == null) {
            return "{\"program_name\": null, \"loaded\": false}";
        }

        return "{\"program_name\": \"" + escapeJson(currentProgram.getName()) +
            "\", \"loaded\": true, \"path\": \"" +
            escapeJson(currentProgram.getExecutablePath()) + "\"}";
    }

    /**
     * Escape a string for JSON
     */
    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
