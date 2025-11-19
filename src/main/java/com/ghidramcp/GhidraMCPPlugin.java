package com.ghidramcp;

import com.ghidramcp.model.BulkOperation;
import com.ghidramcp.model.PrototypeResult;
import com.ghidramcp.services.*;
import com.ghidramcp.util.PluginUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

// BSim imports
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import generic.lsh.vector.LSHVectorFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String DECOMPILE_TIMEOUT_OPTION_NAME = "Decompile Timeout";
    private static final int DEFAULT_PORT = 8080;
    private static final int DEFAULT_DECOMPILE_TIMEOUT = 30;

    private int decompileTimeout;

    // BSim database connection state
    private FunctionDatabase bsimDatabase = null;
    private String currentBSimDatabasePath = null;

    // Service instances
    private FunctionNavigator functionNavigator;
    private CommentService commentService;
    private CrossReferenceAnalyzer crossReferenceAnalyzer;
    private DecompilationService decompilationService;
    private DisassemblyService disassemblyService;
    private ProgramAnalyzer programAnalyzer;
    private SymbolManager symbolManager;
    private FunctionSignatureService functionSignatureService;
    private StructService structService;
    private DecompiledTextSearchService decompiledTextSearchService;
    private InstructionPatternSearchService instructionPatternSearchService;
    private FunctionCallGraphService functionCallGraphService;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        options.registerOption(DECOMPILE_TIMEOUT_OPTION_NAME, DEFAULT_DECOMPILE_TIMEOUT,
            null,
            "Decompilation timeout. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");
        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
        this.decompileTimeout = options.getInt(DECOMPILE_TIMEOUT_OPTION_NAME, DEFAULT_DECOMPILE_TIMEOUT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        // Initialize service instances
        functionNavigator = new FunctionNavigator(tool);
        commentService = new CommentService(functionNavigator);
        crossReferenceAnalyzer = new CrossReferenceAnalyzer(functionNavigator);
        decompilationService = new DecompilationService(functionNavigator, decompileTimeout);
        disassemblyService = new DisassemblyService(functionNavigator, decompileTimeout);
        programAnalyzer = new ProgramAnalyzer(functionNavigator);
        symbolManager = new SymbolManager(functionNavigator, decompileTimeout);
        functionSignatureService = new FunctionSignatureService(functionNavigator, decompilationService, tool, decompileTimeout);
        structService = new StructService(functionNavigator);
        decompiledTextSearchService = new DecompiledTextSearchService(functionNavigator, decompileTimeout);
        instructionPatternSearchService = new InstructionPatternSearchService(functionNavigator);
        functionCallGraphService = new FunctionCallGraphService(functionNavigator);

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = PluginUtils.parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, programAnalyzer.getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = PluginUtils.parseIntOrDefault(qparams.get("limit"),  100);
            String search = qparams.get("search");
            sendResponse(exchange, programAnalyzer.getAllClassNames(offset, limit, search));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompilationService.decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String response = symbolManager.renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String response = symbolManager.renameDataAtAddress(
                params.get("address"),
                PluginUtils.getParamFlexible(params, "newName", "new_name")
            ) ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = symbolManager.renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = PluginUtils.parseIntOrDefault(qparams.get("limit"),  100);
            String search = qparams.get("search");
            sendResponse(exchange, programAnalyzer.listSegments(offset, limit, search));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = PluginUtils.parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, programAnalyzer.listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = PluginUtils.parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, programAnalyzer.listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = PluginUtils.parseIntOrDefault(qparams.get("limit"),  100);
            String search = qparams.get("search");
            sendResponse(exchange, programAnalyzer.listNamespaces(offset, limit, search));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = PluginUtils.parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, programAnalyzer.listDefinedData(offset, limit));
        });

        server.createContext("/get_data_by_address", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, programAnalyzer.getDataByAddress(address));
        });

        server.createContext("/data_in_range", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String startAddress = qparams.get("start_address");
            String endAddress = qparams.get("end_address");
            boolean includeUndefined = Boolean.parseBoolean(qparams.getOrDefault("include_undefined", "false"));
            sendResponse(exchange, programAnalyzer.getDataInRange(startAddress, endAddress, includeUndefined));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            String namespace = qparams.get("namespace");
            String functionName = qparams.get("function_name");
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, programAnalyzer.searchFunctionsByName(searchTerm, namespace, functionName, offset, limit));
        });

        server.createContext("/searchData", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, programAnalyzer.searchDataByName(searchTerm, offset, limit));
        });

        server.createContext("/search_instruction_pattern", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String searchPattern = qparams.get("search");
            String segmentName = qparams.get("segment_name");
            String startAddress = qparams.get("start_address");
            String endAddress = qparams.get("end_address");
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, instructionPatternSearchService.searchInstructionPattern(
                searchPattern, segmentName, startAddress, endAddress, offset, limit));
        });

        server.createContext("/functions_by_segment", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String segmentName = qparams.get("segment_name");
            String startAddress = qparams.get("start_address");
            String endAddress = qparams.get("end_address");
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, programAnalyzer.listFunctionsBySegment(segmentName, startAddress, endAddress, offset, limit));
        });

        server.createContext("/data_by_segment", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String segmentName = qparams.get("segment_name");
            String startAddress = qparams.get("start_address");
            String endAddress = qparams.get("end_address");
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, programAnalyzer.listDataBySegment(segmentName, startAddress, endAddress, offset, limit));
        });

        // New API endpoints based on requirements

        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, functionNavigator.getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, functionNavigator.getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, functionNavigator.getCurrentFunction());
        });

        server.createContext("/ping", exchange -> {
            Program currentProgram = functionNavigator.getCurrentProgram();
            String programName = currentProgram != null ? currentProgram.getName() : null;
            boolean programLoaded = currentProgram != null;
            String response = String.format("{\"status\": \"pong\", \"program_loaded\": %s, \"program_name\": %s}",
                programLoaded,
                programName != null ? "\"" + programName + "\"" : "null");
            sendResponse(exchange, response);
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompilationService.decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            boolean includeBytes = PluginUtils.parseBoolOrDefault(qparams.get("include_bytes"), false);
            sendResponse(exchange, disassemblyService.disassembleFunction(address, includeBytes));
        });

        server.createContext("/get_address_context", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int before = PluginUtils.parseIntOrDefault(qparams.get("before"), 5);
            int after = PluginUtils.parseIntOrDefault(qparams.get("after"), 5);
            boolean includeBytes = PluginUtils.parseBoolOrDefault(qparams.get("include_bytes"), false);
            sendResponse(exchange, disassemblyService.getAddressContext(address, before, after, includeBytes));
        });

        server.createContext("/get_function_data", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            String name = qparams.get("name");

            String response;
            if (address != null && !address.isEmpty()) {
                response = decompilationService.getDataReferencesFromFunctionByAddress(address);
            } else if (name != null && !name.isEmpty()) {
                response = decompilationService.getDataReferencesFromFunctionByName(name);
            } else {
                response = "Error: Either 'address' or 'name' parameter is required";
            }

            sendResponse(exchange, response);
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = commentService.setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = commentService.setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_plate_comment", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = commentService.setPlateComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = symbolManager.renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = functionSignatureService.setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = functionNavigator.getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = functionSignatureService.resolveDataType(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else {
                    responseMsg.append("Type not found: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = functionSignatureService.setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/set_data_type", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String address = params.get("address");
            String typeName = params.get("type_name");

            if (address == null || address.isEmpty() || typeName == null || typeName.isEmpty()) {
                sendResponse(exchange, "Error: Both 'address' and 'type_name' parameters are required");
                return;
            }

            boolean success = functionSignatureService.setDataType(address, typeName);
            String successMsg = success ?
                "Data type '" + typeName + "' set successfully at address " + address :
                "Failed to set data type at address " + address;

            sendResponse(exchange, successMsg);
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(qparams.get("limit"), 100);
            int includeInstruction = PluginUtils.parseIncludeInstructionParam(qparams.get("include_instruction"));
            sendResponse(exchange, crossReferenceAnalyzer.getXrefsTo(address, offset, limit, includeInstruction));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(qparams.get("limit"), 100);
            int includeInstruction = PluginUtils.parseIncludeInstructionParam(qparams.get("include_instruction"));
            sendResponse(exchange, crossReferenceAnalyzer.getXrefsFrom(address, offset, limit, includeInstruction));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(qparams.get("limit"), 100);
            int includeInstruction = PluginUtils.parseIncludeInstructionParam(qparams.get("include_instruction"));
            sendResponse(exchange, crossReferenceAnalyzer.getFunctionXrefs(name, offset, limit, includeInstruction));
        });

        server.createContext("/function_callees", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int depth = PluginUtils.parseIntOrDefault(qparams.get("depth"), 1);
            sendResponse(exchange, functionCallGraphService.getFunctionCallees(address, depth));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(qparams.get("limit"), 100);
            String search = qparams.get("search");
            sendResponse(exchange, programAnalyzer.listDefinedStrings(offset, limit, search));
        });

        server.createContext("/search_decompiled_text", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String pattern = params.get("pattern");
            boolean isRegex = Boolean.parseBoolean(params.getOrDefault("is_regex", "true"));
            boolean caseSensitive = Boolean.parseBoolean(params.getOrDefault("case_sensitive", "true"));
            boolean multiline = Boolean.parseBoolean(params.getOrDefault("multiline", "false"));
            int maxResults = PluginUtils.parseIntOrDefault(params.get("max_results"), 0);
            int offset = PluginUtils.parseIntOrDefault(params.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(params.get("limit"), 100);

            // Parse function names if provided
            List<String> functionNames = null;
            String functionNamesStr = params.get("function_names");
            if (functionNamesStr != null && !functionNamesStr.isEmpty()) {
                functionNames = parseFunctionNamesList(functionNamesStr);
            }

            String result = decompiledTextSearchService.searchDecompiledText(
                pattern, isRegex, caseSensitive, multiline, functionNames, maxResults, offset, limit
            );
            sendResponse(exchange, result);
        });

        // BSim endpoints
        server.createContext("/bsim/select_database", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String dbPath = params.get("database_path");
            sendResponse(exchange, selectBSimDatabase(dbPath));
        });

        server.createContext("/bsim/query_function", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            int maxMatches = PluginUtils.parseIntOrDefault(params.get("max_matches"), 10);
            double similarityThreshold = PluginUtils.parseDoubleOrDefault(params.get("similarity_threshold"), "0.7");
            double confidenceThreshold = PluginUtils.parseDoubleOrDefault(params.get("confidence_threshold"), "0.0");
            double maxSimilarity = PluginUtils.parseDoubleOrDefault(params.get("max_similarity"), String.valueOf(Double.POSITIVE_INFINITY));
            double maxConfidence = PluginUtils.parseDoubleOrDefault(params.get("max_confidence"), String.valueOf(Double.POSITIVE_INFINITY));
            int offset = PluginUtils.parseIntOrDefault(params.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(params.get("limit"), 100);
            sendResponse(exchange, queryBSimFunction(functionAddress, maxMatches, similarityThreshold, confidenceThreshold, maxSimilarity, maxConfidence, offset, limit));
        });

        server.createContext("/bsim/query_all_functions", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            int maxMatchesPerFunction = PluginUtils.parseIntOrDefault(params.get("max_matches_per_function"), 5);
            double similarityThreshold = PluginUtils.parseDoubleOrDefault(params.get("similarity_threshold"), "0.7");
            double confidenceThreshold = PluginUtils.parseDoubleOrDefault(params.get("confidence_threshold"), "0.0");
            double maxSimilarity = PluginUtils.parseDoubleOrDefault(params.get("max_similarity"), String.valueOf(Double.POSITIVE_INFINITY));
            double maxConfidence = PluginUtils.parseDoubleOrDefault(params.get("max_confidence"), String.valueOf(Double.POSITIVE_INFINITY));
            int offset = PluginUtils.parseIntOrDefault(params.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(params.get("limit"), 100);
            sendResponse(exchange, queryAllBSimFunctions(maxMatchesPerFunction, similarityThreshold, confidenceThreshold, maxSimilarity, maxConfidence, offset, limit));
        });

        server.createContext("/bsim/disconnect", exchange -> {
            sendResponse(exchange, disconnectBSimDatabase());
        });

        server.createContext("/bsim/status", exchange -> {
            sendResponse(exchange, getBSimStatus());
        });

        server.createContext("/bsim/get_match_disassembly", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String executablePath = params.get("executable_path");
            String functionName = params.get("function_name");
            String functionAddress = params.get("function_address");
            sendResponse(exchange, getBSimMatchDisassembly(executablePath, functionName, functionAddress));
        });

        server.createContext("/bsim/get_match_decompile", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String executablePath = params.get("executable_path");
            String functionName = params.get("function_name");
            String functionAddress = params.get("function_address");
            sendResponse(exchange, getBSimMatchDecompile(executablePath, functionName, functionAddress));
        });

        // Struct operations endpoints
        server.createContext("/struct/create", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String name = params.get("name");
            int size = PluginUtils.parseIntOrDefault(params.get("size"), 0);
            String categoryPath = params.get("category_path");
            sendResponse(exchange, structService.createStruct(name, size, categoryPath));
        });

        server.createContext("/struct/parse_c", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String cCode = params.get("c_code");
            String categoryPath = params.get("category_path");
            sendResponse(exchange, structService.parseCStruct(cCode, categoryPath));
        });

        server.createContext("/struct/add_field", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String structName = params.get("struct_name");
            String fieldType = params.get("field_type");
            String fieldName = params.get("field_name");
            int length = PluginUtils.parseIntOrDefault(params.get("length"), -1);
            String comment = params.get("comment");
            sendResponse(exchange, structService.addStructField(structName, fieldType, fieldName, length, comment));
        });

        server.createContext("/struct/insert_field", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String structName = params.get("struct_name");
            int offset = PluginUtils.parseIntOrDefault(params.get("offset"), 0);
            String fieldType = params.get("field_type");
            String fieldName = params.get("field_name");
            int length = PluginUtils.parseIntOrDefault(params.get("length"), -1);
            String comment = params.get("comment");
            sendResponse(exchange, structService.insertStructFieldAtOffset(structName, offset, fieldType, fieldName, length, comment));
        });

        server.createContext("/struct/replace_field", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String structName = params.get("struct_name");
            int ordinal = PluginUtils.parseIntOrDefault(params.get("ordinal"), 0);
            String fieldType = params.get("field_type");
            String fieldName = params.get("field_name");
            int length = PluginUtils.parseIntOrDefault(params.get("length"), -1);
            String comment = params.get("comment");
            sendResponse(exchange, structService.replaceStructField(structName, ordinal, fieldType, fieldName, length, comment));
        });

        server.createContext("/struct/delete_field", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String structName = params.get("struct_name");
            int ordinal = PluginUtils.parseIntOrDefault(params.get("ordinal"), -1);
            int offset = PluginUtils.parseIntOrDefault(params.get("offset"), -1);
            sendResponse(exchange, structService.deleteStructField(structName, ordinal, offset));
        });

        server.createContext("/struct/clear_field", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String structName = params.get("struct_name");
            int ordinal = PluginUtils.parseIntOrDefault(params.get("ordinal"), -1);
            int offset = PluginUtils.parseIntOrDefault(params.get("offset"), -1);
            sendResponse(exchange, structService.clearStructField(structName, ordinal, offset));
        });

        server.createContext("/struct/get_info", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String structName = qparams.get("name");
            sendResponse(exchange, structService.getStructInfo(structName));
        });

        server.createContext("/struct/list", exchange -> {
            Map<String, String> qparams = PluginUtils.parseQueryParams(exchange);
            String categoryPath = qparams.get("category_path");
            String search = qparams.get("search");
            int offset = PluginUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = PluginUtils.parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, structService.listStructs(categoryPath, search, offset, limit));
        });

        server.createContext("/struct/rename", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            sendResponse(exchange, structService.renameStruct(oldName, newName));
        });

        server.createContext("/struct/delete", exchange -> {
            Map<String, String> params = PluginUtils.parsePostParams(exchange);
            String structName = params.get("name");
            sendResponse(exchange, structService.deleteStruct(structName));
        });

        // Bulk operations endpoint
        server.createContext("/bulk", exchange -> {
            try {
                byte[] body = exchange.getRequestBody().readAllBytes();
                String bodyStr = new String(body, StandardCharsets.UTF_8);
                String result = processBulkOperations(bodyStr);
                sendResponse(exchange, result);
            } catch (Exception e) {
                sendResponse(exchange, "{\"error\": \"" + PluginUtils.escapeJson(e.getMessage()) + "\"}");
            }
        });

        // Undo management endpoints
        server.createContext("/undo/can_undo", exchange -> {
            Program program = functionNavigator.getCurrentProgram();
            boolean canUndo = program != null && program.canUndo();
            sendResponse(exchange, "{\"can_undo\": " + canUndo + "}");
        });

        server.createContext("/undo/undo", exchange -> {
            Program program = functionNavigator.getCurrentProgram();
            if (program == null) {
                exchange.sendResponseHeaders(404, 0);
                sendResponse(exchange, "{\"error\": \"No program loaded\"}");
                return;
            }

            try {
                if (program.canUndo()) {
                    program.undo();
                    sendResponse(exchange, "{\"success\": true, \"message\": \"Undo successful\"}");
                } else {
                    sendResponse(exchange, "{\"success\": false, \"message\": \"Nothing to undo\"}");
                }
            } catch (IOException e) {
                exchange.sendResponseHeaders(500, 0);
                sendResponse(exchange, "{\"error\": \"Undo failed: " + PluginUtils.escapeJson(e.getMessage()) + "\"}");
            }
        });

        server.createContext("/undo/clear", exchange -> {
            Program program = functionNavigator.getCurrentProgram();
            if (program == null) {
                exchange.sendResponseHeaders(404, 0);
                sendResponse(exchange, "{\"error\": \"No program loaded\"}");
                return;
            }

            program.clearUndo();
            sendResponse(exchange, "{\"success\": true, \"message\": \"Undo stack cleared\"}");
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Bulk operations support
    // ----------------------------------------------------------------------------------

    /**
     * Process bulk operations from JSON input.
     * Expected format: {"operations": [{"endpoint": "/methods", "method": "GET", "params": {...}}, ...]}
     */
    private String processBulkOperations(String jsonInput) {
        try {
            // Parse the JSON input manually (simple parsing for our specific format)
            List<BulkOperation> operations = parseBulkOperationsJson(jsonInput);

            StringBuilder jsonResponse = new StringBuilder();
            jsonResponse.append("{\"results\": [");

            boolean first = true;
            for (BulkOperation op : operations) {
                if (!first) {
                    jsonResponse.append(", ");
                }
                first = false;

                String result = executeBulkOperation(op);
                jsonResponse.append("{\"success\": true, \"result\": \"");
                jsonResponse.append(PluginUtils.escapeJson(result));
                jsonResponse.append("\"}");
            }

            jsonResponse.append("]}");
            return jsonResponse.toString();

        } catch (Exception e) {
            return "{\"error\": \"" + PluginUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Execute a single bulk operation
     */
    private String executeBulkOperation(BulkOperation op) {
        try {
            String endpoint = op.getEndpoint();
            Map<String, String> params = op.getParams();

            // Route to appropriate handler based on endpoint
            switch (endpoint) {
                case "/methods":
                    return programAnalyzer.getAllFunctionNames(
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/classes":
                    return programAnalyzer.getAllClassNames(
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100),
                        params.get("search")
                    );

                case "/decompile":
                    return decompilationService.decompileFunctionByName(params.get("name"));

                case "/renameFunction":
                case "/rename_function":
                    return symbolManager.renameFunction(params.get("oldName"), params.get("newName"))
                        ? "Renamed successfully" : "Rename failed";

                case "/renameData":
                case "/rename_data":
                    return symbolManager.renameDataAtAddress(
                        params.get("address"),
                        PluginUtils.getParamFlexible(params, "newName", "new_name")
                    ) ? "Renamed successfully" : "Rename failed";

                case "/renameVariable":
                case "/rename_variable":
                    return symbolManager.renameVariableInFunction(
                        params.get("functionName"),
                        params.get("oldName"),
                        params.get("newName")
                    );

                case "/segments":
                    return programAnalyzer.listSegments(
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100),
                        params.get("search")
                    );

                case "/imports":
                    return programAnalyzer.listImports(
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/exports":
                    return programAnalyzer.listExports(
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/namespaces":
                    return programAnalyzer.listNamespaces(
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100),
                        params.get("search")
                    );

                case "/data":
                    return programAnalyzer.listDefinedData(
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/get_data_by_address":
                    return programAnalyzer.getDataByAddress(params.get("address"));

                case "/data_in_range":
                    boolean includeUndef = Boolean.parseBoolean(params.getOrDefault("include_undefined", "false"));
                    return programAnalyzer.getDataInRange(
                        params.get("start_address"),
                        params.get("end_address"),
                        includeUndef
                    );

                case "/searchFunctions":
                    return programAnalyzer.searchFunctionsByName(
                        params.get("query"),
                        params.get("namespace"),
                        params.get("function_name"),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/searchData":
                    return programAnalyzer.searchDataByName(
                        params.get("query"),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/functions_by_segment":
                    return programAnalyzer.listFunctionsBySegment(
                        params.get("segment_name"),
                        params.get("start_address"),
                        params.get("end_address"),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/data_by_segment":
                    return programAnalyzer.listDataBySegment(
                        params.get("segment_name"),
                        params.get("start_address"),
                        params.get("end_address"),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/get_function_by_address":
                    return functionNavigator.getFunctionByAddress(params.get("address"));

                case "/get_current_address":
                    return functionNavigator.getCurrentAddress();

                case "/get_current_function":
                    return functionNavigator.getCurrentFunction();

                case "/decompile_function":
                    return decompilationService.decompileFunctionByAddress(params.get("address"));

                case "/disassemble_function":
                    return disassemblyService.disassembleFunction(
                        params.get("address"),
                        PluginUtils.parseBoolOrDefault(params.get("include_bytes"), false)
                    );

                case "/get_address_context":
                    return disassemblyService.getAddressContext(
                        params.get("address"),
                        PluginUtils.parseIntOrDefault(params.get("before"), 5),
                        PluginUtils.parseIntOrDefault(params.get("after"), 5),
                        PluginUtils.parseBoolOrDefault(params.get("include_bytes"), false)
                    );

                case "/get_function_data":
                    String dataAddress = params.get("address");
                    String dataName = params.get("name");
                    if (dataAddress != null && !dataAddress.isEmpty()) {
                        return decompilationService.getDataReferencesFromFunctionByAddress(dataAddress);
                    } else if (dataName != null && !dataName.isEmpty()) {
                        return decompilationService.getDataReferencesFromFunctionByName(dataName);
                    } else {
                        return "Error: Either 'address' or 'name' parameter is required";
                    }

                case "/set_decompiler_comment":
                    return commentService.setDecompilerComment(params.get("address"), params.get("comment"))
                        ? "Comment set successfully" : "Failed to set comment";

                case "/set_disassembly_comment":
                    return commentService.setDisassemblyComment(params.get("address"), params.get("comment"))
                        ? "Comment set successfully" : "Failed to set comment";

                case "/set_plate_comment":
                    return commentService.setPlateComment(params.get("address"), params.get("comment"))
                        ? "Comment set successfully" : "Failed to set comment";

                case "/rename_function_by_address":
                    return symbolManager.renameFunctionByAddress(params.get("function_address"), params.get("new_name"))
                        ? "Function renamed successfully" : "Failed to rename function";

                case "/set_function_prototype":
                    PrototypeResult result = functionSignatureService.setFunctionPrototype(
                        params.get("function_address"),
                        params.get("prototype")
                    );
                    if (result.isSuccess()) {
                        String successMsg = "Function prototype set successfully";
                        if (!result.getErrorMessage().isEmpty()) {
                            successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                        }
                        return successMsg;
                    } else {
                        return "Failed to set function prototype: " + result.getErrorMessage();
                    }

                case "/set_local_variable_type":
                    StringBuilder responseMsg = new StringBuilder();
                    responseMsg.append("Setting variable type: ").append(params.get("variable_name"))
                              .append(" to ").append(params.get("new_type"))
                              .append(" in function at ").append(params.get("function_address")).append("\n\n");

                    Program program = functionNavigator.getCurrentProgram();
                    if (program != null) {
                        DataTypeManager dtm = program.getDataTypeManager();
                        String newType = params.get("new_type");
                        DataType directType = functionSignatureService.resolveDataType(dtm, newType);
                        if (directType != null) {
                            responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                        } else {
                            responseMsg.append("Type not found: ").append(newType).append("\n");
                        }
                    }

                    boolean success = functionSignatureService.setLocalVariableType(
                        params.get("function_address"),
                        params.get("variable_name"),
                        params.get("new_type")
                    );
                    responseMsg.append("\nResult: ").append(success ? "Variable type set successfully" : "Failed to set variable type");
                    return responseMsg.toString();

                case "/set_data_type":
                    String address = params.get("address");
                    String typeName = params.get("type_name");

                    if (address == null || address.isEmpty() || typeName == null || typeName.isEmpty()) {
                        return "Error: Both 'address' and 'type_name' parameters are required";
                    }

                    boolean dataTypeSuccess = functionSignatureService.setDataType(address, typeName);
                    return dataTypeSuccess ?
                        "Data type '" + typeName + "' set successfully at address " + address :
                        "Failed to set data type at address " + address;

                case "/xrefs_to":
                    return crossReferenceAnalyzer.getXrefsTo(
                        params.get("address"),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100),
                        PluginUtils.parseIncludeInstructionParam(params.get("include_instruction"))
                    );

                case "/xrefs_from":
                    return crossReferenceAnalyzer.getXrefsFrom(
                        params.get("address"),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100),
                        PluginUtils.parseIncludeInstructionParam(params.get("include_instruction"))
                    );

                case "/function_xrefs":
                    return crossReferenceAnalyzer.getFunctionXrefs(
                        params.get("name"),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100),
                        PluginUtils.parseIncludeInstructionParam(params.get("include_instruction"))
                    );

                case "/strings":
                    return programAnalyzer.listDefinedStrings(
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100),
                        params.get("search")
                    );

                case "/search_decompiled_text":
                    String pattern = params.get("pattern");
                    boolean isRegex = Boolean.parseBoolean(params.getOrDefault("is_regex", "true"));
                    boolean caseSensitive = Boolean.parseBoolean(params.getOrDefault("case_sensitive", "true"));
                    boolean multiline = Boolean.parseBoolean(params.getOrDefault("multiline", "false"));
                    int maxResults = PluginUtils.parseIntOrDefault(params.get("max_results"), 0);
                    int searchOffset = PluginUtils.parseIntOrDefault(params.get("offset"), 0);
                    int searchLimit = PluginUtils.parseIntOrDefault(params.get("limit"), 100);

                    List<String> funcNames = null;
                    String funcNamesStr = params.get("function_names");
                    if (funcNamesStr != null && !funcNamesStr.isEmpty()) {
                        funcNames = parseFunctionNamesList(funcNamesStr);
                    }

                    return decompiledTextSearchService.searchDecompiledText(
                        pattern, isRegex, caseSensitive, multiline, funcNames, maxResults, searchOffset, searchLimit
                    );

                case "/bsim/select_database":
                    return selectBSimDatabase(params.get("database_path"));

                case "/bsim/query_function":
                    return queryBSimFunction(
                        params.get("function_address"),
                        PluginUtils.parseIntOrDefault(params.get("max_matches"), 10),
                        PluginUtils.parseDoubleOrDefault(params.get("similarity_threshold"), "0.7"),
                        PluginUtils.parseDoubleOrDefault(params.get("confidence_threshold"), "0.0"),
                        PluginUtils.parseDoubleOrDefault(params.get("max_similarity"), String.valueOf(Double.POSITIVE_INFINITY)),
                        PluginUtils.parseDoubleOrDefault(params.get("max_confidence"), String.valueOf(Double.POSITIVE_INFINITY)),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/bsim/query_all_functions":
                    return queryAllBSimFunctions(
                        PluginUtils.parseIntOrDefault(params.get("max_matches_per_function"), 5),
                        PluginUtils.parseDoubleOrDefault(params.get("similarity_threshold"), "0.7"),
                        PluginUtils.parseDoubleOrDefault(params.get("confidence_threshold"), "0.0"),
                        PluginUtils.parseDoubleOrDefault(params.get("max_similarity"), String.valueOf(Double.POSITIVE_INFINITY)),
                        PluginUtils.parseDoubleOrDefault(params.get("max_confidence"), String.valueOf(Double.POSITIVE_INFINITY)),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/bsim/disconnect":
                    return disconnectBSimDatabase();

                case "/bsim/status":
                    return getBSimStatus();

                case "/bsim/get_match_disassembly":
                    return getBSimMatchDisassembly(
                        params.get("executable_path"),
                        params.get("function_name"),
                        params.get("function_address")
                    );

                case "/bsim/get_match_decompile":
                    return getBSimMatchDecompile(
                        params.get("executable_path"),
                        params.get("function_name"),
                        params.get("function_address")
                    );

                // Struct operations
                case "/struct/create":
                    return structService.createStruct(
                        params.get("name"),
                        PluginUtils.parseIntOrDefault(params.get("size"), 0),
                        params.get("category_path")
                    );

                case "/struct/parse_c":
                    return structService.parseCStruct(
                        params.get("c_code"),
                        params.get("category_path")
                    );

                case "/struct/add_field":
                    return structService.addStructField(
                        params.get("struct_name"),
                        params.get("field_type"),
                        params.get("field_name"),
                        PluginUtils.parseIntOrDefault(params.get("length"), -1),
                        params.get("comment")
                    );

                case "/struct/insert_field":
                    return structService.insertStructFieldAtOffset(
                        params.get("struct_name"),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        params.get("field_type"),
                        params.get("field_name"),
                        PluginUtils.parseIntOrDefault(params.get("length"), -1),
                        params.get("comment")
                    );

                case "/struct/replace_field":
                    return structService.replaceStructField(
                        params.get("struct_name"),
                        PluginUtils.parseIntOrDefault(params.get("ordinal"), 0),
                        params.get("field_type"),
                        params.get("field_name"),
                        PluginUtils.parseIntOrDefault(params.get("length"), -1),
                        params.get("comment")
                    );

                case "/struct/delete_field":
                    return structService.deleteStructField(
                        params.get("struct_name"),
                        PluginUtils.parseIntOrDefault(params.get("ordinal"), -1),
                        PluginUtils.parseIntOrDefault(params.get("offset"), -1)
                    );

                case "/struct/clear_field":
                    return structService.clearStructField(
                        params.get("struct_name"),
                        PluginUtils.parseIntOrDefault(params.get("ordinal"), -1),
                        PluginUtils.parseIntOrDefault(params.get("offset"), -1)
                    );

                case "/struct/get_info":
                    return structService.getStructInfo(params.get("name"));

                case "/struct/list":
                    return structService.listStructs(
                        params.get("category_path"),
                        params.get("search"),
                        PluginUtils.parseIntOrDefault(params.get("offset"), 0),
                        PluginUtils.parseIntOrDefault(params.get("limit"), 100)
                    );

                case "/struct/rename":
                    return structService.renameStruct(
                        params.get("old_name"),
                        params.get("new_name")
                    );

                case "/struct/delete":
                    return structService.deleteStruct(params.get("name"));

                default:
                    return "Error: Unknown endpoint: " + endpoint;
            }
        } catch (Exception e) {
            return "Error executing operation: " + e.getMessage();
        }
    }

    /**
     * Parse bulk operations JSON (simple manual parsing)
     */
    private List<BulkOperation> parseBulkOperationsJson(String json) {
        List<BulkOperation> operations = new ArrayList<>();

        // Find the operations array
        int opsStart = json.indexOf("\"operations\"");
        if (opsStart == -1) {
            throw new RuntimeException("Missing 'operations' field in JSON");
        }

        int arrayStart = json.indexOf("[", opsStart);
        int arrayEnd = json.lastIndexOf("]");

        if (arrayStart == -1 || arrayEnd == -1) {
            throw new RuntimeException("Invalid operations array format");
        }

        String opsContent = json.substring(arrayStart + 1, arrayEnd);

        // Parse each operation object
        int depth = 0;
        int objStart = -1;

        for (int i = 0; i < opsContent.length(); i++) {
            char c = opsContent.charAt(i);

            if (c == '{') {
                if (depth == 0) {
                    objStart = i;
                }
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0 && objStart != -1) {
                    String objStr = opsContent.substring(objStart, i + 1);
                    operations.add(parseSingleOperation(objStr));
                    objStart = -1;
                }
            }
        }

        return operations;
    }

    /**
     * Parse a single operation object
     */
    private BulkOperation parseSingleOperation(String json) {
        BulkOperation op = new BulkOperation();
        Map<String, String> params = new HashMap<>();

        // Extract endpoint
        String endpoint = extractJsonValue(json, "endpoint");
        op.setEndpoint(endpoint);

        // Extract params object
        int paramsStart = json.indexOf("\"params\"");
        if (paramsStart != -1) {
            int objStart = json.indexOf("{", paramsStart);

            if (objStart != -1) {
                // Find matching closing brace by counting depth
                int objEnd = findMatchingBrace(json, objStart);

                if (objEnd != -1 && objStart < objEnd) {
                    String paramsJson = json.substring(objStart + 1, objEnd);

                    // Parse key-value pairs
                    String[] pairs = paramsJson.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                    for (String pair : pairs) {
                        int colonIdx = pair.indexOf(":");
                        if (colonIdx != -1) {
                            String key = pair.substring(0, colonIdx).trim();
                            String value = pair.substring(colonIdx + 1).trim();

                            // Remove quotes and unescape JSON strings
                            key = key.replaceAll("^\"|\"$", "");
                            value = value.replaceAll("^\"|\"$", "");
                            value = unescapeJsonString(value);

                            params.put(key, value);
                        }
                    }
                }
            }
        }

        op.setParams(params);
        return op;
    }

    /**
     * Find the matching closing brace for an opening brace at the given position
     */
    private int findMatchingBrace(String json, int openBracePos) {
        int depth = 0;
        boolean inString = false;
        boolean escapeNext = false;

        for (int i = openBracePos; i < json.length(); i++) {
            char c = json.charAt(i);

            if (escapeNext) {
                escapeNext = false;
                continue;
            }

            if (c == '\\') {
                escapeNext = true;
                continue;
            }

            if (c == '"') {
                inString = !inString;
                continue;
            }

            if (!inString) {
                if (c == '{') {
                    depth++;
                } else if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        return i;
                    }
                }
            }
        }

        return -1; // No matching brace found
    }

    /**
     * Extract a simple string value from JSON
     */
    private String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) {
            return null;
        }

        int colonIndex = json.indexOf(":", keyIndex);
        if (colonIndex == -1) {
            return null;
        }

        int valueStart = colonIndex + 1;
        while (valueStart < json.length() && (json.charAt(valueStart) == ' ' || json.charAt(valueStart) == '\t')) {
            valueStart++;
        }

        if (valueStart >= json.length()) {
            return null;
        }

        int valueEnd;
        if (json.charAt(valueStart) == '"') {
            // String value
            valueStart++;
            valueEnd = valueStart;
            while (valueEnd < json.length() && json.charAt(valueEnd) != '"') {
                if (json.charAt(valueEnd) == '\\') {
                    valueEnd++; // Skip escaped character
                }
                valueEnd++;
            }
        } else {
            // Non-string value
            valueEnd = valueStart;
            while (valueEnd < json.length() && json.charAt(valueEnd) != ',' && json.charAt(valueEnd) != '}') {
                valueEnd++;
            }
        }

        return json.substring(valueStart, valueEnd).trim();
    }

    /**
     * Unescape JSON string escape sequences like \n, \t, \", \\, etc.
     */
    private String unescapeJsonString(String str) {
        if (str == null) {
            return null;
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c == '\\' && i + 1 < str.length()) {
                char next = str.charAt(i + 1);
                switch (next) {
                    case 'n': result.append('\n'); i++; break;
                    case 't': result.append('\t'); i++; break;
                    case 'r': result.append('\r'); i++; break;
                    case 'b': result.append('\b'); i++; break;
                    case 'f': result.append('\f'); i++; break;
                    case '"': result.append('"'); i++; break;
                    case '\\': result.append('\\'); i++; break;
                    case '/': result.append('/'); i++; break;
                    case 'u': // Unicode escape (backslash-u followed by 4 hex digits)
                        if (i + 5 < str.length()) {
                            String hex = str.substring(i + 2, i + 6);
                            try {
                                result.append((char) Integer.parseInt(hex, 16));
                                i += 5;
                            } catch (NumberFormatException e) {
                                result.append(c); // Keep original if invalid
                            }
                        } else {
                            result.append(c);
                        }
                        break;
                    default:
                        result.append(c); // Keep the backslash for unknown escapes
                }
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    // ----------------------------------------------------------------------------------
    // BSim functionality
    // ----------------------------------------------------------------------------------

    /**
     * Select and connect to a BSim database
     */
    private String selectBSimDatabase(String databasePath) {
        if (databasePath == null || databasePath.isEmpty()) {
            return "Error: Database path is required";
        }

        try {
            // Disconnect from any existing database first
            if (bsimDatabase != null) {
                disconnectBSimDatabase();
            }

            // Create BSimServerInfo from the path/URL
            // Use URL constructor for URLs (postgresql://, file://, etc.)
            // Use String constructor only for file paths
            BSimServerInfo serverInfo;
            if (databasePath.contains("://")) {
                // It's a URL - use URL constructor
                serverInfo = new BSimServerInfo(new java.net.URL(databasePath));
            } else {
                // It's a file path - use String constructor
                serverInfo = new BSimServerInfo(databasePath);
            }

            // Initialize the database connection
            bsimDatabase = BSimClientFactory.buildClient(serverInfo, false);

            if (bsimDatabase == null) {
                return "Error: Failed to create BSim database client";
            }

            // Try to initialize the connection
            if (!bsimDatabase.initialize()) {
                bsimDatabase = null;
                return "Error: Failed to initialize BSim database connection";
            }

            currentBSimDatabasePath = databasePath;
            return "Successfully connected to BSim database: " + databasePath;

        } catch (Exception e) {
            bsimDatabase = null;
            currentBSimDatabasePath = null;
            return "Error connecting to BSim database: " + e.getMessage();
        }
    }

    /**
     * Disconnect from the current BSim database
     */
    private String disconnectBSimDatabase() {
        if (bsimDatabase != null) {
            try {
                bsimDatabase.close();
                bsimDatabase = null;
                String path = currentBSimDatabasePath;
                currentBSimDatabasePath = null;
                return "Disconnected from BSim database: " + path;
            } catch (Exception e) {
                return "Error disconnecting from BSim database: " + e.getMessage();
            }
        }
        return "No BSim database connection to disconnect";
    }

    /**
     * Get the current BSim database connection status
     */
    private String getBSimStatus() {
        if (bsimDatabase != null && currentBSimDatabasePath != null) {
            try {
                StringBuilder status = new StringBuilder();
                status.append("Connected to: ").append(currentBSimDatabasePath).append("\n");
                status.append("Database info:\n");

                LSHVectorFactory vectorFactory = bsimDatabase.getLSHVectorFactory();
                if (vectorFactory != null) {
                    status.append("  Vector Factory: ").append(vectorFactory.getClass().getSimpleName()).append("\n");
                } else {
                    status.append("  Vector Factory: null (ERROR)\n");
                }

                // Try to get database info
                QueryInfo infoQuery = new QueryInfo();
                ResponseInfo infoResponse = infoQuery.execute(bsimDatabase);
                if (infoResponse != null && infoResponse.info != null) {
                    status.append("  Database name: ").append(infoResponse.info.databasename).append("\n");
                }

                return status.toString();
            } catch (Exception e) {
                return "Connected to: " + currentBSimDatabasePath + " (Error getting details: " + e.getMessage() + ")";
            }
        }
        return "Not connected to any BSim database";
    }

    /**
     * Query a single function against the BSim database
     *
     * @param functionAddress Address of the function to query
     * @param maxMatches Maximum number of matches to return
     * @param similarityThreshold Minimum similarity score (inclusive, 0.0-1.0)
     * @param confidenceThreshold Minimum confidence score (inclusive, 0.0-1.0)
     * @param maxSimilarity Maximum similarity score (exclusive, 0.0-1.0, default: unbounded/infinity)
     * @param maxConfidence Maximum confidence score (exclusive, 0.0-1.0, default: unbounded/infinity)
     * @param offset Pagination offset
     * @param limit Maximum number of results to return
     */
    private String queryBSimFunction(String functionAddress, int maxMatches,
                                     double similarityThreshold, double confidenceThreshold,
                                     double maxSimilarity, double maxConfidence,
                                     int offset, int limit) {
        if (bsimDatabase == null) {
            return "Error: Not connected to a BSim database. Use bsim_select_database first.";
        }

        Program program = functionNavigator.getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = program.getFunctionManager().getFunctionContaining(addr);
            }
            if (func == null) {
                return "Error: No function found at address " + functionAddress;
            }

            // Generate signature for this function
            GenSignatures gensig = new GenSignatures(false);
            gensig.setVectorFactory(bsimDatabase.getLSHVectorFactory());

            // Set up the executable record for the current program
            String exeName = program.getName();
            String exePath = program.getExecutablePath();
            gensig.openProgram(program, exeName, exePath, null, null, null);

            DescriptionManager descManager = gensig.getDescriptionManager();
            gensig.scanFunction(func);

            if (descManager.numFunctions() == 0) {
                return "Error: Failed to generate signature for function";
            }

            // Create and execute query
            QueryNearest query = new QueryNearest();
            query.manage = descManager;
            query.max = Integer.MAX_VALUE; // Get all potential matches
            query.thresh = similarityThreshold;
            query.signifthresh = confidenceThreshold;

            // Execute query
            ResponseNearest response = query.execute(bsimDatabase);

            if (response == null) {
                return "Error: Query returned no response";
            }

            // Debug info
            Msg.info(this, String.format("Query completed for %s: threshold=%.2f, results=%d",
                func.getName(), similarityThreshold,
                response.result != null ? response.result.size() : 0));

            // Filter results by max similarity and max confidence, and limit to maxMatches
            filterBSimResults(response, maxSimilarity, maxConfidence, maxMatches);

            // Format results with pagination
            return formatBSimResults(response, func.getName(), offset, limit);

        } catch (Exception e) {
            return "Error querying BSim database: " + e.getMessage();
        }
    }

    /**
     * Query all functions in the current program against the BSim database
     *
     * @param maxMatchesPerFunction Maximum number of matches per function
     * @param similarityThreshold Minimum similarity score (inclusive, 0.0-1.0)
     * @param confidenceThreshold Minimum confidence score (inclusive, 0.0-1.0)
     * @param maxSimilarity Maximum similarity score (exclusive, 0.0-1.0, default: unbounded/infinity)
     * @param maxConfidence Maximum confidence score (exclusive, 0.0-1.0, default: unbounded/infinity)
     * @param offset Pagination offset
     * @param limit Maximum number of results to return
     */
    private String queryAllBSimFunctions(int maxMatchesPerFunction,
                                        double similarityThreshold, double confidenceThreshold,
                                        double maxSimilarity, double maxConfidence,
                                        int offset, int limit) {
        if (bsimDatabase == null) {
            return "Error: Not connected to a BSim database. Use bsim_select_database first.";
        }

        Program program = functionNavigator.getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            StringBuilder results = new StringBuilder();
            FunctionManager funcManager = program.getFunctionManager();
            int totalFunctions = funcManager.getFunctionCount();
            int queriedFunctions = 0;

            results.append("Querying ").append(totalFunctions).append(" functions against BSim database...\n\n");

            // Generate signatures for all functions
            GenSignatures gensig = new GenSignatures(false);
            gensig.setVectorFactory(bsimDatabase.getLSHVectorFactory());

            // Set up the executable record for the current program
            String exeName = program.getName();
            String exePath = program.getExecutablePath();
            gensig.openProgram(program, exeName, exePath, null, null, null);

            DescriptionManager descManager = gensig.getDescriptionManager();

            // Use built-in scanFunctions to scan all at once
            try {
                gensig.scanFunctions(funcManager.getFunctions(true), 30, new ConsoleTaskMonitor());
                queriedFunctions = descManager.numFunctions();
            } catch (Exception e) {
                return "Error: Failed to generate signatures: " + e.getMessage();
            }

            if (queriedFunctions == 0) {
                return "Error: No function signatures were generated";
            }

            // Create query
            QueryNearest query = new QueryNearest();
            query.manage = descManager;
            query.max = Integer.MAX_VALUE; // Get all potential matches
            query.thresh = similarityThreshold;
            query.signifthresh = confidenceThreshold;

            // Execute query
            ResponseNearest response = query.execute(bsimDatabase);

            if (response == null) {
                return "Error: Query returned no response";
            }

            // Filter results by max similarity and max confidence, and limit to maxMatchesPerFunction
            filterBSimResults(response, maxSimilarity, maxConfidence, maxMatchesPerFunction);

            results.append("Successfully queried ").append(queriedFunctions).append(" functions\n");

            // Format detailed results with pagination
            results.append(formatBSimResults(response, null, offset, limit));

            return results.toString();

        } catch (Exception e) {
            return "Error querying all functions: " + e.getMessage();
        }
    }

    /**
     * Get the disassembly of a BSim match from a program in the Ghidra project.
     */
    private String getBSimMatchDisassembly(String executablePath, String functionName, String functionAddress) {
        return getBSimMatchFunction(executablePath, functionName, functionAddress, true, false);
    }

    /**
     * Get the decompilation of a BSim match from a program in the Ghidra project.
     */
    private String getBSimMatchDecompile(String executablePath, String functionName, String functionAddress) {
        return getBSimMatchFunction(executablePath, functionName, functionAddress, false, true);
    }

    /**
     * Get function details for a BSim match from a program in the Ghidra project.
     * Falls back gracefully if the program is not found in the project.
     */
    private String getBSimMatchFunction(String executablePath, String functionName, String functionAddress,
                                        boolean includeDisassembly, boolean includeDecompile) {
        // Input validation
        if (executablePath == null || executablePath.isEmpty()) {
            return "Error: Executable path is required";
        }
        if (functionName == null || functionName.isEmpty()) {
            return "Error: Function name is required";
        }
        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }

        StringBuilder result = new StringBuilder();
        result.append("Match Details\n");
        result.append("=============\n");
        result.append(String.format("Executable: %s\n", executablePath));
        result.append(String.format("Function: %s\n", functionName));
        result.append(String.format("Address: %s\n\n", functionAddress));

        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            result.append("ERROR: ProgramManager service not available\n");
            return result.toString();
        }

        String fileName = new java.io.File(executablePath).getName();
        Program matchedProgram = null;
        boolean needsRelease = false;

        // Strategy 1: Check all open programs
        Program[] openPrograms = pm.getAllOpenPrograms();
        for (Program program : openPrograms) {
            if (executablePath.equals(program.getExecutablePath()) || fileName.equals(program.getName())) {
                matchedProgram = program;
                needsRelease = false;
                break;
            }
        }

        // Strategy 2: Try to find in project but not currently open
        if (matchedProgram == null) {
            ghidra.framework.model.Project project = tool.getProject();
            if (project != null) {
                ghidra.framework.model.DomainFile domainFile = findDomainFileRecursive(
                    project.getProjectData().getRootFolder(), fileName);

                if (domainFile != null) {
                    try {
                        ghidra.framework.model.DomainObject domainObject =
                            domainFile.getDomainObject(this, false, false, new ConsoleTaskMonitor());
                        if (domainObject instanceof Program) {
                            matchedProgram = (Program) domainObject;
                            needsRelease = true;
                        }
                    } catch (Exception e) {
                        Msg.error(this, "Failed to open program from project: " + fileName, e);
                    }
                }
            }
        }

        if (matchedProgram == null) {
            result.append("ERROR: Program not found in Ghidra project\n");
            result.append("The matched executable is not in the current project.\n");
            result.append("\nTo view match details, please import the program into Ghidra:\n");
            result.append("  ").append(executablePath).append("\n");
            return result.toString();
        }

        try {
            // Find the function
            Address addr = matchedProgram.getAddressFactory().getAddress(functionAddress);
            Function func = matchedProgram.getFunctionManager().getFunctionAt(addr);

            if (func == null) {
                func = matchedProgram.getFunctionManager().getFunctionContaining(addr);
            }

            if (func == null) {
                result.append("ERROR: Function not found at address ").append(functionAddress).append("\n");
                return result.toString();
            }

            // Get function prototype
            result.append("Function Prototype:\n");
            result.append("-------------------\n");
            result.append(func.getSignature()).append("\n\n");

            // Get decompilation if requested
            if (includeDecompile) {
                result.append("Decompilation:\n");
                result.append("--------------\n");
                String decompCode = decompileFunctionInProgram(func, matchedProgram);
                if (decompCode != null && !decompCode.isEmpty()) {
                    result.append(decompCode).append("\n");
                } else {
                    result.append("(Decompilation not available)\n");
                }
            }

            // Get assembly if requested
            if (includeDisassembly) {
                if (includeDecompile) {
                    result.append("\n");
                }
                result.append("Assembly:\n");
                result.append("---------\n");
                String asmCode = disassemblyService.disassembleFunctionInProgram(func, matchedProgram, false);
                if (asmCode != null && !asmCode.isEmpty()) {
                    result.append(asmCode);
                } else {
                    result.append("(Assembly not available)\n");
                }
            }

            return result.toString();

        } catch (Exception e) {
            result.append("ERROR: Exception while processing program: ").append(e.getMessage()).append("\n");
            Msg.error(this, "Error getting BSim match function", e);
            return result.toString();
        } finally {
            // Release the program if we opened it from the project
            if (needsRelease && matchedProgram != null) {
                matchedProgram.release(this);
            }
        }
    }

    /**
     * Recursively search for a domain file by name in a folder and its subfolders
     */
    private ghidra.framework.model.DomainFile findDomainFileRecursive(
            ghidra.framework.model.DomainFolder folder, String fileName) {

        // Check files in current folder
        for (ghidra.framework.model.DomainFile file : folder.getFiles()) {
            if (fileName.equals(file.getName())) {
                return file;
            }
        }

        // Recursively check subfolders
        for (ghidra.framework.model.DomainFolder subfolder : folder.getFolders()) {
            ghidra.framework.model.DomainFile result = findDomainFileRecursive(subfolder, fileName);
            if (result != null) {
                return result;
            }
        }

        return null;
    }

    /**
     * Decompile a function within a specific program
     */
    private String decompileFunctionInProgram(Function func, Program program) {
        try {
            DecompInterface decomp = new DecompInterface();
            DecompileOptions options = new DecompileOptions();
            decomp.setOptions(options);
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, this.decompileTimeout, new ConsoleTaskMonitor());
            decomp.flushCache();

            if (result != null && result.decompileCompleted()) {
                return result.getDecompiledFunction().getC();
            }
        } catch (Exception e) {
            Msg.error(this, "Error decompiling function in external program", e);
        }
        return null;
    }


    /**
     * Filter BSim results by maximum similarity and confidence thresholds, and limit matches.
     */
    private void filterBSimResults(ResponseNearest response, double maxSimilarity, double maxConfidence, int maxMatches) {
        if (response == null || response.result == null) {
            return;
        }

        Iterator<SimilarityResult> iter = response.result.iterator();
        while (iter.hasNext()) {
            SimilarityResult simResult = iter.next();
            Iterator<SimilarityNote> noteIter = simResult.iterator();

            int validMatchCount = 0;

            while (noteIter.hasNext()) {
                SimilarityNote note = noteIter.next();

                // Remove matches that meet or exceed max similarity or max confidence (exclusive)
                if (note.getSimilarity() >= maxSimilarity || note.getSignificance() >= maxConfidence) {
                    noteIter.remove();
                } else {
                    // This is a valid match
                    validMatchCount++;

                    // Early stopping: if we've reached maxMatches valid matches, remove all remaining
                    if (validMatchCount > maxMatches) {
                        noteIter.remove();
                    }
                }
            }
        }
    }

    /**
     * Format BSim query results into a readable string with pagination
     */
    private String formatBSimResults(ResponseNearest response, String queryFunctionName, int offset, int limit) {
        StringBuilder result = new StringBuilder();

        if (queryFunctionName != null) {
            result.append("Matches for function: ").append(queryFunctionName).append("\n\n");
        }

        Iterator<SimilarityResult> iter = response.result.iterator();
        int totalMatchCount = 0;
        int displayedMatchCount = 0;

        while (iter.hasNext()) {
            SimilarityResult simResult = iter.next();
            FunctionDescription base = simResult.getBase();

            if (simResult.size() == 0) {
                if (queryFunctionName == null) {
                    continue; // Skip functions with no matches when querying all
                }
                result.append("No matches found (all matches filtered out or none available)\n");
                return result.toString(); // Early return for single function with no matches
            }

            // For single function query, paginate the matches
            // For all functions query, paginate the functions
            if (queryFunctionName != null) {
                // Single function: paginate through similarity matches
                int totalMatches = simResult.size();

                Iterator<SimilarityNote> noteIter = simResult.iterator();
                int matchIndex = 0;

                while (noteIter.hasNext()) {
                    SimilarityNote note = noteIter.next();

                    // Skip matches before offset
                    if (matchIndex < offset) {
                        matchIndex++;
                        continue;
                    }

                    // Stop if we've reached the limit
                    if (displayedMatchCount >= limit) {
                        break;
                    }

                    FunctionDescription match = note.getFunctionDescription();
                    ExecutableRecord exe = match.getExecutableRecord();

                    result.append(String.format("Match %d:\n", matchIndex + 1));

                    if (exe != null) {
                        result.append(String.format("  Executable: %s\n", exe.getNameExec()));
                    }

                    result.append(String.format("  Function: %s\n", match.getFunctionName()));
                    result.append(String.format("  Address: %s\n", functionNavigator.getAddressFromLong(match.getAddress())));
                    result.append(String.format("  Similarity: %.4f\n", note.getSimilarity()));
                    result.append(String.format("  Confidence: %.4f\n", note.getSignificance()));

                    if (exe != null) {
                        String arch = exe.getArchitecture();
                        String compiler = exe.getNameCompiler();
                        if (arch != null && !arch.isEmpty()) {
                            result.append(String.format("  Architecture: %s\n", arch));
                        }
                        if (compiler != null && !compiler.isEmpty()) {
                            result.append(String.format("  Compiler: %s\n", compiler));
                        }
                    }

                    result.append("\n");
                    matchIndex++;
                    displayedMatchCount++;
                }

                // Add pagination info for single function
                int remaining = totalMatches - offset - displayedMatchCount;
                if (remaining < 0) remaining = 0;

                result.append(String.format("Showing matches %d-%d of %d",
                    offset + 1, offset + displayedMatchCount, totalMatches));
                if (remaining > 0) {
                    result.append(String.format(" (%d more available)\n", remaining));
                } else {
                    result.append("\n");
                }
            } else {
                // All functions query: paginate by function (skip if before offset)
                if (totalMatchCount < offset) {
                    totalMatchCount++;
                    continue;
                }

                result.append("Function: ").append(base.getFunctionName())
                        .append(" at ").append(functionNavigator.getAddressFromLong(base.getAddress())).append("\n");

                // Stop if we've reached the limit
                if (displayedMatchCount >= limit) {
                    break;
                }

                result.append("Found ").append(simResult.size()).append(" match(es):\n");

                Iterator<SimilarityNote> noteIter = simResult.iterator();
                int matchNum = 1;
                while (noteIter.hasNext()) {
                    SimilarityNote note = noteIter.next();
                    FunctionDescription match = note.getFunctionDescription();
                    ExecutableRecord exe = match.getExecutableRecord();

                    result.append(String.format("Match %d:\n", matchNum));

                    result.append(String.format("  Executable: %s\n", exe.getNameExec()));
                    result.append(String.format("  Function: %s\n", match.getFunctionName()));
                    result.append(String.format("  Address: %s\n", functionNavigator.getAddressFromLong(match.getAddress())));
                    result.append(String.format("  Similarity: %.4f\n", note.getSimilarity()));
                    result.append(String.format("  Confidence: %.4f\n", note.getSignificance()));

                    result.append("\n");
                    matchNum++;
                }
                result.append("\n");
                totalMatchCount++;
                displayedMatchCount++;
            }
        }

        // Add pagination info for all functions query
        if (queryFunctionName == null) {
            // Count remaining functions
            int remaining = 0;
            while (iter.hasNext()) {
                SimilarityResult simResult = iter.next();
                if (simResult.size() > 0) {
                    remaining++;
                }
            }

            if (displayedMatchCount == 0) {
                result.append("No matches found for any functions\n");
            } else {
                result.append(String.format("Showing functions %d-%d of %d+ results",
                    offset + 1, offset + displayedMatchCount, offset + displayedMatchCount + remaining));
                if (remaining > 0) {
                    result.append(String.format(" (%d more available)\n", remaining));
                } else {
                    result.append("\n");
                }
            }
        }

        return result.toString();
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * Parse a comma-separated list of function names
     */
    private List<String> parseFunctionNamesList(String functionNamesStr) {
        List<String> functionNames = new ArrayList<>();
        if (functionNamesStr != null && !functionNamesStr.isEmpty()) {
            String[] parts = functionNamesStr.split(",");
            for (String part : parts) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    functionNames.add(trimmed);
                }
            }
        }
        return functionNames;
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
