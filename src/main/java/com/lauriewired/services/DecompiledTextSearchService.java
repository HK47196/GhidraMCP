package com.lauriewired.services;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Service for searching through decompiled function code
 */
public class DecompiledTextSearchService {

    private final FunctionNavigator navigator;
    private final int decompileTimeout;

    public DecompiledTextSearchService(FunctionNavigator navigator, int decompileTimeout) {
        this.navigator = navigator;
        this.decompileTimeout = decompileTimeout;
    }

    /**
     * Search for a pattern in decompiled functions
     * @param patternStr Search pattern (regex or literal string)
     * @param isRegex Whether pattern is regex (true) or literal string (false)
     * @param caseSensitive Whether search is case-sensitive
     * @param multiline Whether pattern can match across multiple lines
     * @param functionNames Optional list of specific function names to search (null for all)
     * @param maxResults Maximum number of results to return (0 for unlimited)
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return JSON string with search results
     */
    public String searchDecompiledText(String patternStr, boolean isRegex, boolean caseSensitive,
                                      boolean multiline, List<String> functionNames,
                                      int maxResults, int offset, int limit) {
        Program program = navigator.getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (patternStr == null || patternStr.isEmpty()) {
            return "{\"error\": \"Pattern is required\"}";
        }

        // Compile the pattern
        Pattern pattern;
        try {
            pattern = compilePattern(patternStr, isRegex, caseSensitive, multiline);
        } catch (PatternSyntaxException e) {
            return String.format("{\"error\": \"Invalid regex pattern: %s\"}", escapeJson(e.getMessage()));
        }

        // Get functions to search
        List<Function> functionsToSearch = getFunctionsToSearch(program, functionNames);
        if (functionsToSearch.isEmpty()) {
            return "{\"matches\": [], \"count\": 0, \"message\": \"No functions to search\"}";
        }

        // Search through functions
        List<SearchMatch> allMatches = new ArrayList<>();
        DecompInterface decomp = null;

        try {
            decomp = setupDecompiler(program);

            for (Function func : functionsToSearch) {
                // Stop if we've reached maxResults (if specified)
                if (maxResults > 0 && allMatches.size() >= maxResults) {
                    break;
                }

                // Skip thunk and external functions
                if (func.isThunk() || func.isExternal()) {
                    continue;
                }

                // Decompile the function
                DecompileResults results = decomp.decompileFunction(func, decompileTimeout, new ConsoleTaskMonitor());
                decomp.flushCache();

                if (results == null || !results.decompileCompleted()) {
                    continue;
                }

                String decompiled = results.getDecompiledFunction().getC();
                if (decompiled == null || decompiled.isEmpty()) {
                    continue;
                }

                // Search for pattern in decompiled code
                List<SearchMatch> functionMatches = searchInText(func, decompiled, pattern, multiline);
                allMatches.addAll(functionMatches);
            }

        } catch (Exception e) {
            Msg.error(this, "Error searching decompiled text", e);
            return String.format("{\"error\": \"Search failed: %s\"}", escapeJson(e.getMessage()));
        } finally {
            if (decomp != null) {
                decomp.dispose();
            }
        }

        // Apply pagination
        List<SearchMatch> paginatedMatches = applyPagination(allMatches, offset, limit);

        // Format results as JSON
        return formatResultsAsJson(paginatedMatches, allMatches.size(), offset, limit);
    }

    /**
     * Compile a pattern with the specified flags
     */
    private Pattern compilePattern(String patternStr, boolean isRegex, boolean caseSensitive, boolean multiline) {
        String actualPattern = isRegex ? patternStr : Pattern.quote(patternStr);

        int flags = 0;
        if (!caseSensitive) {
            flags |= Pattern.CASE_INSENSITIVE;
        }
        if (multiline) {
            flags |= Pattern.DOTALL;
        }

        return Pattern.compile(actualPattern, flags);
    }

    /**
     * Get functions to search based on filter
     */
    private List<Function> getFunctionsToSearch(Program program, List<String> functionNames) {
        List<Function> functions = new ArrayList<>();
        FunctionManager funcManager = program.getFunctionManager();

        if (functionNames == null || functionNames.isEmpty()) {
            // Search all functions
            FunctionIterator iter = funcManager.getFunctions(true);
            while (iter.hasNext()) {
                functions.add(iter.next());
            }
        } else {
            // Search specific functions
            for (String name : functionNames) {
                FunctionIterator iter = funcManager.getFunctions(true);
                while (iter.hasNext()) {
                    Function func = iter.next();
                    if (func.getName().equals(name)) {
                        functions.add(func);
                        break;
                    }
                }
            }
        }

        return functions;
    }

    /**
     * Set up decompiler with appropriate options
     */
    private DecompInterface setupDecompiler(Program program) {
        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.setSimplificationStyle("decompile");
        decomp.openProgram(program);
        return decomp;
    }

    /**
     * Search for pattern in decompiled text
     */
    private List<SearchMatch> searchInText(Function func, String text, Pattern pattern, boolean multiline) {
        List<SearchMatch> matches = new ArrayList<>();

        if (multiline) {
            // Multi-line search: search entire text at once
            Matcher matcher = pattern.matcher(text);
            while (matcher.find()) {
                int matchStart = matcher.start();
                int matchEnd = matcher.end();
                int lineNumber = getLineNumber(text, matchStart);
                String context = extractContext(text, matchStart, matchEnd);
                String matchedText = matcher.group();

                matches.add(new SearchMatch(
                    func.getName(),
                    func.getEntryPoint().toString(),
                    lineNumber,
                    matchedText,
                    context,
                    true
                ));
            }
        } else {
            // Single-line search: search line by line
            String[] lines = text.split("\n");
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                Matcher matcher = pattern.matcher(line);

                while (matcher.find()) {
                    String matchedText = matcher.group();
                    String context = highlightMatch(line, matcher.start(), matcher.end());

                    matches.add(new SearchMatch(
                        func.getName(),
                        func.getEntryPoint().toString(),
                        i + 1, // Line numbers are 1-based
                        matchedText,
                        context,
                        false
                    ));
                }
            }
        }

        return matches;
    }

    /**
     * Get line number for a character position in text
     */
    private int getLineNumber(String text, int position) {
        int lineNumber = 1;
        for (int i = 0; i < position && i < text.length(); i++) {
            if (text.charAt(i) == '\n') {
                lineNumber++;
            }
        }
        return lineNumber;
    }

    /**
     * Extract context around a match (up to 200 characters before and after)
     */
    private String extractContext(String text, int matchStart, int matchEnd) {
        int contextStart = Math.max(0, matchStart - 100);
        int contextEnd = Math.min(text.length(), matchEnd + 100);

        // Adjust to line boundaries if possible
        while (contextStart > 0 && text.charAt(contextStart) != '\n') {
            contextStart--;
        }
        while (contextEnd < text.length() && text.charAt(contextEnd) != '\n') {
            contextEnd++;
        }

        String context = text.substring(contextStart, contextEnd).trim();

        // Add ellipsis if truncated
        if (contextStart > 0) context = "..." + context;
        if (contextEnd < text.length()) context = context + "...";

        return context;
    }

    /**
     * Highlight match in line with markers
     */
    private String highlightMatch(String line, int start, int end) {
        StringBuilder result = new StringBuilder();
        result.append(line.substring(0, start));
        result.append("[[");
        result.append(line.substring(start, end));
        result.append("]]");
        if (end < line.length()) {
            result.append(line.substring(end));
        }
        return result.toString();
    }

    /**
     * Apply pagination to results
     */
    private List<SearchMatch> applyPagination(List<SearchMatch> matches, int offset, int limit) {
        if (offset >= matches.size()) {
            return new ArrayList<>();
        }

        int end = Math.min(matches.size(), offset + limit);
        return new ArrayList<>(matches.subList(offset, end));
    }

    /**
     * Format results as JSON
     */
    private String formatResultsAsJson(List<SearchMatch> matches, int totalCount, int offset, int limit) {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"matches\": [");

        for (int i = 0; i < matches.size(); i++) {
            if (i > 0) json.append(", ");
            json.append(matches.get(i).toJson());
        }

        json.append("], ");
        json.append("\"count\": ").append(matches.size()).append(", ");
        json.append("\"total_count\": ").append(totalCount).append(", ");
        json.append("\"offset\": ").append(offset).append(", ");
        json.append("\"limit\": ").append(limit);
        json.append("}");

        return json.toString();
    }

    /**
     * Escape JSON strings
     */
    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    /**
     * Inner class to represent a search match
     */
    private static class SearchMatch {
        private final String functionName;
        private final String functionAddress;
        private final int lineNumber;
        private final String matchedText;
        private final String context;
        private final boolean isMultiline;

        public SearchMatch(String functionName, String functionAddress, int lineNumber,
                          String matchedText, String context, boolean isMultiline) {
            this.functionName = functionName;
            this.functionAddress = functionAddress;
            this.lineNumber = lineNumber;
            this.matchedText = matchedText;
            this.context = context;
            this.isMultiline = isMultiline;
        }

        public String toJson() {
            return String.format(
                "{\"function_name\": \"%s\", \"function_address\": \"%s\", " +
                "\"line_number\": %d, \"matched_text\": \"%s\", " +
                "\"context\": \"%s\", \"is_multiline\": %s}",
                escapeJson(functionName),
                escapeJson(functionAddress),
                lineNumber,
                escapeJson(matchedText),
                escapeJson(context),
                isMultiline
            );
        }

        private static String escapeJson(String str) {
            if (str == null) return "";
            return str.replace("\\", "\\\\")
                      .replace("\"", "\\\"")
                      .replace("\n", "\\n")
                      .replace("\r", "\\r")
                      .replace("\t", "\\t");
        }
    }
}
