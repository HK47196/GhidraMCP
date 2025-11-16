package com.ghidramcp.util;

import com.sun.net.httpserver.HttpExchange;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility methods for HTTP request handling, parameter parsing, and data formatting
 */
public class PluginUtils {

    /**
     * Parse query parameters from HTTP exchange
     * @param exchange HTTP exchange containing the request
     * @return Map of parameter names to values
     */
    public static Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(PluginUtils.class, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse POST parameters from HTTP exchange
     * @param exchange HTTP exchange containing the request
     * @return Map of parameter names to values
     * @throws IOException if reading request body fails
     */
    public static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(PluginUtils.class, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Paginate a list of items
     * @param items List of items to paginate
     * @param offset Starting offset
     * @param limit Maximum number of items
     * @return Newline-separated string of paginated items
     */
    public static String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), start + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse integer with default value
     * @param val String value to parse
     * @param defaultValue Default value if parsing fails
     * @return Parsed integer or default value
     */
    public static int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Parse double with default value
     * @param val String value to parse
     * @param defaultValue Default value if parsing fails
     * @return Parsed double or default value
     */
    public static double parseDoubleOrDefault(String val, String defaultValue) {
        if (val == null) val = defaultValue;
        try {
            return Double.parseDouble(val);
        }
        catch (NumberFormatException e) {
            try {
                return Double.parseDouble(defaultValue);
            }
            catch (NumberFormatException e2) {
                return 0.0;
            }
        }
    }

    /**
     * Parse boolean with default value
     * @param val String value to parse (accepts "true", "false", "1", "0")
     * @param defaultValue Default value if parsing fails or value is null
     * @return Parsed boolean or default value
     */
    public static boolean parseBoolOrDefault(String val, boolean defaultValue) {
        if (val == null) return defaultValue;
        String normalized = val.toLowerCase().trim();
        if (normalized.equals("true") || normalized.equals("1")) {
            return true;
        } else if (normalized.equals("false") || normalized.equals("0")) {
            return false;
        }
        return defaultValue;
    }

    /**
     * Escape non-ASCII characters
     * @param input String to escape
     * @return Escaped string
     */
    public static String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Escape string for JSON output
     * @param input String to escape
     * @return JSON-escaped string
     */
    public static String escapeJson(String input) {
        if (input == null) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 32 || c > 126) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /**
     * Get parameter value by checking both camelCase and snake_case variants.
     * This supports flexible parameter naming for API compatibility.
     *
     * @param params Map of parameters
     * @param camelCaseName Parameter name in camelCase (e.g., "newName")
     * @param snakeCaseName Parameter name in snake_case (e.g., "new_name")
     * @return The parameter value, or null if not found
     */
    public static String getParamFlexible(Map<String, String> params, String camelCaseName, String snakeCaseName) {
        String value = params.get(camelCaseName);
        if (value != null) {
            return value;
        }
        return params.get(snakeCaseName);
    }

    /**
     * Parse include_instruction parameter which can be either boolean or int.
     * This supports flexible parameter values for backward compatibility.
     *
     * @param val String value to parse (e.g., "true", "false", "0", "3")
     * @return -1 if false/null, 0 if true, or N if numeric >= 0
     */
    public static int parseIncludeInstructionParam(String val) {
        if (val == null) return -1;

        String normalized = val.toLowerCase().trim();

        // Handle boolean values
        if (normalized.equals("true")) {
            return 0; // true = include instruction only, no context
        } else if (normalized.equals("false")) {
            return -1; // false = don't include instruction
        }

        // Try to parse as integer
        try {
            int intVal = Integer.parseInt(normalized);
            // Return the integer value if >= 0, otherwise return -1
            return (intVal >= 0) ? intVal : -1;
        } catch (NumberFormatException e) {
            return -1; // Invalid value, default to false
        }
    }
}
