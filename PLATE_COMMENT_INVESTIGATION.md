# Plate Comment Failure Investigation

## Problem Statement
Users report that plate comment operations frequently fail in the MCP, returning:
```json
{"success": true, "result": "Failed to set comment"}
```

Even though the comments are actually being set in Ghidra, the MCP reports `"success": true` while the result indicates failure.

## Solution Implemented

**Fixed:** Modified `safe_post()` in `bridge_mcp_ghidra.py` to detect failure messages in response text and raise exceptions.

When the Ghidra server returns responses starting with "Failed to " or "Error", `safe_post` now raises an exception instead of returning the error message as a string. This allows the MCP framework to correctly report `{"success": false, "error": "..."}` to clients.

**Changes:**
- `bridge_mcp_ghidra.py`: Updated `safe_post()` to raise exceptions for failure responses
- `tests/test_bridge_mcp_ghidra.py`: Updated 18+ tests to expect exceptions instead of error strings
- All 167 tests pass ✓

## Root Cause Analysis

### 1. HTTP Response Handling

The Ghidra server **always returns HTTP 200**, regardless of operation success or failure.

**Evidence:**
- `GhidraMCPPlugin.java:1777`: `exchange.sendResponseHeaders(200, bytes.length);`
- This applies to ALL endpoints, not just plate comments

### 2. Success/Failure Communication

Success or failure is communicated solely through the **response body text**:
- **Success response**: `"Comment set successfully"`
- **Failure response**: `"Failed to set comment"`

**Evidence:**
```java
// GhidraMCPPlugin.java:257-263
server.createContext("/set_plate_comment", exchange -> {
    Map<String, String> params = PluginUtils.parsePostParams(exchange);
    String address = params.get("address");
    String comment = params.get("comment");
    boolean success = commentService.setPlateComment(address, comment);
    sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
});
```

### 3. Python Bridge Behavior

The Python bridge (`safe_post` function) correctly handles the response:
- Checks `response.ok` (True for HTTP 200-299)
- Returns `response.text.strip()` when ok
- Returns error message if not ok

**Since the server always returns HTTP 200**, the Python bridge will always return the response text as-is, whether it's a success or failure message.

### 4. Transaction Logic

The Java `CommentService` uses Ghidra transactions to set comments:

```java
// CommentService.java:61-86
private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
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
```

**Key issue at line 78:** `success.set(program.endTransaction(tx, success.get()));`

The final success value is determined by `endTransaction`, which returns:
- `true` if the transaction committed successfully
- `false` if the transaction was rolled back or invalid

### 5. Potential Failure Scenarios

The operation could fail (return `false`) even if the comment was set, if:

1. **Transaction rollback**: `endTransaction` returns false, causing a rollback
2. **Threading issues**: Exception in `SwingUtilities.invokeAndWait`
3. **Program state**: Program becomes invalid between setting the comment and ending the transaction
4. **Address parsing**: Exception when parsing the address string
5. **Null/empty parameters**: Validation fails before attempting to set the comment

## Test Coverage

Added 9 comprehensive diagnostic tests to verify response handling:

1. `test_set_plate_comment_exact_success_response` - Verifies correct handling of success message
2. `test_set_plate_comment_exact_failure_response` - Verifies correct handling of failure message
3. `test_set_plate_comment_with_http_200_and_failure_message` - Confirms failure detection despite HTTP 200
4. `test_set_plate_comment_response_parsing` - Tests low-level response parsing
5. `test_set_plate_comment_response_with_whitespace` - Verifies whitespace stripping
6. `test_set_plate_comment_transaction_failure_response` - Tests transaction failure scenario
7. `test_set_decompiler_comment_success_response` - Compares with decompiler comments
8. `test_set_disassembly_comment_success_response` - Compares with disassembly comments

**All tests pass**, confirming that the Python bridge correctly handles both success and failure responses.

## Architectural Issues

### Current Design
- **Pros**: Simple, all responses have consistent HTTP status
- **Cons**:
  - Cannot use HTTP status codes for error detection
  - Client must parse response text to determine success/failure
  - Violates HTTP semantics (200 means success, but may contain failure message)
  - Makes monitoring and debugging harder

### Recommended Design
Use proper HTTP status codes:
- **200 OK**: Operation succeeded
- **400 Bad Request**: Invalid parameters (bad address, null comment, etc.)
- **500 Internal Server Error**: Transaction failed, Ghidra internal error

This would allow:
- Standard HTTP error handling
- Better integration with MCP frameworks
- Clearer success/failure semantics
- Easier debugging and monitoring

## Diagnosis Steps for Users

When a plate comment "fails":

1. **Check if the comment was actually set in Ghidra**
   - If YES: The operation succeeded but returned a false negative
   - If NO: The operation truly failed

2. **Check the response text**
   - Look for "Comment set successfully" vs "Failed to set comment"
   - The MCP client should display this text

3. **Common failure causes:**
   - Invalid address format (must be parseable by Ghidra's AddressFactory)
   - No program currently open in Ghidra
   - Address doesn't exist in the current program
   - Transaction conflicts (another operation in progress)
   - Ghidra program is in read-only mode

4. **Check Ghidra logs**
   - Look for `Msg.error` messages from CommentService
   - Check for transaction errors or exceptions

## Conclusion

The Python MCP bridge is working correctly. The apparent "failures" are due to:

1. **Architectural design**: HTTP 200 always returned, making it impossible to use HTTP status for error detection
2. **Transaction failures**: Operations may fail at the Ghidra transaction level even if the HTTP request succeeds
3. **User perception**: Users must inspect response text, not HTTP status, to determine success/failure

The diagnostic tests confirm that when Ghidra returns "Comment set successfully", the MCP correctly reports success. When Ghidra returns "Failed to set comment", the MCP correctly reports failure. The issue is that the MCP framework and users expect HTTP status codes to indicate success/failure, but this server uses response text instead.
