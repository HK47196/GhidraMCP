# Service Tests

This directory contains tests for GhidraMCP service classes.

## Testing Challenges

The service classes (`StructService`, `FunctionSignatureService`, `ProgramAnalyzer`, etc.)
depend heavily on Ghidra's internal APIs and require a loaded program to function properly.

## Testing Strategy

Due to the tight coupling with Ghidra:

1. **Unit Testing**: Tests use Mockito to mock Ghidra dependencies where possible
2. **Integration Testing**: Full integration tests require a running Ghidra instance with a loaded program
3. **Utility Testing**: Pure utility functions (like those in `PluginUtils`) can be tested without mocks

## Running Tests

### Unit Tests
```bash
mvn test
```

### Python Tests
```bash
pytest
```

## Test Coverage

Current test coverage includes:
- ✅ `PluginUtils` - Comprehensive unit tests for all utility methods
- ✅ `BulkOperation` - Model class tests
- ⚠️ Service classes - Require Ghidra runtime for full integration testing

## Future Improvements

To improve service test coverage, consider:
1. Creating a test harness with a minimal Ghidra program
2. Using test fixtures with pre-analyzed binaries
3. Implementing more comprehensive mocking strategies
4. Adding end-to-end HTTP API tests
