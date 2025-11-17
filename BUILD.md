Run `./build.sh` - this will automatically:
1. Download and extract required Ghidra libraries (if not already present)
2. Set up Python environment
3. Build Java components with Maven
4. Run all tests

Run full integration tests with `./test_e2e.sh`

## Ghidra Version

The default Ghidra version is 11.4.2 (matching the version used in E2E tests). To use a different version, set the environment variables:

```bash
GHIDRA_VERSION=11.4.2 GHIDRA_DATE=20250826 ./build.sh
```
