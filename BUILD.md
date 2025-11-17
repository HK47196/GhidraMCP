Run `./build.sh` - this will automatically:
1. Download and extract required Ghidra libraries (if not already present)
2. Set up Python environment
3. Build Java components with Maven
4. Run all tests

Run full integration tests with `./test_e2e.sh`

## Ghidra Version

The default Ghidra version is configured in `download_ghidra.sh`. To use a different version, set the `GHIDRA_VERSION` environment variable:

```bash
GHIDRA_VERSION=11.2_PUBLIC_20250106 ./build.sh
```
