[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports
- BSim integration for function similarity matching
  - Connect to BSim databases (H2, PostgreSQL)
  - Query individual functions for similar matches
  - Batch query all functions in a program
  - View similarity scores, confidence levels, and executable metadata

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-2.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure the port in Ghidra with `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Three examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. If not set, both will default to localhost:8080.

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

The only *required* argument is the transport. If all other arguments are unspecified, they will default to the above. Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source

## Prerequisites
- Java 21 or higher
- Maven 3.6 or higher
- Internet connection (for downloading Ghidra and dependencies)

## Build Instructions

The build process automatically downloads Ghidra 11.4.2 and all required dependencies. No manual file copying needed!

### First-time build:

```bash
mvn initialize && mvn package
```

This two-step process:
1. **First command** (`mvn initialize`):
   - Downloads Ghidra 11.4.2 (~435 MB) to `.ghidra-cache/` directory
   - Extracts Ghidra
   - Installs Ghidra JARs to your local Maven repository (~/.m2/repository)

2. **Second command** (`mvn package`):
   - Compiles the plugin using the installed Ghidra JARs
   - Downloads Apache Commons and database drivers from Maven Central
   - Generates `GhidraMCP-1.0-SNAPSHOT.zip` in the `target/` directory

### Subsequent builds:

Once Ghidra JARs are in your local Maven repository, you can build normally:

```bash
mvn clean package
```

**Note:** The downloaded Ghidra is cached in `.ghidra-cache/` and the JARs remain in your local Maven repository, so you only download once.

The generated zip file includes the built Ghidra plugin and its resources:
- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest

## Changing Ghidra Version

To build against a different Ghidra version, edit the properties in `pom.xml`:

```xml
<properties>
  <ghidra.version>11.4.2</ghidra.version>
  <ghidra.release.date>20250826</ghidra.release.date>
</properties>
```

## Offline/Containerized Builds

The build works in containerized environments without a pre-installed Ghidra. On first build:
- Ghidra is downloaded to `.ghidra-cache/` (survives `mvn clean`)
- Ghidra JARs are installed to Maven's local repository

Both are reused on subsequent builds, so you only download Ghidra once per environment.

To force a fresh download:
```bash
rm -rf .ghidra-cache/
rm -rf ~/.m2/repository/ghidra/
```
