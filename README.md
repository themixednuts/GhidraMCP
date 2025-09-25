<div align="center">
  <a href="https://github.com/themixednuts/GhidraMCP/releases"><img src="https://img.shields.io/github/v/release/themixednuts/GhidraMCP?label=latest%20release&style=flat-square" alt="GitHub release (latest by date)"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/themixednuts/GhidraMCP/build.yml?style=flat-square" alt="Build Status"></a>
  <a href="#"><img src="https://img.shields.io/badge/Ghidra-11.4.2-blue?style=flat-square" alt="Tested Ghidra Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/stargazers"><img src="https://img.shields.io/github/stars/themixednuts/GhidraMCP?style=flat-square" alt="GitHub stars"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/network/members"><img src="https://img.shields.io/github/forks/themixednuts/GhidraMCP?style=flat-square" alt="GitHub forks"></a>
</div>

<!-- Optional: Add a project logo here -->
<!-- <p align="center">
  <img src="PATH_TO_YOUR_LOGO.png" alt="GhidraMCP Logo" width="200"/>
</p> -->

<div align="center">
  <a href="https://cursor.com/install-mcp?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvc3NlIn0%3D"><img src="https://cursor.com/deeplink/mcp-install-dark.svg" alt="Add ghidra MCP server to Cursor" height="32" /></a>
</div>
<h1 align="center">GhidraMCP</h1>

> Ghidra integration for the Model Context Protocol (MCP)

A Ghidra extension that runs an embedded MCP server to expose Ghidra program data and functionalities via tools.

---

## ✨ Features

This extension exposes Ghidra functionalities to MCP clients through semantic tools designed for reverse engineering workflows. Each tool provides comprehensive operations tailored to specific analysis tasks.

### [`Function Analysis`](src/main/java/com/themixednuts/tools/AnalyzeFunctionsTool.java)

Comprehensive function analysis including creation, inspection, decompilation, and prototype management. Supports multiple identification methods (name, address, symbol ID, regex) and provides detailed function information including parameters, return types, and call sites.

### [`Code Decompilation`](src/main/java/com/themixednuts/tools/DecompileCodeTool.java)

Advanced decompilation and P-code analysis for functions and code regions. Decompiles functions to C-like pseudocode, analyzes P-code operations, and supports configurable timeout and analysis depth for complex control structures.

### [`Data Type Management`](src/main/java/com/themixednuts/tools/ManageDataTypesTool.java)

Comprehensive management of all data types in Ghidra programs. Create, read, update, delete, and list structures, enums, unions, typedefs, pointers, function definitions, and categories with automatic type resolution and validation.

### [`Memory Operations`](src/main/java/com/themixednuts/tools/ManageMemoryTool.java)

Comprehensive memory operations for reverse engineering. Read and write bytes, search for patterns, analyze memory layout, and manage memory segments. Supports multiple search formats including hex, string, binary, and regex patterns.

### [`Symbol Management`](src/main/java/com/themixednuts/tools/ManageSymbolsTool.java)

Comprehensive symbol management including creating, renaming, deleting, searching, and analyzing symbols. Supports multiple symbol identification methods, namespace organization, and symbol scoping with validation according to Ghidra rules.

---

## 🚀 Installation

1.  Download the latest release `zip` file from the [Releases](https://github.com/themixednuts/GhidraMCP/releases) page.
2.  In Ghidra, go to `File` -> `Install Extensions...`.
3.  Click the `+` button (Add extension) in the top right corner.
4.  Navigate to the downloaded `zip` file and select it.
5.  Ensure the `GhidraMCP` extension is checked in the list and click `OK`.
6.  Restart Ghidra.

---

## ▶️ Usage

1.  Ensure Ghidra is running with the GhidraMCP extension active.
2.  Ensure your MCP Client is configured to connect to the GhidraMCP server (see 'Configuring an MCP Client' below).

> [!WARNING] > **Script Error Dialogs:** Some tools that execute Ghidra scripts may trigger GUI error dialogs via `Msg.showError`. These dialogs **must** be manually closed, or the server will hang and become unresponsive.

> [!TIP] > **Missing fileName Parameter:** When tools request a `fileName` parameter, use the `list_open_files` tool to see available programs. Most tools provide this context automatically on failed calls.

## 🛠️ Building from Source

1.  Clone the repository:
    ```bash
    git clone https://github.com/themixednuts/GhidraMCP.git
    ```
2.  Navigate to the project directory:
    ```bash
    cd GhidraMCP
    ```
3.  Ensure you have [Apache Maven](https://maven.apache.org/install.html) and a JDK (compatible version, e.g., JDK 21 or later recommended for modern Ghidra development) installed.
4.  Copy the following required JAR files from your Ghidra installation directory into the `lib/` directory of this project. Create the `lib/` directory if it doesn't exist:
    - `Ghidra/Features/Base/lib/Base.jar`
    - `Ghidra/Features/Decompiler/lib/Decompiler.jar`
    - `Ghidra/Framework/Docking/lib/Docking.jar`
    - `Ghidra/Framework/Generic/lib/Generic.jar`
    - `Ghidra/Framework/Project/lib/Project.jar`
    - `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
    - `Ghidra/Framework/Utility/lib/Utility.jar`
    - `Ghidra/Framework/Gui/lib/Gui.jar`
      > [!NOTE]
      > Paths are relative to your Ghidra installation folder. Exact paths might vary slightly based on Ghidra version and OS.
5.  Build the project using Maven:
    ```bash
    mvn clean package assembly:single
    ```
6.  The installable `zip` file will be located in the `target/` directory (e.g., `target/GhidraMCP-*-SNAPSHOT-ghidra.zip`). Follow the Installation steps above using this file.

---

## 🔌 Configuring an MCP Client

To allow an MCP client (like Claude Desktop or a custom client) to interact with Ghidra via this extension, you need to configure the client to connect to the server endpoint provided by GhidraMCP.

The GhidraMCP server runs within Ghidra itself when the extension is active. It typically exposes an HTTP SSE (Server-Sent Events) endpoint.

Add the following configuration to your MCP client's settings (e.g., `claude_desktop_config.json` for Claude Desktop). Adjust the key (`"ghidra"` in this example) as needed:

```json
{
	"mcpServers": {
		"ghidra": {
			"url": "http://127.0.0.1:8080/sse"
		}
		// Add other MCP server configurations here if needed
	}
}
```

---

> [!IMPORTANT]
> **Port:** The default port is `8080`. This is configurable within Ghidra under the Tool Options for the GhidraMCP extension. If you change the port in Ghidra, you **must** update the `url` in your client configuration accordingly.

> [!IMPORTANT]
> **Server Status:** Ghidra must be running with the GhidraMCP extension enabled for the client to connect successfully.

> [!NOTE]
> **Timeout Issues:** If you encounter timeout problems, refer to the [Ghidra timeout configuration guide](https://github.com/NationalSecurityAgency/ghidra/issues/1613#issuecomment-597165377).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.
AI agents are also welcome to contribute; please ensure agents refer to the project's contribution guidelines and development conventions (often found in `.cursor/rules/` or a `CONTRIBUTING.md` file if present).

---

## Acknowledgements

This project is heavily inspired by and based on the work of [LaurieWired](https://github.com/LaurieWired). Instead of using a bridge, this plugin directly embeds the server in the plugin.
