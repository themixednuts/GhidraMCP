<div align="center">
<a href="https://github.com/themixednuts/GhidraMCP/releases"><img src="https://img.shields.io/github/v/release/themixednuts/GhidraMCP?label=latest%20release&style=flat-square" alt="GitHub release (latest by date)"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/themixednuts/GhidraMCP/build.yml?style=flat-square" alt="Build Status"></a>
  <a href="#"><img src="https://img.shields.io/badge/Ghidra-12.0-blue?style=flat-square" alt="Tested Ghidra Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/stargazers"><img src="https://img.shields.io/github/stars/themixednuts/GhidraMCP?style=flat-square" alt="GitHub stars"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/network/members"><img src="https://img.shields.io/github/forks/themixednuts/GhidraMCP?style=flat-square" alt="GitHub forks"></a>
</div>

<!-- Optional: Add a project logo here -->
<!-- <p align="center">
  <img src="PATH_TO_YOUR_LOGO.png" alt="GhidraMCP Logo" width="200"/>
</p> -->

<div align="center">

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](cursor://anysphere.cursor-deeplink/mcp/install?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)

</div>
<h1 align="center">GhidraMCP</h1>

> Ghidra integration for the Model Context Protocol (MCP)

---

## ✨ Features

### Core Analysis

- **Analyze RTTI** - Microsoft RTTI structure analysis with type detection and
  demangling
- **Decompile Code** - Function decompilation to C-like pseudocode with P-code
  analysis
- **Demangle Symbols** - C++ symbol demangling with multiple format support
- **Script Guidance** - Provides guidance on using Ghidra scripts like
  DemangleAllScript for advanced demangling

### Management Operations

- **Manage Data Types** - Create and update structures, enums, unions, typedefs,
  and categories
- **Manage Functions** - Create, update, and manage function definitions and
  prototypes
- **Manage Memory** - Read/write bytes, manage segments, and analyze memory
  layout
- **Manage Project** - Navigate addresses, manage bookmarks, and control project
  settings
- **Manage Symbols** - Create, rename, and organize symbols with namespace
  support

### Read Operations

- **Read Data Types** - Browse and query program data types with filtering and
  pagination
- **Read Functions** - Enumerate functions with detailed metadata and filtering
- **Read Listing** - View disassembly and data from program listing with
  address, range, or function-based viewing
- **Read Memory Blocks** - View memory segments, permissions, and properties
- **Read Symbols** - Browse symbols with type and namespace filtering

### Delete Operations

- **Delete Bookmark** - Remove bookmarks by address or category
- **Delete Data Type** - Remove data type definitions from the program
- **Delete Function** - Remove function definitions and associated data
- **Delete Symbol** - Remove symbols by name, ID, or address

### Discovery & Search

- **List Analysis Options** - View available analysis options and settings
- **List Programs** - Discover open and closed programs in the project with
  pagination and filtering
- **Find References** - Locate code and data references with pagination support
- **Search Memory** - Pattern search with hex, string, binary, and regex support

### Utilities

- **Batch Operations** - Execute multiple tool operations in a single
  transaction with automatic rollback on failure
- **Undo/Redo** - Transaction-based undo/redo operations

---

## 🚀 Installation

1. Download the latest release `zip` file from the
   [Releases](https://github.com/themixednuts/GhidraMCP/releases) page.
2. In Ghidra, go to `File` -> `Install Extensions...`.
3. Click the `+` button (Add extension) in the top right corner.
4. Navigate to the downloaded `zip` file and select it.
5. Ensure the `GhidraMCP` extension is checked in the list and click `OK`.
6. Restart Ghidra.

---

## ▶️ Usage

Configure the MCP server settings (see 'Configuration' below) and ensure your
MCP Client is configured to connect (see 'Configuring an MCP Client' below).

> [!WARNING]
> **Script Error Dialogs:** Some tools that execute Ghidra scripts may trigger
> GUI error dialogs via `Msg.showError`. These dialogs **must** be manually
> closed, or the server will hang and become unresponsive.

> [!TIP]
> **Missing fileName Parameter:** When tools request a `fileName` parameter, use
> the `list_programs` tool to see available programs. Most tools provide this
> context automatically on failed calls.

## ⚙️ Configuration

The GhidraMCP server can be configured through Ghidra's application-level
settings:

1. In Ghidra, go to **Browser** → **Edit** → **Tool Options**.
2. In the left panel, expand **Miscellaneous** and select **GhidraMCP HTTP
   Server**.
3. Configure the following options:
   - **Server Port**: The port number for the MCP server (default: 8080)
   - **Auto-start Server**: Whether to automatically start the server when
     Ghidra launches
4. Click **OK** to save your settings.

## 🛠️ Building from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/themixednuts/GhidraMCP.git
   ```
2. Ensure you have [Apache Maven](https://maven.apache.org/install.html) and JDK
   21 or later installed.
3. Copy the following required JAR files from your Ghidra installation directory
   into the `lib/` directory (create it if needed):
   - `Ghidra/Features/Base/lib/Base.jar`
   - `Ghidra/Features/Decompiler/lib/Decompiler.jar`
   - `Ghidra/Framework/Docking/lib/Docking.jar`
   - `Ghidra/Framework/Generic/lib/Generic.jar`
   - `Ghidra/Framework/Project/lib/Project.jar`
   - `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
   - `Ghidra/Framework/Utility/lib/Utility.jar`
   - `Ghidra/Framework/Gui/lib/Gui.jar`
   - `Ghidra/Features/MicrosoftCodeAnalyzer/lib/MicrosoftCodeAnalyzer.jar`
   - `Ghidra/Features/MicrosoftDemangler/lib/MicrosoftDemangler.jar`
   - `Ghidra/Features/MicrosoftDmang/lib/MicrosoftDmang.jar`
4. Build the project using Maven:
   ```bash
   mvn clean package
   ```
5. The installable `zip` file will be in the `target/` directory (e.g.,
   `target/GhidraMCP-0.5.0.zip`). Install it using the steps above.

> [!TIP]
> **CI Test JAR:** The test JAR with dependencies is only built when explicitly
> requested. To build it locally for testing:
>
> ```bash
> mvn clean package -P ci-tests
> ```

---

## 🔌 Configuring an MCP Client

Configure your MCP client to connect to `http://127.0.0.1:8080/mcp` (or your
configured port).

### Agent-Specific Setup Instructions

<details>
<summary><strong>🤖 Claude Desktop</strong></summary>

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

**Configuration file location:**

- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

After updating the configuration, restart Claude Desktop to apply the changes.

</details>

<details>
<summary><strong>🔧 Claude Code (CLI)</strong></summary>

For Claude Code, use the following command to add the GhidraMCP server:

```bash
claude mcp add ghidra "http://127.0.0.1:8080/mcp" --transport http
```

</details>

<details>
<summary><strong>⚡ Cursor</strong></summary>

For Cursor, you can
[install via this link](https://cursor.com/install-mcp?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D).

Or manually add to your MCP configuration:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

**Configuration file location:**

- `~/.cursor/mcp_settings.json` (or your Cursor configuration directory)

</details>

<details>
<summary><strong>🛠️ Custom MCP Client</strong></summary>

For custom MCP clients or other implementations, use the standard MCP
configuration format:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://127.0.0.1:8080/mcp",
      "transport": "http"
    }
  }
}
```

</details>

---

> [!IMPORTANT]
> The default port is `8080` (configurable in Ghidra: **Browser** → **Edit** →
> **Tool Options** → **Miscellaneous** → **GhidraMCP HTTP Server**). If you
> change the port, update your client configuration accordingly. Ghidra must be
> running with the extension enabled for the client to connect.

> [!NOTE]
> **Timeout Issues:** If you encounter timeout problems, refer to the
> [Ghidra timeout configuration guide](https://github.com/NationalSecurityAgency/ghidra/issues/1613#issuecomment-597165377).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open
issues. AI agents are also welcome to contribute; please ensure agents refer to
the project's contribution guidelines and development conventions (often found
in `.cursor/rules/` or a `CONTRIBUTING.md` file if present).

---

## Acknowledgements

This project is heavily inspired by and based on the work of
[LaurieWired](https://github.com/LaurieWired). Instead of using a bridge, this
plugin directly embeds the server in the plugin.
