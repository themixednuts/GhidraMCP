<div align="center">
<a href="https://github.com/themixednuts/GhidraMCP/releases"><img src="https://img.shields.io/github/v/release/themixednuts/GhidraMCP?label=latest%20release&style=flat-square" alt="GitHub release (latest by date)"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/themixednuts/GhidraMCP/build.yml?style=flat-square" alt="Build Status"></a>
  <a href="#"><img src="https://img.shields.io/badge/Ghidra-12.0-blue?style=flat-square" alt="Tested Ghidra Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/stargazers"><img src="https://img.shields.io/github/stars/themixednuts/GhidraMCP?style=flat-square" alt="GitHub stars"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/network/members"><img src="https://img.shields.io/github/forks/themixednuts/GhidraMCP?style=flat-square" alt="GitHub forks"></a>
</div>

<div align="center">

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](cursor://anysphere.cursor-deeplink/mcp/install?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)

If your browser/GitHub blocks custom URI handlers, use the web fallback:
[Cursor install fallback](https://cursor.com/install-mcp?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)

</div>
<h1 align="center">GhidraMCP</h1>

> Connect Ghidra to MCP-compatible clients

Related project: [WinDbg MCP Server](https://github.com/themixednuts/windbg-mcp-server)

---

## ✨ Features

### Core Analysis

- **Analyze RTTI** - Microsoft and Itanium C++ RTTI plus Go runtime RTTI
  analysis with type detection and demangling
- **Decompile Code** - Decompile functions to readable C-like pseudocode
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
- **Undo/Redo** - Program history undo/redo operations
- **Read Tool Output** - Retrieve large tool responses in follow-up chunks

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

1. Start Ghidra with the GhidraMCP extension enabled.
2. Confirm the server port in **Configuration**.
3. Point your MCP client to `http://127.0.0.1:8080/mcp` (or your custom port).

> [!WARNING]
> **Script Error Dialogs:** Some script-driven operations can open a Ghidra error
> dialog. Close the dialog before continuing, or requests may appear to hang.

> [!TIP]
> **Missing `file_name`:** Use `list_programs` to see available programs and pass
> the exact name returned by that tool.

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

If you are installing from a GitHub release zip, you can skip this section.
The steps below are only for building from source.

1. Clone the repository:
   ```bash
   git clone https://github.com/themixednuts/GhidraMCP.git
   ```
2. Ensure you have [Apache Maven](https://maven.apache.org/install.html)
   **3.6.3+** and JDK 21 or later installed.
3. Download the required Ghidra libraries (first time only):
   ```bash
   mvn -f bootstrap.xml initialize
   ```

   Optional: choose a specific Ghidra release:
   ```bash
   mvn -f bootstrap.xml initialize -Dghidra.release=12.0
   ```

4. Build the project:
   ```bash
   mvn clean package
   ```
5. The installable `zip` file is written to `target/` (for example,
   `target/GhidraMCP-0.6.1.zip`). Install it using the steps above.

---

## 🔌 Configuring an MCP Client

Use this server URL in your client:

- `http://127.0.0.1:8080/mcp` (or your custom port)

Most clients use a config like:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

### Client Setup Instructions

<details>
<summary><strong><img src="https://claude.ai/favicon.ico" alt="Claude" width="16" height="16" valign="middle" />&nbsp;Claude Desktop</strong></summary>

Config path:

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Add the JSON config above, then restart Claude Desktop.

</details>

<details>
<summary><strong><img src="https://claude.ai/favicon.ico" alt="Claude" width="16" height="16" valign="middle" />&nbsp;Claude Code (CLI)</strong></summary>

```bash
claude mcp add ghidra "http://127.0.0.1:8080/mcp" --transport http
```

</details>

<details>
<summary><strong><img src="https://cursor.com/favicon.ico" alt="Cursor" width="16" height="16" valign="middle" />&nbsp;Cursor</strong></summary>

- [Install via deep link](cursor://anysphere.cursor-deeplink/mcp/install?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)
- [Install via web fallback](https://cursor.com/install-mcp?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)

Manual config path: `~/.cursor/mcp_settings.json`

</details>

<details>
<summary><strong><img src="https://opencode.ai/favicon.ico" alt="OpenCode" width="16" height="16" valign="middle" />&nbsp;OpenCode</strong></summary>

Use `~/.config/opencode/opencode.json` (or project-level `opencode.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ghidra": {
      "type": "remote",
      "url": "http://127.0.0.1:8080/mcp",
      "enabled": true
    }
  }
}
```

</details>

<details>
<summary><strong><img src="https://openai.com/favicon.ico" alt="Codex" width="16" height="16" valign="middle" />&nbsp;Codex CLI</strong></summary>

```bash
codex mcp
```

Or add this to `~/.codex/config.toml`:

```toml
[mcp_servers.ghidra]
url = "http://127.0.0.1:8080/mcp"
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
issues.

---

## Acknowledgements

This project is heavily inspired by and based on the work of
[LaurieWired](https://github.com/LaurieWired). Instead of using a bridge, this
plugin directly embeds the server in the plugin.
