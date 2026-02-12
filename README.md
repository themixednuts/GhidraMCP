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

If your browser/GitHub blocks custom URI handlers, use the web fallback:
[Cursor install fallback](https://cursor.com/install-mcp?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)

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
- **Undo/Redo** - Program history undo/redo operations
- **Read Tool Output** - Retrieve oversized tool responses from session-based
  temp storage in chunked, composable calls

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
> **Missing file_name Parameter:** When tools request a `file_name` parameter,
> use the `list_programs` tool to see available programs. Most tools provide
> this context automatically on failed calls.

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

## 🔄 Dependency Automation

- `/.github/dependabot.yml` manages regular Maven and GitHub Actions dependency
  update PRs.
- `/renovate.json` + `/.github/workflows/renovate-bootstrap.yml` manage
  `bootstrap.xml` version properties via regex-based updates.
- `/.github/workflows/dependency-update-validation.yml` runs stricter validation
  for bot-authored dependency PRs (pinned build + latest-bootstrap smoke test).
- You can run the Renovate bootstrap updater on demand from the Actions tab using
  the **Renovate Bootstrap Dependencies** workflow.

## 🛠️ Building from Source

If you are installing from a GitHub release zip, you can skip this section.
The steps below are only for building from source.

1. Clone the repository:
   ```bash
   git clone https://github.com/themixednuts/GhidraMCP.git
   ```
2. Ensure you have [Apache Maven](https://maven.apache.org/install.html)
   **3.6.3+** and JDK 21 or later installed.
3. Download the required Ghidra jars (first time only, ~350MB):

   Recommended (reproducible, matches `pom.xml` `ghidra.version`):
   ```bash
   mvn -f bootstrap.xml initialize
   ```

   Pin to a specific version:
   ```bash
   mvn -f bootstrap.xml initialize -Dghidra.release=12.0
   ```

   Track latest release:
   ```bash
   mvn -f bootstrap.xml initialize -Dghidra.release=latest
   ```

   This writes jars to `lib/` and records metadata in
   `lib/.ghidra-bootstrap.properties` for version checks.

   If you bootstrap with `latest` and it differs from `pom.xml`'s
   `ghidra.version`, either:

   - build with a matching version override, e.g.
     `mvn clean package -Dghidra.version=<resolved-version>`
   - or bypass the guard (not recommended):
     `mvn clean package -Dghidra.version.check.skip=true`

   Optional advanced override:

   - bootstrap output directory: `-Dghidra.lib.output.dir=/path/to/lib`
   - compile-time library directory: `-Dghidra.lib.dir=/path/to/lib`

4. Build the project:
   ```bash
   mvn clean package
   ```
5. The installable `zip` file will be in the `target/` directory (e.g.,
   `target/GhidraMCP-0.5.3.zip`). Install it using the steps above.

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

GitHub README deep links are supported for both section headings and custom
anchors (see GitHub docs for
[section links](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#section-links)
and
[custom anchors](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#custom-anchors)).

<a name="client-claude-desktop"></a>

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

<a name="client-claude-code-cli"></a>

<details>
<summary><strong>🔧 Claude Code (CLI)</strong></summary>

For Claude Code, use the following command to add the GhidraMCP server:

```bash
claude mcp add ghidra "http://127.0.0.1:8080/mcp" --transport http
```

</details>

<a name="client-cursor"></a>

<details>
<summary><strong>⚡ Cursor</strong></summary>

Use the direct Cursor deep link:

- [Install via deep link](cursor://anysphere.cursor-deeplink/mcp/install?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)

If your browser/GitHub blocks custom URI handlers, use the web fallback:

- [Install via web fallback](https://cursor.com/install-mcp?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)

Or copy this deep link directly into your browser address bar:

```text
cursor://anysphere.cursor-deeplink/mcp/install?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D
```

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

<a name="client-opencode"></a>

<details>
<summary><strong>🧩 OpenCode</strong></summary>

Add GhidraMCP to your OpenCode config under `mcp`:

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

**Configuration file location:**

- Global: `~/.config/opencode/opencode.json`
- Project override: `opencode.json` in your project root

</details>

<a name="client-codex-cli"></a>

<details>
<summary><strong>🧠 Codex CLI</strong></summary>

You can add/manage MCP servers interactively from the Codex CLI:

```bash
codex mcp
```

Or configure it directly in `config.toml`:

```toml
[mcp_servers.ghidra]
url = "http://127.0.0.1:8080/mcp"
```

**Configuration file location:**

- User-level: `~/.codex/config.toml`
- Project-level (trusted projects): `.codex/config.toml`

</details>

<a name="client-custom-mcp"></a>

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
