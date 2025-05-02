[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/themixednuts/GhidraMCP?label=latest%20release)](https://github.com/themixednuts/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/themixednuts/GhidraMCP)](https://github.com/themixednuts/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/themixednuts/GhidraMCP)](https://github.com/themixednuts/GhidraMCP/network/members)

<!-- Optional: Add build status badge if using GitHub Actions -->
<!-- [![Build Status](https://github.com/themixednuts/GhidraMCP/actions/workflows/YOUR_BUILD_WORKFLOW.yml/badge.svg)](https://github.com/themixednuts/GhidraMCP/actions/workflows/YOUR_BUILD_WORKFLOW.yml) -->

<!-- Optional: Add a project logo here -->
<!-- <p align="center">
  <img src="PATH_TO_YOUR_LOGO.png" alt="GhidraMCP Logo" width="200"/>
</p> -->

# GhidraMCP

> Ghidra integration for the Model Context Protocol (MCP)

A Ghidra extension providing tools and integration points for the Model Context Protocol (MCP). This project allows interaction with MCP servers and resources directly within the Ghidra reverse engineering framework.

## Features

This extension exposes various Ghidra functionalities to MCP clients, grouped by category:

**Project Management** (`projectmanagement`)

- [x] List open programs.
- [ ] Get current program information (architecture, image base, etc.).

**Functions** (`functions`)

- [x] List functions within a program.
- [x] Retrieve function details by name or address.
- [x] Rename functions.
- [ ] Get/Set function comments.
- [ ] Add/Remove functions.

**Symbols** (`symbols`)

- [x] List symbols within functions.
- [x] Get symbol details by name.
- [x] Rename symbols.
- [x] Modify symbol data types.
- [ ] List all labels/symbols in the program.
- [ ] Add/Remove labels at addresses.
- [ ] Get/Set comments on symbols/labels.

**Data Types** (`datatypes`)

- [x] List classes and namespaces.
- [ ] List defined structures and enums.
- [ ] Get details of specific structures/enums.
- [ ] Create/Define new structures/enums.
- [ ] Modify existing structures/enums.
- [ ] Apply data type at a specific address.

**Memory & Addresses** (`memory`)

- [x] List memory segments.
- [x] Get defined strings.
- [ ] Read bytes from an address.
- [ ] Write bytes to an address (Patching).
- [ ] Search memory for bytes, strings, or instructions.
- [x] Get cross-references (XRefs) _to_ and _from_ specific addresses.
- [ ] Get/Set EOL, Pre, Post, Plate comments at addresses.

**Decompiler** (`decompiler`)

- [x] Provide decompiled code for functions.

**Bookmarks**

- [ ] List bookmarks.
- [ ] Add/Remove bookmarks.

**Analysis & Scripting**

- [ ] Trigger auto-analysis (or specific analyzers).
- [ ] Clear code bytes / Undefine data at an address.
- [ ] Run existing Ghidra scripts.

## Installation

1.  Download the latest release `zip` file from the [Releases](https://github.com/themixednuts/GhidraMCP/releases) page.
2.  In Ghidra, go to `File` -> `Install Extensions...`.
3.  Click the `+` button (Add extension) in the top right corner.
4.  Navigate to the downloaded `zip` file and select it.
5.  Ensure the `GhidraMCP` extension is checked in the list and click `OK`.
6.  Restart Ghidra.

## Usage

1.  Ensure Ghidra is running with the GhidraMCP extension active.
2.  Ensure your MCP Client is configured to connect to the GhidraMCP server (see 'Configuring an MCP Client' below).

## Building from Source

1.  Clone the repository: `git clone https://github.com/themixednuts/GhidraMCP.git`
2.  Navigate to the project directory: `cd GhidraMCP`
3.  Ensure you have Apache Maven and a JDK (compatible version, e.g., JDK 21 or later recommended for modern Ghidra development) installed.
4.  Copy the following required JAR files from your Ghidra installation directory into the `lib/` directory of this project. Create the `lib/` directory if it doesn't exist:
    - `Ghidra/Features/Base/lib/Base.jar`
    - `Ghidra/Features/Decompiler/lib/Decompiler.jar`
    - `Ghidra/Framework/Docking/lib/Docking.jar`
    - `Ghidra/Framework/Generic/lib/Generic.jar`
    - `Ghidra/Framework/Project/lib/Project.jar`
    - `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
    - `Ghidra/Framework/Utility/lib/Utility.jar`
    - `Ghidra/Framework/Gui/lib/Gui.jar`
    - _(Note: Paths are relative to your Ghidra installation folder. Exact paths might vary slightly based on Ghidra version and OS.)_
5.  Build the project using Maven: `mvn clean package assembly:single`
6.  The installable `zip` file will be located in the `target/` directory (e.g., `target/GhidraMCP-*-SNAPSHOT-ghidra.zip`). Follow the Installation steps above using this file.

## Configuring an MCP Client

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

**Important Notes:**

- **Port:** The default port is `8080`. This is configurable within Ghidra under the Tool Options for the GhidraMCP extension. If you change the port in Ghidra, you **must** update the `url` in your client configuration accordingly.
- **Server Status:** Ghidra must be running with the GhidraMCP extension enabled for the client to connect successfully.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## Acknowledgements

This project is heavily inspired by and based on the work of [LaurieWired](https://github.com/LaurieWired). Instead of using a bridge, this plugin directly embeds the server in the plugin.
