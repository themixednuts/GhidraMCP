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

Additionally, 'grouped' tools are available (e.g., under the `grouped` category) that combine multiple related operations into a single request. This can be beneficial for MCP clients with limits on the total number of tools that can be enabled simultaneously.

**Project Management** ([`projectmanagement`](src/main/java/com/themixednuts/tools/projectmanagement/)) - ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedProjectManagementOperationsTool.java))

- [x] List open programs/files ([`GhidraListFilesTool`](src/main/java/com/themixednuts/tools/projectmanagement/GhidraListFilesTool.java)).
- [x] Get current program information (architecture, image base, etc.) ([`GhidraGetCurrentProgramInfoTool`](src/main/java/com/themixednuts/tools/projectmanagement/GhidraGetCurrentProgramInfoTool.java)).

**Functions** ([`functions`](src/main/java/com/themixednuts/tools/functions/)) - ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedFunctionOperationsTool.java))

- [x] List functions within a program ([`GhidraListFunctionNamesTool`](src/main/java/com/themixednuts/tools/functions/GhidraListFunctionNamesTool.java)).
- [x] Retrieve function details by name or address ([`GhidraGetFunctionByNameTool`](src/main/java/com/themixednuts/tools/functions/GhidraGetFunctionByNameTool.java), [`GhidraGetFunctionByAddressTool`](src/main/java/com/themixednuts/tools/functions/GhidraGetFunctionByAddressTool.java)).
- [x] Get the function containing a specific address/location ([`GhidraGetFunctionContainingLocationTool`](src/main/java/com/themixednuts/tools/functions/GhidraGetFunctionContainingLocationTool.java)).
- [x] Get the current function based on cursor location ([`GhidraGetCurrentFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraGetCurrentFunctionTool.java)).
- [x] Rename functions by name or address ([`GhidraRenameFunctionByNameTool`](src/main/java/com/themixednuts/tools/functions/GhidraRenameFunctionByNameTool.java), [`GhidraRenameFunctionByAddressTool`](src/main/java/com/themixednuts/tools/functions/GhidraRenameFunctionByAddressTool.java)).
- [x] List symbols (variables, parameters) within a function ([`GhidraListSymbolsInFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraListSymbolsInFunctionTool.java)).
- [x] Get symbol details by name within a function ([`GhidraGetSymbolByNameInFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraGetSymbolByNameInFunctionTool.java)).
- [x] Rename symbols within a function ([`GhidraRenameSymbolInFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraRenameSymbolInFunctionTool.java)).
- [x] Change symbol data type within a function ([`GhidraChangeSymbolDataTypeInFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraChangeSymbolDataTypeInFunctionTool.java)).
- [x] Get/Set function comments (Use [`GhidraGetCommentAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraGetCommentAtAddressTool.java) / [`GhidraSetCommentAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraSetCommentAtAddressTool.java) at function entry point).
- [x] Add function ([`GhidraAddFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraAddFunctionTool.java)).
- [x] Remove function ([`GhidraRemoveFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraRemoveFunctionTool.java)).
- [x] Update function prototype/signature ([`GhidraUpdateFunctionPrototypeTool`](src/main/java/com/themixednuts/tools/functions/GhidraUpdateFunctionPrototypeTool.java)).

**Symbols & Labels** ([`symbols`](src/main/java/com/themixednuts/tools/symbols/)) - ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedSymbolOperationsTool.java))

- [x] List defined strings ([`GhidraGetDefinedStringsTool`](src/main/java/com/themixednuts/tools/symbols/GhidraGetDefinedStringsTool.java)).
- [x] List namespaces ([`GhidraListNamespacesTool`](src/main/java/com/themixednuts/tools/symbols/GhidraListNamespacesTool.java)).
- [x] Set comment at a specific address ([`GhidraSetCommentAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraSetCommentAtAddressTool.java)).
- [x] Get comment at a specific address ([`GhidraGetCommentAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraGetCommentAtAddressTool.java)).
- [x] Rename data/label at a specific address ([`GhidraRenameDataAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraRenameDataAtAddressTool.java)).
- [x] Clear symbol/label at a specific address ([`GhidraClearSymbolTool`](src/main/java/com/themixednuts/tools/symbols/GhidraClearSymbolTool.java)).
- [x] List all labels/symbols in the program ([`GhidraListAllSymbolsTool`](src/main/java/com/themixednuts/tools/symbols/GhidraListAllSymbolsTool.java)).
- [x] Add label at address ([`GhidraAddLabelTool`](src/main/java/com/themixednuts/tools/symbols/GhidraAddLabelTool.java)).
- [x] Remove label at address ([`GhidraRemoveLabelTool`](src/main/java/com/themixednuts/tools/symbols/GhidraRemoveLabelTool.java)).

**Data Types** ([`datatypes`](src/main/java/com/themixednuts/tools/datatypes/)) - ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedDatatypeOperationsTool.java))

- [x] List data types ([`GhidraListDataTypesTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraListDataTypesTool.java)).
- [x] List data type categories ([`GhidraListCategoriesTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraListCategoriesTool.java)).
- [x] Create a new data type category ([`GhidraCreateCategoryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateCategoryTool.java)).
- [x] Rename a data type category ([`GhidraRenameCategoryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraRenameCategoryTool.java)).
- [x] Delete a data type category ([`GhidraDeleteCategoryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraDeleteCategoryTool.java)).
- [x] Move a data type category ([`GhidraMoveCategoryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraMoveCategoryTool.java)).
- [x] List namespaces ([`GhidraListNamespacesTool`](src/main/java/com/themixednuts/tools/symbols/GhidraListNamespacesTool.java)).
- [x] List class names ([`GhidraListClassNamesTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraListClassNamesTool.java)).
- [x] List defined structures and enums (Covered by [`GhidraListDataTypesTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraListDataTypesTool.java)).
- [x] Get details of specific structures ([`GhidraGetStructDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraGetStructDefinitionTool.java)).
- [x] Get details of specific enums ([`GhidraGetEnumDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraGetEnumDefinitionTool.java)).
- [x] Get details of specific unions ([`GhidraGetUnionDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraGetUnionDefinitionTool.java)).
- [x] Get details of specific typedefs ([`GhidraGetTypeDefDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraGetTypeDefDefinitionTool.java)).
- [x] Get details of specific function definitions ([`GhidraGetFunctionDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraGetFunctionDefinitionTool.java)).
- [x] Create/Define new structures ([`GhidraCreateStructTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateStructTool.java)).
- [x] Create/Define new enums ([`GhidraCreateEnumTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateEnumTool.java)).
- [x] Create/Define new unions ([`GhidraCreateUnionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateUnionTool.java)).
- [x] Create/Define new typedefs ([`GhidraCreateTypeDefTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateTypeDefTool.java)).
- [x] Create/Define new function definitions ([`GhidraCreateFunctionDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateFunctionDefinitionTool.java)).
- [x] Modify existing structures (Add/Edit/Delete members) ([`GhidraAddStructMemberTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraAddStructMemberTool.java), [`GhidraEditStructMemberTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraEditStructMemberTool.java), [`GhidraDeleteStructMemberTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraDeleteStructMemberTool.java)).
- [x] Modify existing enums (Add/Edit/Delete entries) ([`GhidraAddEnumEntryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraAddEnumEntryTool.java), [`GhidraEditEnumEntryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraEditEnumEntryTool.java), [`GhidraDeleteEnumEntryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraDeleteEnumEntryTool.java)).
- [x] Modify existing unions (Add members) ([`GhidraAddUnionMemberTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraAddUnionMemberTool.java)).
- [x] Modify existing function definitions ([`GhidraUpdateFunctionDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraUpdateFunctionDefinitionTool.java)).
- [x] Modify existing typedefs ([`GhidraUpdateTypeDefTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraUpdateTypeDefTool.java)).
- [x] Rename data types ([`GhidraRenameDataTypeTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraRenameDataTypeTool.java)).
- [x] Delete data types ([`GhidraDeleteDataTypeTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraDeleteDataTypeTool.java)).
- [x] Apply data type at a specific address ([`GhidraApplyDataTypeTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraApplyDataTypeTool.java)).

**Memory & Addresses** ([`memory`](src/main/java/com/themixednuts/tools/memory/)) - ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedMemoryOperationsTool.java))

- [x] List memory segments ([`GhidraListSegmentsTool`](src/main/java/com/themixednuts/tools/memory/GhidraListSegmentsTool.java)).
- [x] Get current address/location based on cursor ([`GhidraGetCurrentAddressTool`](src/main/java/com/themixednuts/tools/memory/GhidraGetCurrentAddressTool.java)).
- [x] Read bytes from an address ([`GhidraReadBytesTool`](src/main/java/com/themixednuts/tools/memory/GhidraReadBytesTool.java)).
- [x] Write bytes to an address (Patching) ([`GhidraWriteBytesTool`](src/main/java/com/themixednuts/tools/memory/GhidraWriteBytesTool.java)).
- [x] Search memory for bytes or strings ([`GhidraSearchMemoryTool`](src/main/java/com/themixednuts/tools/memory/GhidraSearchMemoryTool.java)).
- [x] Get cross-references (XRefs) _to_ a specific address ([`GhidraGetXRefsToTool`](src/main/java/com/themixednuts/tools/memory/GhidraGetXRefsToTool.java)).
- [x] Get cross-references (XRefs) _from_ a specific address ([`GhidraGetXRefsFromTool`](src/main/java/com/themixednuts/tools/memory/GhidraGetXRefsFromTool.java)).
- [x] List imported libraries/functions ([`GhidraListImportsTool`](src/main/java/com/themixednuts/tools/memory/GhidraListImportsTool.java)).

**Decompiler** ([`decompiler`](src/main/java/com/themixednuts/tools/decompiler/)) - ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedDecompilerOperationsTool.java))

- [x] Provide decompiled code for functions by name ([`GhidraDecompileFunctionByNameTool`](src/main/java/com/themixednuts/tools/decompiler/GhidraDecompileFunctionByNameTool.java)).

**Bookmarks**

- [ ] List bookmarks.
- [ ] Add/Remove bookmarks.

**Analysis & Scripting** ([`analysis`](src/main/java/com/themixednuts/tools/analysis/)) - ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedAnalysisOperationsTool.java))

- [x] Trigger auto-analysis ([`GhidraTriggerAnalysisTool`](src/main/java/com/themixednuts/tools/analysis/GhidraTriggerAnalysisTool.java)).
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
