<div align="center">
  <a href="https://github.com/themixednuts/GhidraMCP/releases"><img src="https://img.shields.io/github/v/release/themixednuts/GhidraMCP?label=latest%20release&style=flat-square" alt="GitHub release (latest by date)"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/themixednuts/GhidraMCP/build.yml?style=flat-square" alt="Build Status"></a>
  <a href="#"><img src="https://img.shields.io/badge/Ghidra-11.3.2-blue?style=flat-square" alt="Tested Ghidra Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/stargazers"><img src="https://img.shields.io/github/stars/themixednuts/GhidraMCP?style=flat-square" alt="GitHub stars"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/network/members"><img src="https://img.shields.io/github/forks/themixednuts/GhidraMCP?style=flat-square" alt="GitHub forks"></a>
</div>

<!-- Optional: Add a project logo here -->
<!-- <p align="center">
  <img src="PATH_TO_YOUR_LOGO.png" alt="GhidraMCP Logo" width="200"/>
</p> -->

<h1 align="center">GhidraMCP</h1>

> Ghidra integration for the Model Context Protocol (MCP)

A Ghidra extension that runs an embedded MCP server to expose Ghidra program data and functionalities via tools.

---

## ✨ Features

<details>
<summary>Click to expand/collapse the full features list</summary>

This extension exposes various Ghidra functionalities to MCP clients, grouped by category:

> [!TIP]
> To help manage limits on the number of enabled tools in some MCP clients, 'grouped' tools are available. These combine multiple related operations (e.g., several function operations) into a single tool interface. You can find links to these grouped tools in the category headers below (e.g., **Functions** - [`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedFunctionOperationsTool.java)).

### Project Management ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedProjectManagementOperationsTool.java))

- [x] List open programs/files: [`GhidraListOpenFilesTool`](src/main/java/com/themixednuts/tools/projectmanagement/GhidraListOpenFilesTool.java)
- [x] Get current program info: [`GhidraGetCurrentProgramInfoTool`](src/main/java/com/themixednuts/tools/projectmanagement/GhidraGetCurrentProgramInfoTool.java)
- [x] List bookmarks: [`GhidraListBookmarksTool`](src/main/java/com/themixednuts/tools/projectmanagement/GhidraListBookmarksTool.java)
- [x] Add bookmark: [`GhidraCreateBookmarkTool`](src/main/java/com/themixednuts/tools/projectmanagement/GhidraCreateBookmarkTool.java)
- [x] Remove bookmark: [`GhidraDeleteBookmarkTool`](src/main/java/com/themixednuts/tools/projectmanagement/GhidraDeleteBookmarkTool.java)
- [x] List Ghidra scripts: [`GhidraListScriptsTool`](src/main/java/com/themixednuts/tools/projectmanagement/GhidraListScriptsTool.java)
- [x] Run Ghidra script: [`GhidraRunScriptTool`](src/main/java/com/themixednuts/tools/projectmanagement/GhidraRunScriptTool.java)

### Functions ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedFunctionOperationsTool.java))

- [x] List functions: [`GhidraListFunctionNamesTool`](src/main/java/com/themixednuts/tools/functions/GhidraListFunctionNamesTool.java)
- [x] Get function details by name ([`GhidraGetFunctionByNameTool`](src/main/java/com/themixednuts/tools/functions/GhidraGetFunctionByNameTool.java)) or address ([`GhidraGetFunctionByAddressTool`](src/main/java/com/themixednuts/tools/functions/GhidraGetFunctionByAddressTool.java))
- [x] Get function containing location: [`GhidraGetFunctionContainingLocationTool`](src/main/java/com/themixednuts/tools/functions/GhidraGetFunctionContainingLocationTool.java)
- [x] Get current function: [`GhidraGetCurrentFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraGetCurrentFunctionTool.java)
- [x] Rename function by name ([`GhidraRenameFunctionByNameTool`](src/main/java/com/themixednuts/tools/functions/GhidraRenameFunctionByNameTool.java)) or address ([`GhidraRenameFunctionByAddressTool`](src/main/java/com/themixednuts/tools/functions/GhidraRenameFunctionByAddressTool.java))
- [x] List symbols in function: [`GhidraListSymbolsInFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraListSymbolsInFunctionTool.java)
- [x] Get symbol by name in function: [`GhidraGetSymbolByNameInFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraGetSymbolByNameInFunctionTool.java)
- [x] Rename symbol in function: [`GhidraRenameSymbolInFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraRenameSymbolInFunctionTool.java)
- [x] Change symbol data type in function: [`GhidraUpdateSymbolDataTypeInFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraUpdateSymbolDataTypeInFunctionTool.java)
- [x] Get/Set function comments (Use [`GhidraGetCommentAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraGetCommentAtAddressTool.java) / [`GhidraUpdateCommentAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraUpdateCommentAtAddressTool.java) at entry point)
- [x] Add function: [`GhidraCreateFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraCreateFunctionTool.java)
- [x] Remove function: [`GhidraDeleteFunctionTool`](src/main/java/com/themixednuts/tools/functions/GhidraDeleteFunctionTool.java)
- [x] Update function prototype/signature: [`GhidraUpdateFunctionPrototypeTool`](src/main/java/com/themixednuts/tools/functions/GhidraUpdateFunctionPrototypeTool.java)
- [x] Decompile function by name: [`GhidraDecompileFunctionByNameTool`](src/main/java/com/themixednuts/tools/decompiler/GhidraDecompileFunctionByNameTool.java)

### Symbols & Labels ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedSymbolOperationsTool.java))

- [x] List defined strings: [`GhidraGetDefinedStringsTool`](src/main/java/com/themixednuts/tools/symbols/GhidraGetDefinedStringsTool.java)
- [x] List namespaces: [`GhidraListNamespacesTool`](src/main/java/com/themixednuts/tools/symbols/GhidraListNamespacesTool.java)
- [x] Set comment at address: [`GhidraUpdateCommentAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraUpdateCommentAtAddressTool.java)
- [x] Get comment at address: [`GhidraGetCommentAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraGetCommentAtAddressTool.java)
- [x] Rename data at address: [`GhidraRenameDataAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraRenameDataAtAddressTool.java)
- [x] Clear symbol at address: [`GhidraDeleteSymbolAtAddressTool`](src/main/java/com/themixednuts/tools/symbols/GhidraDeleteSymbolAtAddressTool.java)
- [x] List all symbols: [`GhidraListAllSymbolsTool`](src/main/java/com/themixednuts/tools/symbols/GhidraListAllSymbolsTool.java)
- [x] Add label at address: [`GhidraCreateLabelTool`](src/main/java/com/themixednuts/tools/symbols/GhidraCreateLabelTool.java)
- [x] Remove label at address: [`GhidraDeleteLabelTool`](src/main/java/com/themixednuts/tools/symbols/GhidraDeleteLabelTool.java)

### Data Types ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedDatatypeOperationsTool.java))

- [x] List data types: [`GhidraListDataTypesTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraListDataTypesTool.java)
- [x] List categories: [`GhidraListCategoriesTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraListCategoriesTool.java)
- [x] Create category: [`GhidraCreateCategoryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateCategoryTool.java)
- [x] Rename category: [`GhidraRenameCategoryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraRenameCategoryTool.java)
- [x] Delete category: [`GhidraDeleteCategoryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraDeleteCategoryTool.java)
- [x] Move category: [`GhidraMoveCategoryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraMoveCategoryTool.java)
- [x] List namespaces: [`GhidraListNamespacesTool`](src/main/java/com/themixednuts/tools/symbols/GhidraListNamespacesTool.java)
- [x] List class names: [`GhidraListClassNamesTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraListClassNamesTool.java)
- [x] List defined structures/enums (Covered by [`GhidraListDataTypesTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraListDataTypesTool.java))
- [x] Get struct definition: [`GhidraGetStructDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraGetStructDefinitionTool.java)
- [x] Get enum definition: [`GhidraGetEnumDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraGetEnumDefinitionTool.java)
- [x] Get union definition: [`GhidraGetUnionDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraGetUnionDefinitionTool.java)
- [x] Get typedef definition: [`GhidraGetTypeDefDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraGetTypeDefDefinitionTool.java)
- [x] Get function definition: [`GhidraGetFunctionDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraGetFunctionDefinitionTool.java)
- [x] Create struct: [`GhidraCreateStructTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateStructTool.java)
- [x] Create enum: [`GhidraCreateEnumTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateEnumTool.java)
- [x] Create union: [`GhidraCreateUnionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateUnionTool.java)
- [x] Create typedef: [`GhidraCreateTypeDefTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateTypeDefTool.java)
- [x] Create function definition: [`GhidraCreateFunctionDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateFunctionDefinitionTool.java)
- [x] Modify structs (Add/Edit/Delete members): [`GhidraCreateStructMemberTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateStructMemberTool.java), [`GhidraUpdateStructMemberTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraUpdateStructMemberTool.java), [`GhidraDeleteStructMemberTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraDeleteStructMemberTool.java)
- [x] Modify enums (Add/Edit/Delete entries): [`GhidraCreateEnumEntryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateEnumEntryTool.java), [`GhidraUpdateEnumEntryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraUpdateEnumEntryTool.java), [`GhidraDeleteEnumEntryTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraDeleteEnumEntryTool.java)
- [x] Modify unions (Add members): [`GhidraCreateUnionMemberTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraCreateUnionMemberTool.java)
- [x] Modify function definitions: [`GhidraUpdateFunctionDefinitionTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraUpdateFunctionDefinitionTool.java)
- [x] Modify typedefs: [`GhidraUpdateTypeDefTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraUpdateTypeDefTool.java)
- [x] Rename data types: [`GhidraRenameDataTypeTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraRenameDataTypeTool.java)
- [x] Delete data types: [`GhidraDeleteDataTypeTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraDeleteDataTypeTool.java)
- [x] Apply data type at address: [`GhidraSetDataTypeAtAddressTool`](src/main/java/com/themixednuts/tools/datatypes/GhidraSetDataTypeAtAddressTool.java)

### Memory & Addresses ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedMemoryOperationsTool.java))

- [x] List segments: [`GhidraListSegmentsTool`](src/main/java/com/themixednuts/tools/memory/GhidraListSegmentsTool.java)
- [x] Get current address: [`GhidraGetCurrentAddressTool`](src/main/java/com/themixednuts/tools/memory/GhidraGetCurrentAddressTool.java)
- [x] Read bytes from address: [`GhidraReadMemoryBytesTool`](src/main/java/com/themixednuts/tools/memory/GhidraReadMemoryBytesTool.java)
- [x] Write bytes to address (Patching): [`GhidraWriteMemoryBytesTool`](src/main/java/com/themixednuts/tools/memory/GhidraWriteMemoryBytesTool.java)
- [x] Search memory: [`GhidraSearchMemoryTool`](src/main/java/com/themixednuts/tools/memory/GhidraSearchMemoryTool.java)
- [x] Get XRefs _to_ address: [`GhidraGetXRefsToAddressTool`](src/main/java/com/themixednuts/tools/memory/GhidraGetXRefsToAddressTool.java)
- [x] Get XRefs _from_ address: [`GhidraGetXRefsFromAddressTool`](src/main/java/com/themixednuts/tools/memory/GhidraGetXRefsFromAddressTool.java)
- [x] List imports: [`GhidraListImportsTool`](src/main/java/com/themixednuts/tools/memory/GhidraListImportsTool.java)

### Decompiler ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedDecompilerOperationsTool.java))

- [x] Decompile function by name: [`GhidraDecompileFunctionByNameTool`](src/main/java/com/themixednuts/tools/decompiler/GhidraDecompileFunctionByNameTool.java)

### Analysis & Scripting ([`grouped`](src/main/java/com/themixednuts/tools/grouped/GroupedAnalysisOperationsTool.java))

- [x] Trigger auto-analysis: [`GhidraTriggerAutoAnalysisTool`](src/main/java/com/themixednuts/tools/projectmanagement/GhidraTriggerAutoAnalysisTool.java)

</details>

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
    - > [!NOTE]
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

> [!IMPORTANT] > **Port:** The default port is `8080`. This is configurable within Ghidra under the Tool Options for the GhidraMCP extension. If you change the port in Ghidra, you **must** update the `url` in your client configuration accordingly.

> [!IMPORTANT] > **Server Status:** Ghidra must be running with the GhidraMCP extension enabled for the client to connect successfully.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

---

## Acknowledgements

This project is heavily inspired by and based on the work of [LaurieWired](https://github.com/LaurieWired). Instead of using a bridge, this plugin directly embeds the server in the plugin. Developed by TheMixedNuts.
