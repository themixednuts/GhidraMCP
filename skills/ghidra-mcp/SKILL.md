---
name: ghidra-mcp
description: Reverse engineering with Ghidra via MCP. Use when analyzing binaries, decompiling code, managing functions/symbols/data types, or performing any Ghidra-related reverse engineering task.
license: MIT
compatibility: Requires GhidraMCP server running with Ghidra
metadata:
  author: themixednuts
  version: "0.5.2"
---

# Ghidra MCP Skill

This skill enables reverse engineering workflows using Ghidra through the Model Context Protocol (MCP).

## Quick Start

1. **List available programs**: `list_programs` to see what's loaded
2. **Read functions**: `read_functions` with filtering to find targets
3. **Decompile**: `decompile_code` to see source-like output
4. **Analyze references**: `find_references` to trace data/code flow

## Core Workflows

### Analyzing a New Binary

1. Use `list_programs` to confirm the binary is loaded
2. Use `read_functions` to get an overview of functions
3. Use `decompile_code` on interesting functions (like `main` or entry points)
4. Use `find_references` to understand how functions/data are used
5. Use `manage_symbols` to rename functions and variables as you understand them

### Understanding a Function

1. `read_functions` with `name` or `address` to get function metadata
2. `decompile_code` with `operation: decompile` to see decompiled C code
3. `manage_functions` with `operation: get_variables` to see local variables
4. `manage_functions` with `operation: get_graph` to see control flow
5. `find_references` with `direction: to` to find callers

### Defining Data Structures

1. `read_data_types` to check existing types
2. `manage_data_types` with `operation: create` and `type_kind: struct` to create structures
3. Add fields with proper offsets and types
4. Use `manage_data_types` with `operation: update` to modify existing types

### Searching for Patterns

1. `search_memory` with `search_type: string` for string literals
2. `search_memory` with `search_type: bytes` for byte patterns
3. `search_memory` with `search_type: regex` for complex patterns
4. Follow up with `find_references` on interesting addresses

### Bulk Operations

Use `batch_operations` to execute multiple changes atomically:
- Rename multiple symbols
- Create multiple data types
- All operations succeed or all are rolled back

## Tool Categories

### Read Operations (No Modifications)
| Tool | Purpose |
|------|---------|
| `list_programs` | List all programs in the project |
| `read_functions` | Read function details or list functions |
| `read_symbols` | Read symbol details or list symbols |
| `read_data_types` | Read data type details or list types |
| `read_memory_blocks` | List memory segments |
| `read_listing` | View disassembly at addresses |
| `decompile_code` | Decompile functions to C-like code |
| `find_references` | Find cross-references to/from addresses |
| `search_memory` | Search for strings, bytes, patterns |
| `list_analysis_options` | View analysis configuration |

### Write Operations (Modify Program)
| Tool | Purpose |
|------|---------|
| `manage_functions` | Create functions, update prototypes |
| `manage_symbols` | Create/rename labels and symbols |
| `manage_data_types` | Create/update structs, enums, unions |
| `manage_memory` | Read/write bytes, undefine code |
| `manage_project` | Bookmarks, navigation, metadata |

### Delete Operations
| Tool | Purpose |
|------|---------|
| `delete_function` | Remove function definitions |
| `delete_symbol` | Remove symbols/labels |
| `delete_data_type` | Remove data types |
| `delete_bookmark` | Remove bookmarks |

### Utility Operations
| Tool | Purpose |
|------|---------|
| `batch_operations` | Execute multiple operations atomically |
| `undo_redo` | Undo/redo changes |
| `demangle_symbol` | Demangle C++ symbols |
| `analyze_rtti` | Analyze MSVC RTTI structures |

## Common Patterns

### Pagination
Most list operations return paginated results. Use the `cursor` field from the response to get the next page:
```json
{"operation": "list", "cursor": "returned_cursor_value"}
```

### Identifying Targets
Tools accept multiple ways to identify targets:
- **By address**: `"address": "0x401000"`
- **By name**: `"name": "main"`
- **By ID**: `"symbol_id": 12345` or `"function_id": "0x401000"`

### Address Formats
Addresses can be specified as:
- Hex with prefix: `"0x401000"`
- Hex without prefix: `"401000"`
- Decimal: `"4198400"`

## Tips

1. **Start broad, then narrow**: Use list operations first, then read specific items
2. **Use filtering**: Most list operations support `name_filter` with wildcards
3. **Check before modifying**: Read the current state before making changes
4. **Use batch for related changes**: Group related modifications in `batch_operations`
5. **Undo mistakes**: Use `undo_redo` if something goes wrong

## Reference

See [references/TOOLS.md](references/TOOLS.md) for detailed documentation of each tool's operations and parameters.
