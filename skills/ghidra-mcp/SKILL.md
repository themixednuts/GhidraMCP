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

1. **List available programs**: read the `ghidra://programs` resource
2. **Read functions**: use `functions` with `action: "list"` and filters to find targets
3. **Decompile**: use `inspect` with `action: "decompile"` for C-like output
4. **Analyze references**: use `inspect` with `action: "references_to"` or `"references_from"`

## Core Workflows

### Analyzing a New Binary

1. Read `ghidra://programs` to confirm the binary is loaded
2. Use `functions` with `action: "list"` to get compact function rows
3. Use `inspect` with `action: "decompile"` on interesting functions
4. Use `inspect` reference actions to understand how functions/data are used
5. Use `symbols` / `functions` update actions to rename symbols and variables

### Understanding a Function

1. `functions` with `action: "get"` and `name`, `address`, or `symbol_id`
2. `inspect` with `action: "decompile"` to see decompiled C code
3. `functions` with `action: "list_variables"` to see stable variable targets
4. `analyze` with `action: "graph"` to see control flow
5. `inspect` with `action: "references_to"` to find callers

### Defining Data Structures

1. `data_types` with `action: "list"` to check existing types
2. `data_types` with `action: "create"` and `data_type_kind: "struct"` to create structures
3. Add fields with proper offsets and types
4. Use `data_types` with `action: "update"` to modify existing types

### Searching for Patterns

1. `memory` with `action: "search"` and `search_type: "string"` for string literals
2. `memory` with `action: "search"` and `search_type: "hex"` for byte patterns
3. `memory` with `action: "search"` and `search_type: "regex"` for complex patterns
4. Follow up with `inspect` reference actions on interesting addresses

### Bulk Operations

Use `batch_operations` to execute multiple changes atomically:
- Rename multiple symbols
- Create multiple data types
- All operations succeed or all are rolled back

## Tool Categories

### Read Operations (No Modifications)
| Tool | Purpose |
|------|---------|
| `ghidra://programs` | List all programs in the project |
| `functions` | List/get/create/update functions and variables |
| `symbols` | List/get/create/update symbols, labels, namespaces, classes |
| `data_types` | List/get/create/update data types |
| `memory` | List blocks, search memory, read/write bytes |
| `inspect` | Listing, decompile, and references |
| `analyze` | Demangle, RTTI, graph, and call graph |
| `project` | Analysis options, analysis run, save, navigation, undo/redo |

### Write Operations (Modify Program)
| Tool | Purpose |
|------|---------|
| `functions` | Create functions, update prototypes, rename/retype variables |
| `symbols` | Create/rename labels and symbols |
| `data_types` | Create/update structs, enums, unions |
| `memory` | Write bytes, undefine code, apply vtables |
| `annotate` | Comments and bookmarks |

### Delete Operations
| Tool | Purpose |
|------|---------|
| `delete` | Remove functions, symbols, data types, or bookmarks |

### Utility Operations
| Tool | Purpose |
|------|---------|
| `batch_operations` | Execute multiple operations atomically |
| `project` | Undo/redo changes |
| `analyze` | Demangle symbols and analyze RTTI |

## Common Patterns

### Pagination
Most list operations return paginated results. Pass the response `next_cursor` back as `cursor` to get the next page:
```json
{"action": "list", "cursor": "returned_next_cursor_value"}
```

### Identifying Targets
Tools accept multiple ways to identify targets:
- **By address**: `"address": "0x401000"`
- **By name**: `"name": "main"`
- **By ID**: `"symbol_id": 12345` or `"variable_symbol_id": "12345"`

### Address Formats
Addresses can be specified as:
- Hex with prefix: `"0x401000"`
- Hex without prefix: `"401000"`
- Decimal: `"4198400"`

## Tips

1. **Start broad, then narrow**: Use list operations first, then read specific items
2. **Use filtering**: Most list operations support `name_pattern` regex filters
3. **Check before modifying**: Read the current state before making changes
4. **Use batch for related changes**: Group related modifications in `batch_operations`
5. **Undo mistakes**: Use `project` with `action: "undo"` if something goes wrong

## Reference

See [references/TOOLS.md](references/TOOLS.md) for detailed documentation of each tool's operations and parameters.
