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
5. Use `memory` with `action: "map_data_type"` to apply the type at an address and inspect the bounded byte-to-field mapping

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
| `memory` | List/search memory, read/write bytes, and map data types |
| `inspect` | Listing, decompile, and references |
| `analyze` | Demangle, RTTI, graph, and call graph |
| `debugger` | Trace RMI connect/launch, target control, trace model discovery, memory/register/watch operations, mappings, remote methods, emulation, and navigation |
| `project` | Analysis options, analysis run, save, navigation, image-base rebasing, undo/redo |

### Write Operations (Modify Program)
| Tool | Purpose |
|------|---------|
| `functions` | Create functions, update prototypes, rename/retype variables |
| `symbols` | Create/rename labels and symbols |
| `data_types` | Create/update structs, enums, unions |
| `memory` | Write bytes, undefine code, apply/map data types, apply vtables |
| `annotate` | Comments and bookmarks |
| `debugger` | Connect/launch debuggers, control targets, write target or trace memory, apply mappings, manage breakpoints/watchpoints, write registers, update watches, and run emulation |

### Delete Operations
| Tool | Purpose |
|------|---------|
| `delete` | Remove functions, symbols, data types, or bookmarks |

### Utility Operations
| Tool | Purpose |
|------|---------|
| `batch_operations` | Execute multiple operations atomically |
| `project` | Rebase image bases and undo/redo changes |
| `analyze` | Demangle symbols and analyze RTTI |

### Debugger Control
Use `debugger` for the full Ghidra debugger lifecycle. Start with
`{"action": "status"}` and `{"action": "list_connections"}` to see whether a
trace/target is already active. If not, use `list_launchers` with `file_name`,
then `launch` with the selected `launcher_index` or `launcher_name`.

After launch or attach, use `list_traces`, `list_targets`, `activate_trace`,
`activate_target`, `list_threads`, `list_stack`, `list_snapshots`, and
`list_objects` to discover the trace model, then `activate_thread`,
`activate_frame`, `activate_snap`, `activate_time`, or `activate_object` to
select the active debugger context. Use `list_modules`, `list_sections`, or
`list_memory_regions` followed by `apply_mapping` with `mapping_kind: "module"`,
`"section"`, or `"region"` and `file_name` to map the running target back to the
static analyzed Program.

Prefer structured actions such as `resume`, `interrupt`, `step_over`,
`detach`, `kill`, `read_memory`, `write_memory`, `set_breakpoint`,
`set_watchpoint`, `read_registers`, `list_watches`, and `map_data_type`; use
`execute` for raw debugger-console commands. Use `list_remote_methods` and
`invoke_remote_method` when the Trace RMI backend exposes a capability that does
not yet have a structured action.

Use `read_memory` for live target bytes; it refreshes the trace from the target
by default when a live target is selected. Use `read_trace_bytes` and
`write_trace_bytes` only when you intentionally want cached trace bytes without
touching the target. Use `get_memory_state`/`set_memory_state` to reason about
known, unknown, or error byte state.

`debugger.map_data_type` applies a data type in the current trace view and
returns a bounded byte-to-field mapping. `list_registers`, `read_registers`, and
`list_watches` use `max_registers`/`max_watches` plus `next_cursor` pagination.
Broad debugger discovery actions use `page_size` plus `next_cursor`.

## Common Patterns

### Pagination
Most broad read operations are intentionally bounded. Start with an explicit limit
such as `page_size`, `max_lines`, or `max_results`, then pass the response
`next_cursor` back as `cursor` to get the next page. Keep the same filters and
target arguments while paging.
```json
{"action": "list", "page_size": 50, "cursor": "returned_next_cursor_value"}
```

### UI Synchronization
Focused CodeBrowser operations also update the user's active Ghidra UI when the
server is running inside a tool with navigation services. `inspect.decompile`,
`inspect.listing`, `functions.get`, `functions.create`, `functions.update_prototype`,
`memory.define`, `memory.map_data_type`, `project.go_to_address`, and focused
`debugger` actions navigate to the resolved function or address automatically;
the structured response payload stays unchanged.

### Identifying Targets
Tools accept multiple ways to identify targets:
- **By address**: `"address": "0x401000"`
- **By name**: `"name": "main"`
- **By ID**: `"symbol_id": 12345` or `"variable_symbol_id": "12345"`

### Address Formats
Addresses can be specified as:
- Hex with prefix: `"0x401000"`
- Hex without prefix: `"401000"`
- Image-base-relative offset: `"+0x401000"` or `"+401000"`
- Module-prefixed image-base-relative offset: `"NewWorld+0x401000"`

## Tips

1. **Start broad, then narrow**: Use list operations first, then read specific items
2. **Use filtering**: Most list operations support `name_pattern` regex filters
3. **Check before modifying**: Read the current state before making changes
4. **Use batch for related changes**: Group related modifications in `batch_operations`
5. **Undo mistakes**: Use `project` with `action: "undo"` if something goes wrong

## Reference

See [references/TOOLS.md](references/TOOLS.md) for detailed documentation of each tool's operations and parameters.
