# GhidraMCP Tools Reference

Complete reference for all GhidraMCP tools. Each tool is documented with its operations, parameters, and examples.

## Common Parameters

Most tools accept these common parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `file_name` | string | Program file name (required for most tools) |
| `page_size` | integer | Results per page for list/search/discovery operations, including debugger launcher/trace/target/module/thread/object/platform lists; use the returned `next_cursor` as the next request's `cursor` |
| `max_lines` | integer | Maximum listing lines for `inspect` `action: "listing"` |
| `max_results` | integer | Tool-specific maximum result count, or an alias for `page_size` where documented |
| `max_fields` | integer | Maximum typed fields/components for `memory.map_data_type` and `debugger.map_data_type` |
| `max_registers` | integer | Maximum register rows for `debugger.list_registers` and `debugger.read_registers` |
| `max_watches` | integer | Maximum watch rows for `debugger.list_watches` |
| `cursor` | string | Opaque pagination token copied from the previous response's `next_cursor`; keep filters and target args unchanged while paging |

## Pagination and Output Limits

There is no output replay tool. Large responses should be requested in bounded
chunks with `page_size`, `max_lines`, or `max_results`. If a response contains
`next_cursor`, call the same tool again with the same filters and pass that value
as `cursor`. Stop when `next_cursor` is absent.

## Read Tools

### debugger

Inspect and control the active Ghidra Debugger trace/target.

**Modes:**
- **Trace RMI lifecycle**: `start_server`, `stop_server`, `connect`, `accept`, `list_connections`
- **Launcher and target lifecycle**: `list_launchers`, `launch`, `attach`, `detach`, `kill`, `disconnect`, `close_connection`, `close_trace`, `save_trace`
- **Context discovery/selection**: `list_traces`, `list_targets`, `list_threads`, `list_stack`, `list_snapshots`, `list_objects`, `get_object`, `activate_trace`, `activate_target`, `activate_thread`, `activate_snap`, `activate_time`, `activate_frame`, `activate_object`, `list_platforms`, `activate_platform`
- **Static mappings**: `list_modules`, `list_sections`, `list_memory_regions`, `propose_mapping`, `apply_mapping`, `add_identity_mapping`, `map_dynamic_to_static`, `map_static_to_dynamic`, `find_best_module_program`, `open_mapped_programs`, `list_mapped_views`
- **Status**: `action: "status"` reports current trace, target, thread, snap, frame, and state
- **Execution/control mode**: `resume`, `interrupt`, `step_into`, `step_over`, `step_out`, `step_skip`, `step_back`, `get_control_mode`, `set_control_mode`
- **Command and backend methods**: `execute`, `list_remote_methods`, `invoke_remote_method`
- **Memory**: `read_memory`, `refresh_memory`, `write_memory`, `invalidate_memory_cache`, `read_trace_bytes`, `write_trace_bytes`, `get_memory_state`, `set_memory_state`
- **Breakpoints**: `set_breakpoint`, `set_static_breakpoint`, `set_watchpoint`, `list_supported_breakpoint_kinds`, `list_breakpoints`, `enable_breakpoint`, `disable_breakpoint`, `delete_breakpoint`
- **Registers**: `list_registers`, `read_registers`, `write_register`
- **Watches**: `list_watches`, `add_watch`, `update_watch`, `remove_watch`
- **Emulation**: `list_emulator_factories`, `set_emulator_factory`, `launch_emulator`, `emulate`, `run_emulation`, `list_busy_emulators`, `invalidate_emulator_cache`
- **Typed memory**: `map_data_type` applies a data type in the current trace view and returns bounded field/byte rows
- **Navigation/UI**: `go_to_address`, `select_range`, `list_tracking_specs`, `set_tracking_spec`

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | Debugger operation |
| `file_name` | string | Static Program file name for launchers and static mapping actions |
| `command` | string | Raw target command for `execute` |
| `address` | string | Trace/view address for memory, breakpoints, typed memory, mapping, and navigation |
| `address_end` | string | Optional inclusive end address for selection and mapped-view queries |
| `static_address` | string | Static Program address for address mappings and static-to-dynamic lookup |
| `bytes_hex` | string | Hex bytes for `write_memory` or `write_trace_bytes` |
| `memory_state` | string | `unknown`, `known`, or `error` for `set_memory_state` |
| `host` | string | Trace RMI host for `start_server`, `connect`, or `accept` |
| `port` | integer | Trace RMI port for `start_server`, `connect`, or `accept` |
| `wait` | boolean | For `accept`, wait for one inbound connection before returning |
| `connection_index` | integer | Zero-based Trace RMI connection index from `list_connections` |
| `launcher_index` | integer | Zero-based launcher index from `list_launchers` |
| `launcher_name` | string | Launcher config name or title from `list_launchers` |
| `launch_arguments` | object | Launcher parameter values keyed by parameter name |
| `trace_index` | integer | Zero-based trace index from `list_traces` |
| `trace_name` | string | Trace name for `activate_trace` |
| `target_index` | integer | Zero-based target index from `list_targets` |
| `thread_key` | integer | Thread key for `activate_thread` |
| `thread_path` | string | Thread path for `activate_thread` |
| `object_path` | string | Canonical trace object path for object activation, object reads, platform mapping, or remote method object args |
| `time` | string | Ghidra trace schedule string for `activate_time`, `emulate`, or `run_emulation` |
| `platform_index` | integer | Zero-based platform index from `list_platforms` |
| `snap` | integer | Trace snap for activation and mapping; defaults to current snap |
| `frame` | integer | Stack frame index for `activate_frame` |
| `module_name` | string | Loaded trace module name for module mappings |
| `module_path` | string | Loaded trace module path for module mappings |
| `section_name` / `section_path` | string | Loaded trace section selector for section-oriented workflows |
| `region_name` / `region_path` | string | Trace memory region selector for region mapping |
| `mapping_kind` | string | `module`, `section`, `region`, `address`, or `identity`; default `module` for mapping actions |
| `truncate_existing` | boolean | Allow static mapping additions to truncate conflicting mappings |
| `memorize` | boolean | For module mappings, memorize the accepted module-program association |
| `control_mode` | string | `ro_target`, `rw_target`, `ro_trace`, `rw_trace`, or `rw_emulator` |
| `data_type_path` | string | Data type path for `map_data_type` or watch type updates |
| `data_type_id` | integer | Data type ID alternative to `data_type_path` |
| `max_fields` | integer | Maximum typed fields for `map_data_type`; use `next_cursor` to continue |
| `register_name` | string | Register name for `write_register` |
| `register_names` | array | Optional register names for `read_registers` |
| `max_registers` | integer | Maximum register rows for `list_registers`/`read_registers` |
| `expression` | string | Watch expression for `add_watch`/`update_watch` |
| `watch_index` | integer | Zero-based watch index from `list_watches` |
| `max_watches` | integer | Maximum watch rows for `list_watches` |
| `max_values` | integer | Maximum object values for `get_object` |
| `method_name` | string | Trace RMI remote method name for `invoke_remote_method` |
| `method_arguments` | object | Remote method arguments keyed by parameter name |
| `tracking_spec` | string | Tracking spec config name from `list_tracking_specs` |
| `emulator_index` / `emulator_name` | integer/string | Emulator factory selector from `list_emulator_factories` |
| `breakpoint_kinds` | array | `sw_execute`, `hw_execute`, `read`, `write`, or `access`; default `sw_execute` |
| `length` | integer | Length in bytes for memory/range/breakpoint actions |
| `timeout_ms` | integer | Timeout for target futures; default `10000` |

**Examples:**
```json
{"action": "status"}
{"action": "list_launchers", "file_name": "prog.exe"}
{"action": "launch", "file_name": "prog.exe", "launcher_index": 0}
{"action": "list_modules"}
{"action": "apply_mapping", "file_name": "prog.exe", "mapping_kind": "module", "module_name": "prog.exe"}
{"action": "read_memory", "address": "0x140001000", "length": 64}
{"action": "step_over"}
{"action": "set_watchpoint", "address": "0x140020000", "length": 4}
{"action": "read_registers", "register_names": ["RIP", "RSP"], "refresh": true}
{"action": "list_threads", "page_size": 64}
{"action": "list_remote_methods", "name_pattern": "attach|detach|refresh"}
{"action": "list_emulator_factories"}
{"action": "map_data_type", "address": "+0x1234", "data_type_path": "/PacketHeader", "max_fields": 128}
```

---

### functions

List/get/create/update functions and variables. Use `action: "list"` for compact rows and `action: "get"` for details.

**Modes:**
- **Single read**: `action: "get"` plus `symbol_id`, `address`, or `name`
- **List mode**: `action: "list"` to list compact rows with `symbol_id`

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `symbol_id` | integer | Function's symbol ID |
| `address` | string | Function entry point address |
| `name` | string | Function name (exact match) |
| `name_pattern` | string | Regex pattern for filtering (list mode) |

**Examples:**
```json
// Read by address
{"file_name": "prog.exe", "action": "get", "address": "0x401000"}

// Read by name
{"file_name": "prog.exe", "action": "get", "name": "main"}

// List with filter
{"file_name": "prog.exe", "action": "list", "name_pattern": ".*crypt.*"}
```

---

### symbols

List/get/create/update symbols, labels, namespaces, and classes. List rows are compact and include `symbol_id` for follow-up calls.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `symbol_id` | integer | Symbol ID |
| `address` | string | Symbol address |
| `name` | string | Symbol name |
| `name_pattern` | string | Regex pattern for filtering |
| `symbol_type` | string | Filter by type: `function`, `label`, `class`, etc. |

**Examples:**
```json
// Read specific symbol
{"file_name": "prog.exe", "action": "get", "name": "g_GlobalVar"}

// List labels only
{"file_name": "prog.exe", "action": "list", "symbol_type": "LABEL"}
```

---

### data_types

List/get/create/update data types.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `data_type_id` | integer | Data type ID |
| `data_type_path` | string | Full path (e.g., `/MyCategory/MyStruct`) |
| `name_pattern` | string | Regex pattern for filtering |
| `category_path` | string | Filter by category |
| `type_kind` | string | `struct`, `enum`, `union`, `typedef`, `pointer` |

**Examples:**
```json
// Read specific struct
{"file_name": "prog.exe", "action": "get", "data_type_path": "/MyCategory/MyStruct"}

// List all enums
{"file_name": "prog.exe", "action": "list", "type_kind": "enum"}
```

---

### memory

List blocks, search memory, read/write bytes, undefine code, apply vtables, and map data types.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | `list_blocks`, `search`, `read`, `write`, `define`, `map_data_type`, `undefine`, or `apply_vtable` |
| `address` | string | Target address for read/write/define/map/undefine/apply_vtable |
| `data_type_path` | string | Data type path for `define` or `map_data_type` |
| `data_type_id` | integer | Data type ID alternative to `data_type_path` |
| `max_fields` | integer | Maximum typed fields/components for `map_data_type`; use `next_cursor` to continue |
| `name_pattern` | string | Filter by block name |
| `permissions` | string | Filter by permissions (e.g., `rwx`, `r-x`) |

**Example:**
```json
{"file_name": "prog.exe", "action": "list_blocks", "executable": true}
{"file_name": "prog.exe", "action": "map_data_type", "address": "+0x1234", "data_type_path": "/PacketHeader", "max_fields": 128}
```

---

### inspect

View listing/disassembly, decompile functions, and find references.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `address` | string | Start address |
| `end_address` | string | End address (for range) |
| `name` | string | Show listing/decompile for a function |
| `max_lines` | integer | Maximum listing lines to return; pass returned `next_cursor` as `cursor` to continue |

**Examples:**
```json
// View at address
{"file_name": "prog.exe", "action": "listing", "address": "0x401000", "max_lines": 50}

// View entire function
{"file_name": "prog.exe", "action": "listing", "name": "main"}
```

---

### ghidra://programs

Resource URI that lists all programs in the Ghidra project.

**Parameters:** None required.

**Example:**
```json
{}
```

---

### project

Project-level operations including analysis options, analysis runs, save, navigation, image-base rebasing, and undo/redo.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | `list_analysis_options`, `run_analysis`, `save`, `go_to_address`, `rebase`, `undo`, `redo`, or `history` |
| `address` | string | Target address for `go_to_address` |
| `image_base` | string | Explicit absolute image base for `rebase`, e.g. `0x140000000` |
| `use_stated_image_base` | boolean | For `rebase`, use the PE optional-header ImageBase from the original executable path |
| `filter` | string | Filter options by name pattern |

**Examples:**
```json
{"file_name": "prog.exe", "action": "rebase", "image_base": "0x140000000"}
{"file_name": "prog.exe", "action": "rebase", "use_stated_image_base": true}
```

---

## Analysis Tools

### inspect decompile

Decompile functions to C-like pseudocode.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | `decompile` |
| `name` | string | Function name |
| `address` | string | Function entry address |
| `include_pcode` | boolean | Include P-code IR (default: false) |
| `include_ast` | boolean | Include AST info (default: false) |
| `timeout` | integer | Timeout in seconds (5-300, default: 30) |
| `analysis_level` | string | `basic`, `standard`, `advanced` |

**Examples:**
```json
// Decompile by name
{
  "file_name": "prog.exe",
  "action": "decompile",
  "name": "main"
}

// Decompile with P-code
{
  "file_name": "prog.exe",
  "action": "decompile",
  "name": "decrypt",
  "include_pcode": true
}
```

---

### inspect references

Find cross-references to/from addresses.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `address` | string | Target address |
| `action` | string | `references_to` or `references_from` |

**Example:**
```json
{
  "file_name": "prog.exe",
  "action": "references_to",
  "address": "0x401000"
}
```

---

### memory search

Search program memory for patterns.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `search_type` | string | `string`, `hex`, `binary`, `decimal`, `float`, `double`, `regex` |
| `search_value` | string | Pattern to search for |
| `case_sensitive` | boolean | Case sensitivity (default: false) |
| `max_results` | integer | Max matches to return; use `page_size` for new calls and pass returned `next_cursor` as `cursor` to continue |

**Examples:**
```json
// String search
{
  "file_name": "prog.exe",
  "action": "search",
  "search_type": "string",
  "search_value": "password"
}

// Hex pattern
{
  "file_name": "prog.exe",
  "action": "search",
  "search_type": "hex",
  "search_value": "90 90 90 E8"
}

// Regex search
{
  "file_name": "prog.exe",
  "action": "search",
  "search_type": "regex",
  "search_value": "https?://[^\\s]+"
}
```

---

### analyze rtti

Analyze Microsoft RTTI structures.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `address` | string | Address of RTTI structure |

**Example:**
```json
{"file_name": "prog.exe", "action": "rtti", "address": "0x140005000"}
```

---

### analyze demangle

Demangle C++ mangled names.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `mangled_symbol` | string | The mangled symbol name |

**Example:**
```json
{"file_name": "prog.exe", "action": "demangle", "mangled_symbol": "_ZN4test3fooEv"}
```

---

## Write Tools

### functions

Create functions and update prototypes.

**Actions:**
- `create` - Create function at address
- `update_prototype` - Update function signature
- `list_variables` - List function variables

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | Operation to perform |
| `address` | string | Function address |
| `name` | string | Function name |
| `symbol_id` | integer | Function symbol ID |
| `prototype` | string | Function signature (for update) |

**Examples:**
```json
// Create function
{
  "file_name": "prog.exe",
  "action": "create",
  "address": "0x401000",
  "name": "decrypt_data"
}

// Update prototype
{
  "file_name": "prog.exe",
  "action": "update_prototype",
  "name": "process_data",
  "prototype": "int process_data(char *buf, int len)"
}

// Get variables
{
  "file_name": "prog.exe",
  "action": "list_variables",
  "name": "main"
}

```

---

### symbols

Create and update symbols/labels.

**Actions:**
- `create` - Create new symbol/label
- `update` - Rename or modify symbol

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | `create` or `update` |
| `address` | string | Symbol address |
| `name` | string | Symbol name |
| `symbol_id` | integer | Symbol ID (for update) |
| `new_name` | string | New name (for rename) |
| `namespace` | string | Namespace path |

**Examples:**
```json
// Create label
{
  "file_name": "prog.exe",
  "action": "create",
  "address": "0x401000",
  "name": "entry_point"
}

// Rename symbol
{
  "file_name": "prog.exe",
  "action": "update",
  "symbol_id": 12345,
  "new_name": "better_name"
}
```

---

### data_types

Create and update data types.

**Actions:**
- `create` - Create new data type
- `update` - Update existing data type (preserves references)

**Data Type Kinds:**
- `struct` - Structure with fields
- `enum` - Enumeration
- `union` - Union type
- `typedef` - Type alias
- `pointer` - Pointer type
- `function_definition` - Function signature type
- `category` - Data type category/folder

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | `create` or `update` |
| `data_type_kind` | string | Type of data type |
| `name` | string | Data type name |
| `category_path` | string | Category path (default: `/`) |
| `members` | array | Struct/union members |
| `entries` | array | Enum entries |
| `base_type` | string | Base type for typedef/pointer |

**Member Object:**
```json
{
  "name": "field_name",
  "data_type_path": "int",  // or use data_type_id
  "data_type_id": 12345,    // alternative to path
  "offset": 0,              // optional, for explicit layout
  "comment": "description"  // optional
}
```

**Examples:**
```json
// Create struct
{
  "file_name": "prog.exe",
  "action": "create",
  "data_type_kind": "struct",
  "name": "PacketHeader",
  "category_path": "/Network",
  "members": [
    {"name": "magic", "data_type_path": "uint"},
    {"name": "size", "data_type_path": "uint"},
    {"name": "flags", "data_type_path": "byte"}
  ]
}

// Create enum
{
  "file_name": "prog.exe",
  "action": "create",
  "data_type_kind": "enum",
  "name": "ErrorCode",
  "entries": [
    {"name": "SUCCESS", "value": 0},
    {"name": "ERROR", "value": 1},
    {"name": "INVALID", "value": -1}
  ]
}

// Update struct (preserves references)
{
  "file_name": "prog.exe",
  "action": "update",
  "data_type_kind": "struct",
  "name": "PacketHeader",
  "category_path": "/Network",
  "members": [
    {"name": "magic", "data_type_path": "uint"},
    {"name": "version", "data_type_path": "ushort"},
    {"name": "size", "data_type_path": "uint"},
    {"name": "flags", "data_type_path": "byte"}
  ]
}
```

---

### memory

Memory read/write operations.

**Actions:**
- `read_bytes` - Read bytes from address
- `write_bytes` - Write bytes to address
- `define` - Apply a data type at address
- `map_data_type` - Apply a data type and return bounded byte-to-field rows
- `undefine` - Undefine code unit at address

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | Operation to perform |
| `address` | string | Target address |
| `length` | integer | Number of bytes (for read) |
| `bytes` | string | Hex bytes to write |
| `data_type_path` | string | Data type path for `define` or `map_data_type` |
| `data_type_id` | integer | Data type ID alternative to `data_type_path` |
| `max_fields` | integer | Maximum typed fields/components for `map_data_type` |

**Examples:**
```json
// Read bytes
{
  "file_name": "prog.exe",
  "action": "read_bytes",
  "address": "0x401000",
  "length": 16
}

// Write bytes
{
  "file_name": "prog.exe",
  "action": "write_bytes",
  "address": "0x401000",
  "bytes": "90 90 90 90"
}

// Apply a struct and inspect mapped fields
{
  "file_name": "prog.exe",
  "action": "map_data_type",
  "address": "0x401000",
  "data_type_path": "/PacketHeader",
  "max_fields": 128
}
```

---

### project / annotate

Project-level operations.

**Actions:**
- `go_to_address` - Navigate to address in Ghidra UI
- `rebase` - Set the program image base explicitly, or from the PE optional-header ImageBase
- `create_bookmark` - Create bookmark
- `get_info` - Get program metadata

**Examples:**
```json
// Navigate to address
{
  "file_name": "prog.exe",
  "action": "go_to_address",
  "address": "0x401000"
}

// Rebase to an explicit image base
{
  "file_name": "prog.exe",
  "action": "rebase",
  "image_base": "0x140000000"
}

// Rebase to the ImageBase stated in the original PE header
{
  "file_name": "prog.exe",
  "action": "rebase",
  "use_stated_image_base": true
}

// Create bookmark
{
  "file_name": "prog.exe",
  "action": "create_bookmark",
  "address": "0x401000",
  "category": "Analysis",
  "comment": "Interesting function"
}
```

---

## Delete Tools

### delete

Delete functions, symbols, data types, or bookmarks. Pass `action` as `function`, `symbol`, `data_type`, or `bookmark`.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `address` | string | Bookmark address |
| `type` | string | Filter by bookmark type |
| `category` | string | Filter by category |

---

## Utility Tools

### batch_operations

Execute multiple operations atomically.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `operations` | array | List of operations to execute |

Each operation is an object with:
- `tool` - Tool name to invoke
- `args` - Arguments for the tool

**Example:**
```json
{
  "file_name": "prog.exe",
  "operations": [
    {
      "tool": "symbols",
      "args": {
        "action": "update",
        "symbol_id": 123,
        "new_name": "init_system"
      }
    },
    {
      "tool": "symbols",
      "args": {
        "action": "update",
        "symbol_id": 456,
        "new_name": "cleanup_system"
      }
    }
  ]
}
```

---

### project undo/redo

Undo or redo changes.

**Actions:**
- `undo` - Undo last change
- `redo` - Redo last undone change
- `history` - Get undo/redo stack info

**Example:**
```json
{"file_name": "prog.exe", "action": "undo"}
```

---

## Response Format

Tool responses keep useful data in `structuredContent`; object payloads flatten into the response root, and list/string payloads use `data`.

**Success:**
```json
{
  "name": "main",
  "entry_point": "00401000"
}
```

**Success with pagination:**
```json
{
  "data": [ ... ],
  "next_cursor": "v1:..."
}
```

**Error:**
```json
{
  "message": "Error description",
  "hint": "Suggestion to fix"
}
```
