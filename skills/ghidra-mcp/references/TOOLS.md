# GhidraMCP Tools Reference

Complete reference for all GhidraMCP tools. Each tool is documented with its operations, parameters, and examples.

## Common Parameters

Most tools accept these common parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `file_name` | string | Program file name (required for most tools) |
| `cursor` | string | Pagination cursor from previous response |

## Read Tools

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

List blocks, search memory, read/write bytes, undefine code, and apply vtables.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `name_pattern` | string | Filter by block name |
| `permissions` | string | Filter by permissions (e.g., `rwx`, `r-x`) |

**Example:**
```json
{"file_name": "prog.exe", "action": "list_blocks", "executable": true}
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
| `max_lines` | integer | Limit number of listing lines |

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

Project-level operations including analysis options, analysis runs, save, navigation, and undo/redo.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `filter` | string | Filter options by name pattern |

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
| `max_results` | integer | Max results (default: 100, max: 1000) |

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
- `undefine` - Undefine code unit at address

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | Operation to perform |
| `address` | string | Target address |
| `length` | integer | Number of bytes (for read) |
| `bytes` | string | Hex bytes to write |

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
```

---

### project / annotate

Project-level operations.

**Actions:**
- `goto` - Navigate to address in Ghidra UI
- `create_bookmark` - Create bookmark
- `get_info` - Get program metadata

**Examples:**
```json
// Navigate to address
{
  "file_name": "prog.exe",
  "action": "goto",
  "address": "0x401000"
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
