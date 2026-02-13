# Cursor Formats

This project now treats cursors as strict, opaque tokens.

## Opaque V1 Format

- Prefix: `v1`
- Segment separator: `:`
- Payload segments: Base64 URL-safe encoding without padding

General form:

`v1:<segment_1>:<segment_2>[:<segment_n>]`

## Tool Cursor Contracts

- `read_symbols`
  - `v1:<base64url_symbol_name>:<base64url_address>`
- `read_functions`
  - `v1:<base64url_address>:<base64url_function_name>`
- `read_data_types`
  - `v1:<base64url_data_type_name>:<base64url_data_type_path>`
- `manage_functions` (`action=list_variables`)
  - `v1:<base64url_storage>:<base64url_variable_name>`
- `list_programs`
  - `v1:<base64url_program_path>`
- `read_memory_blocks`
  - `v1:<base64url_block_start_address>`
- `read_listing`
  - `v1:<base64url_listing_address>`
- `list_analysis_options`
  - `v1:<base64url_option_name>`
- `read_vt_matches`
  - `v1:<base64url_match_set_index>:<base64url_match_index>`
- `find_references`
  - `v1:<base64url_primary_address>:<base64url_secondary_address>:<base64url_reference_type>`
- `read_tool_output` (`action=list_sessions` / `action=list_outputs`)
  - `v1:<base64url_store_cursor_key>`

## Validation Rules

- Cursors must match expected segment count and version.
- Decoded segments must be non-blank.
- Tool-specific fields must also pass semantic validation (e.g., address decodes to a valid Ghidra address).
- Invalid or stale cursors return a validation error; cursors do not silently reset pagination.

## Implementation

Shared encoding/decoding is implemented in `src/main/java/com/themixednuts/utils/OpaqueCursorCodec.java`.
