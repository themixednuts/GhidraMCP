# Cursor Formats

This project treats cursors as strict, opaque tokens. Callers should copy the
returned `next_cursor` value back into the next request's `cursor` parameter;
do not synthesize cursor values from the formats below.

## Opaque V1 Format

- Prefix: `v1`
- Segment separator: `:`
- Payload segments: Base64 URL-safe encoding without padding

General form:

`v1:<segment_1>:<segment_2>[:<segment_n>]`

## Tool Cursor Contracts

- `symbols` (`action=list`)
  - `v1:<base64url_symbol_id>`
- `functions` (`action=list`)
  - `v1:<base64url_symbol_id>`
- `data_types` (`action=list`)
  - `v1:<base64url_data_type_name>:<base64url_data_type_path>`
- `functions` (`action=list_variables`)
  - `v1:<base64url_variable_symbol_id>`
- `memory` (`action=list_blocks`)
  - `v1:<base64url_block_start_address>`
- `memory` (`action=search`)
  - `v1:<base64url_match_address>`
- `memory` (`action=map_data_type`)
  - `v1:<base64url_typed_field_offset>`
- `debugger` (`action=map_data_type`)
  - `v1:<base64url_typed_field_offset>`
- `debugger` (`action=list_registers` / `action=read_registers`)
  - `v1:<base64url_register_offset>`
- `debugger` (`action=list_watches`)
  - `v1:<base64url_watch_offset>`
- `debugger` (`action=list_launchers`)
  - `v1:<base64url_launcher_offset>`
- `debugger` (`action=list_traces`)
  - `v1:<base64url_trace_offset>`
- `debugger` (`action=list_targets`)
  - `v1:<base64url_target_offset>`
- `debugger` (`action=list_modules`)
  - `v1:<base64url_module_offset>`
- `debugger` (`action=list_sections`)
  - `v1:<base64url_section_offset>`
- `debugger` (`action=list_memory_regions`)
  - `v1:<base64url_memory_region_offset>`
- `debugger` (`action=list_threads`)
  - `v1:<base64url_thread_offset>`
- `debugger` (`action=list_stack`)
  - `v1:<base64url_stack_frame_offset>`
- `debugger` (`action=list_snapshots`)
  - `v1:<base64url_snapshot_offset>`
- `debugger` (`action=list_objects`)
  - `v1:<base64url_object_offset>`
- `debugger` (`action=get_object`)
  - `v1:<base64url_object_value_offset>`
- `debugger` (`action=list_mapped_views`)
  - `v1:<base64url_mapped_view_offset>`
- `debugger` (`action=list_platforms`)
  - `v1:<base64url_platform_offset>`
- `debugger` (`action=list_remote_methods`)
  - `v1:<base64url_remote_method_offset>`
- `debugger` (`action=list_emulator_factories`)
  - `v1:<base64url_emulator_factory_offset>`
- `debugger` (`action=list_tracking_specs`)
  - `v1:<base64url_tracking_spec_offset>`
- `inspect` (`action=listing`)
  - `v1:<base64url_listing_address>`
- `project` (`action=list_analysis_options`)
  - `v1:<base64url_option_name>`
- `vt_operations` (`action=list_matches`)
  - `v1:<base64url_match_set_index>:<base64url_match_index>`
- `inspect` (`action=references_to` / `action=references_from`)
  - `v1:<base64url_primary_address>:<base64url_secondary_address>:<base64url_reference_type>`
- `annotate` (`action=list_bookmarks`)
  - `v1:<base64url_bookmark_address>`
- `analyze` (`action=list_rtti`)
  - `v1:<base64url_result_index>`

## Validation Rules

- Cursors must match expected segment count and version.
- Decoded segments must be non-blank.
- Tool-specific fields must also pass semantic validation (e.g., address decodes to a valid Ghidra address).
- Invalid or stale cursors return a validation error; cursors do not silently reset pagination.

## Implementation

Shared encoding/decoding is implemented in `src/main/java/com/themixednuts/utils/OpaqueCursorCodec.java`.
