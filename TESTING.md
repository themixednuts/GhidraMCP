# Ghidra MCP Tool Testing Status

This document tracks the manual testing status of individual Ghidra MCP tools.

## Test Environment

- MCP Server: Current Development Build
- Ghidra Version: 11.3.2
- Test Program: `NewWorld.exe`
- Date Tested: 2025-05-06

## Tested Read-Only Tools (Success)

The following read-only tools have been successfully tested against the live MCP server:

- **`list_open_files`** (`GhidraListOpenFilesTool`):
  - Successfully listed the open file (`NewWorld.exe`).
- **`list_function_names`** (`GhidraListFunctionNamesTool`):
  - Successfully listed the first page of functions from `NewWorld.exe`.
  - Returned a `next_cursor`.
- **`get_function`** (`GhidraGetFunctionTool`):
  - Successfully retrieved function `OPENSSL_cleanse` using its address (`140001240`).
  - Successfully retrieved function `OPENSSL_cleanse` using its name.
- **`decompile_function`** (`GhidraDecompileFunctionTool`):
  - Successfully retrieved C-like decompilation for function `OPENSSL_cleanse`.
- **`list_bookmarks`** (`GhidraListBookmarksTool`):
  - Successfully listed the first page of bookmarks from `NewWorld.exe`.
  - Successfully retrieved the second page of bookmarks using the `cursor` argument.
- **`get_symbol_in_function`** (`GhidraGetSymbolInFunctionTool`):
  - Successfully retrieved symbol `ptr` from function `OPENSSL_cleanse`.
- **`get_current_function`** (`GhidraGetCurrentFunctionTool`):
  - Successfully retrieved current function details (e.g., `CarrierThread::CarrierThread` at `14591db20`).
- **`get_function_prototype`** (`GhidraGetFunctionPrototypeTool`):
  - Successfully retrieved prototype for `OPENSSL_cleanse`.
- **`list_symbols_in_function`** (`GhidraListSymbolsInFunctionTool`):
  - Successfully listed symbols (parameters `len`, `ptr`) for `OPENSSL_cleanse`.
- **`search_functions_by_name`** (`GhidraSearchFunctionsByNameTool`):
  - Successfully searched for functions matching regex "OPENSSL" (using `regexPattern` argument).
  - Returned a `next_cursor`.
- **`get_function_containing_location`** (`GhidraGetFunctionContainingLocationTool`):
  - Successfully identified `OPENSSL_cleanse` as containing address `140001250`.
- **`get_pcode_for_function`** (`GhidraGetPcodeForFunctionTool`):
  - Successfully retrieved PCode for `OPENSSL_cleanse`.
- **`get_pcode_at_address`** (`GhidraGetPcodeAtAddressTool`):
  - Successfully retrieved PCode for instruction at `140001243`.
- **`list_data_types`** (`GhidraListDataTypesTool`):
  - Successfully listed data types and handled pagination.
  - Successfully filtered by `typeFilter: "enum"` and found `/WORK_STATE`.
  - Successfully filtered by `typeFilter: "structure"`.
  - Successfully filtered by `typeFilter: "pointer"`.
  - Successfully filtered by `typeFilter: "typedef"`.
  - Successfully filtered by `typeFilter: "function_definition"`.
  - Successfully filtered by `typeFilter: "basic"`.
- **`get_function_definition`** (`GhidraGetFunctionDefinitionTool`):
  - Successfully retrieved function definition for `/ClassDataTypes/AK/IAkPlugin/Bytes`.
- **`list_class_names`** (`GhidraListClassNamesTool`):
  - Successfully executed and returned an empty list (no classes defined).
- **`get_data_type_at_address`** (`GhidraGetDataTypeAtAddressTool`):
  - Successfully retrieved `undefined` for address `14a000000` (no specific data type defined there).
- **`list_categories`** (`GhidraListCategoriesTool`):
  - Successfully listed data type categories.
- **`get_typedef_definition`** (`GhidraGetTypeDefDefinitionTool`):
  - Successfully retrieved typedef definition for `/ClassDataTypes/AZ/u32`.
- **`get_struct_definition`** (`GhidraGetStructDefinitionTool`):
  - Successfully retrieved struct definition for `/BUF_MEM`.
- **`get_comment_at_address`** (`GhidraGetCommentAtAddressTool`):
  - Successfully retrieved empty EOL_COMMENT for `1400171e1`.
- **`get_defined_strings`** (`GhidraGetDefinedStringsTool`):
  - Successfully listed defined strings with pagination.
- **`get_symbol_at_address`** (`GhidraGetSymbolAtAddressTool`):
  - Successfully retrieved symbol `OPENSSL_cleanse` at `140001240`.
- **`list_all_symbols`** (`GhidraListAllSymbolsTool`):
  - Successfully listed symbols with pagination.
- **`list_namespaces`** (`GhidraListNamespacesTool`):
  - Successfully listed namespaces with pagination.
- **`get_basic_block_at_address`** (`GhidraGetBasicBlockAtAddressTool`):
  - Successfully retrieved basic block info for address `140001243`.
- **`get_xrefs_to_address`** (`GhidraGetXRefsToAddressTool`):
  - Successfully listed XRefs to `140001240` with pagination.
- **`get_xrefs_from_address`** (`GhidraGetXRefsFromAddressTool`):
  - Successfully returned empty list for XRefs from `140001240` (entry point instruction).
- **`search_memory`** (`GhidraSearchMemoryTool`):
  - Successfully searched for byte pattern `554889E5` with pagination.
- **`read_memory_bytes`** (`GhidraReadMemoryBytesTool`):
  - Successfully read 16 bytes from `140001240`.
- **`list_imports`** (`GhidraListImportsTool`):
  - Successfully listed imported functions with pagination.
- **`list_memory_segments`** (`GhidraListMemorySegmentsTool`):
  - Successfully listed memory segments.
- **`get_assembly_at_address`** (`GhidraGetAssemblyAtAddressTool`):
  - Successfully retrieved single assembly instruction at `140001240`.
- **`get_current_address`** (`GhidraGetCurrentAddressTool`):
  - Successfully retrieved current address `14591db20`.
- **`list_ghidra_scripts`** (`GhidraListScriptsTool`):
  - Successfully listed Ghidra scripts with pagination.
- **`get_current_program_info`** (`GhidraGetCurrentProgramInfoTool`):
  - Successfully retrieved info for `NewWorld.exe`.
- **`get_enum_definition`** (`GhidraGetEnumDefinitionTool`):
  - Successfully retrieved enum definition for `/WORK_STATE`.
- **`get_union_definition`** (`GhidraGetUnionDefinitionTool`):
  - Successfully retrieved union definition for `/ERR_CODES`.
- **`get_basic_block_predecessors`** (`GhidraGetBasicBlockPredecessorsTool`):
  - Successfully retrieved predecessor blocks for `140001243`.
- **`get_basic_block_successors`** (`GhidraGetBasicBlockSuccessorsTool`):
  - Successfully retrieved successor blocks for `140001240`.
- **`go_to_address`** (`GhidraGoToAddressTool`):
  - Successfully navigated to address `0x140001240` in `NewWorld.exe`.

## Tested Action Tools (Success)

- **`trigger_auto_analysis`** (`GhidraTriggerAutoAnalysisTool`):
  - Successfully triggered auto-analysis for `NewWorld.exe`.
  - Confirmed completion via server logs.

## Untested Read-Only Tools (Skipped or No Suitable Test Data)

## Tools with Issues
