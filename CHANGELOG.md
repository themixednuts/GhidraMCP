# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to a custom versioning scheme suited for GhidraMCP.

## [Unreleased]

### Fixed
- **64-bit symbol ID precision loss** — `functions.list_variables` now serializes `symbol_id` and `high_symbol_id` as JSON strings, and `functions.rename_variable` accepts `variable_symbol_id` as either a string or an integer. Prevents truncation of IDs above 2^53 by JSON parsers that decode numbers as 64-bit floats (#38)

## [0.7.0-pre8] - 2026-04-14

### Fixed
- **Null progress token transport crash** - Guard Reactor context writes in the streamable HTTP tool wrapper so `tools/call` requests without a progress token no longer fail with `NullPointerException: value` (closes #44)
- **Internal error diagnostics** - Preserve exception causes and stack traces for unexpected tool failures so decompilation and transport issues log actionable diagnostics instead of flattened `-32603` messages

## [0.7.0-pre7] - 2026-04-09

### Fixed
- **Codex Streamable HTTP startup compatibility** - Return `405 Method Not Allowed` for pre-session `GET /mcp` requests instead of surfacing a transport-level `400` session-id error, allowing Codex to complete MCP startup correctly (closes #42)

## [0.7.0-pre6] - 2026-04-09

### Changed
- **MCP transport upgrade** - Replaced the stateless servlet transport with full Streamable HTTP, upgraded the MCP Java SDK to `1.1.1`, and migrated JSON handling to the Jackson 3 stack used by the latest SDK.
- **Live capability updates** - Tools, prompts, resources, and resource templates now refresh in-place when options change, with correct `listChanged` and `resources/updated` notifications instead of requiring a full restart for every feature toggle.
- **Progress and logging semantics** - Long-running operations now use MCP progress notifications for task advancement and reserve log notifications for lifecycle and phase messages, including nested tool calls executed through `batch_operations`.

## [0.7.0-pre5] - 2026-04-05

### Added
- **Struct/union patch mode** — `member_update_mode="patch"` for granular member edits by offset (structs) or ordinal (unions) without full replacement (closes #40)
- **Variable retype support** — `new_data_type` parameter on `rename_variable` action to change local variable types via `HighFunctionDBUtil.updateDBVariable`
- **`variable_symbol_id` targeting** — Stable decompiler-level ID (`high_symbol_id` from `list_variables`) for batch rename/retype operations, avoiding synthetic name renumbering issues (#38)
- **Component comments and ordinals** — `get` action now returns `comment` and `ordinal` fields for struct/union members

### Fixed
- **Schema bug** — Multiple `anyOf` blocks on `rename_variable` were overwriting each other; wrapped in `allOf` to compose correctly

## [0.7.0-pre4] - 2026-04-04

### Added
- **`functions.rename_variable` action** — Rename local variables within functions using the decompiler's high-level variable mapping via `HighFunctionDBUtil` (closes #38)

## [0.7.0-pre1] - 2026-03-25

### Changed
- **BREAKING: Task-Oriented Tool Redesign** — Consolidated 31 API-wrapper tools into 14 task-oriented tools following MCP best practices. Tool names, schemas, and action parameters have changed.
  - `inspect` — decompile, listing, references_to, references_from (replaces DecompileCodeTool, ReadListingTool, FindReferencesTool)
  - `functions` — list, get, create, update_prototype, list_variables (replaces ManageFunctionsTool, ReadFunctionsTool)
  - `symbols` — list, get, create, update, convert_to_class (replaces ManageSymbolsTool, ReadSymbolsTool)
  - `data_types` — list, get, create, update (replaces ManageDataTypesTool, ReadDataTypesTool)
  - `memory` — read, write, define, undefine, list_blocks, search (replaces ManageMemoryTool, ReadMemoryBlocksTool, SearchMemoryTool)
  - `project` — list_analysis_options, run_analysis, save, go_to_address, undo, redo, history (replaces ManageProjectTool, ListProgramsTool, ListAnalysisOptionsTool, UndoRedoTool)
  - `annotate` — set_comment, get_comments, create_bookmark, list_bookmarks (new)
  - `delete` — function, symbol, data_type, bookmark (replaces 4 separate delete tools, destructiveHint=true)
  - `analyze` — demangle, rtti, graph, call_graph (replaces DemanglerTool, AnalyzeRttiTool)
  - `vt_sessions` / `vt_operations` — consolidated from 5 VT tools
- **BREAKING: Dropped `target_type`/`target_value`** — All tools now use direct identifier args (`symbol_id`, `address`, `name`)
- **BREAKING: Standardized list filtering** — All list actions use `name_pattern` (regex) instead of mixed `name_filter`/`name_pattern`
- **Demangle cascade** — MDMangGhidra (full MSVC demangler) runs first, handling all symbol types including RTTI descriptors, vtables, constructors, and operators
- **RTTI serialization** — Replaced `Optional<T>` fields with nullable types in RTTIAnalysisResult to fix MCP SDK serialization
- **Server instructions** — Updated to guide agents through triage → inspect → analyze → annotate workflow
- **Build Tooling Migration** — Replaced the Maven/bootstrap shell flow with a Gradle build, Gradle version catalog, and `just` entrypoints for local development and CI
- **CI Modernization** — Updated GitHub Actions to current action releases and standardized the main workflow entrypoints on `just`

### Added
- **6 new resources** — Program info, listing, memory layout, imports, exports, defined strings
- **RTTI discovery resource** — `ghidra://program/{name}/rtti` scans for MSVC RTTI type descriptors with RTTI4 chain traversal and lambda method extraction
- **AnnotateTool** — Comments (EOL/PRE/POST/PLATE/REPEATABLE) and bookmarks for documenting findings
- **`memory.define` action** — Apply data types at addresses (CreateDataCmd) for vtable and struct workflows
- **`project.run_analysis` action** — Trigger Ghidra auto-analysis after modifications
- **`project.save` action** — Persist program changes to the Ghidra project
- **`analyze.call_graph` action** — Extract caller/callee relationships with BFS traversal and depth control
- **`analyze.graph` action** — Control flow graph visualization via BasicBlockModel
- **Bookmark delete safety** — Requires at least one filter or explicit `delete_all` flag
- **5 new prompts** — triage_binary, map_data_structures, analyze_vtable, compare_binaries, rename_analysis
- **7 new completions** — File name and address completions for new prompts
- **Resource hints in tool descriptions** — Tools reference relevant resources for browsing context

### Removed
- 17 absorbed tool files (Read*, Manage*, Delete*, List*, UndoRedo*, Demangler*, AnalyzeRtti*, FindReferences*, DecompileCode*, ReadListing*, SearchMemory*)
- `target_type`/`target_value` dual identifier pattern
- Silent "first executable block" default in listing
- `decompile_all` mode (batch decompilation)
- `analyze_segment` action (covered by read + list_blocks)
- `rtti0` from data_type_kind (moved to analyze.rtti)

## [0.6.2] - 2026-02-16

### Changed
- **Tool Infrastructure Deduplication** - Consolidated repeated pagination, cursor decoding, bounded argument parsing, and active-project/session boilerplate into shared base helpers across MCP tools
- **Version Tracking Refactor** - Introduced shared VT session/match utilities to centralize address parsing, match lookup, transaction handling, and path normalization

### Added
- **VT Edge-Case E2E Fixture** - Expanded in-memory VT fixture to exercise correlator edge conditions (minimum sizes, duplicate signatures, relocated functions, homogeneous/modified data, symbol-name matching)
- **VT Edge-Case Test Coverage** - Added targeted assertions for expected match and non-match behavior by correlator type

## [0.6.1] - 2026-02-14

### Fixed
- **Jackson Serialization Error** - `McpResponse.getDataOptional()` and `getErrorMessageOptional()` returned `Optional<T>` which Jackson treated as bean properties; the MCP SDK's ObjectMapper lacks `Jdk8Module`, causing `InvalidDefinitionException` on every tool call (#20)
- **Git Bash Build** - Removed `RequireFilesExist` enforcer rule that failed under MSYS2/git-bash due to path resolution bugs

### Added
- **Vanilla ObjectMapper Test** - `McpResponseTest` serializes with a plain `ObjectMapper` (no `Jdk8Module`) to catch SDK-incompatible getters
- **Build Wrapper** - `build.sh` auto-bootstraps Ghidra jars when missing or incomplete

## [0.6.0] - 2026-02-12

### Added
- **Structured Tool Output** - Tools now return typed `structuredContent` with `outputSchema` per MCP 2025-06-18 spec
  - Opaque cursor encoding (`OpaqueCursorCodec`) replaces raw cursor values in paginated responses
- **Per-Component Enable/Disable** - Individual tools, resources, prompts, and completions can be toggled in Ghidra options UI
- **ServiceLoader Completions** - Completions overhauled to ServiceLoader discovery with grouped routing by `CompleteReference`
- **Server Enhancements** - Transport context extraction, server instructions, and 180-second request timeout
- **Enriched Error Model** - `GhidraMcpError` now carries context, related resources, and actionable suggestions
- **Tool Output Storage UI** - Temp directory path displayed in Ghidra options for easy cleanup
- **E2E Test Coverage** - `ReadToolOutputTool` e2e tests exercise full store-and-retrieve workflow against real tool output

### Changed
- **Inline Response Limit** - Lowered from 32k to 16k chars (~4k tokens) for better context budget management
- **Test Layout** - Tests reorganized into `unit/` and `e2e/` directories
- **Build Infrastructure** - Added Ghidra system dependencies and e2e test execution support
- **CI** - Pinned `github-script@v7` and added MCP BOM drift check

## [0.5.3] - 2026-02-11

### Added
- **Oversized Output Sessions** - Added session-based tool output storage and retrieval
  - New `read_tool_output` MCP tool for listing sessions, listing stored outputs, and chunked reads
  - New `ToolOutputStore` with temp-file backing, cursor pagination, TTL cleanup, and bounded storage
  - Automatic oversized-response wrapping in `BaseMcpTool` with session/output references for composable follow-up calls
- **Dependency Automation Hardening**
  - Added scoped Dependabot configuration for Maven and GitHub Actions updates
  - Added Renovate regex manager for `bootstrap.xml` version properties and scheduled workflow
  - Added bot-PR dependency validation workflow that verifies pinned bootstrap, formatting, and full package build

### Changed
- **Pagination Coverage** - Extended `page_size` controls and normalized pagination behavior across listing/reference tools
- **Build/Bootstrap Reliability**
  - Added build prerequisite checks and Ghidra version-alignment verification
  - Improved bootstrap version resolution for pinned/latest flows and metadata output
  - Centralized dependency/plugin version properties for easier upgrades
- **Dependency Updates**
  - Updated MCP BOM, Maven plugins, JUnit/Mockito/Jetty and related dependencies
  - Upgraded Jackson stack to 2.21.x with aligned core/databind/annotations/jdk8 module versions

### Fixed
- Fixed classpath mismatch during Jackson 2.21.x updates by explicitly aligning all Jackson modules
- Fixed bootstrap metadata file generation to write line-delimited properties for reliable parsing

## [0.5.2] - 2026-01-14

### Fixed
- Fixed `extension.properties` version field to use Ghidra version for compatibility
- Fixed duplicate `sprintf` entry in `FindVulnerabilitiesPrompt` causing ServiceLoader error

## [0.5.1] - 2026-01-09

### Added
- **Pagination Support** - Extended pagination to additional tools
  - `FindReferencesTool` now supports cursor-based pagination for large reference sets
  - `ListAnalysisOptionsTool` now supports cursor-based pagination
- **MCP Prompts, Resources, and Completions** - New MCP specification features
  - Added prompt provider infrastructure for guided workflows
  - Added resource provider for exposing program data as MCP resources
  - Added completion provider for argument autocompletion

### Changed
- **Ghidra 12.0 Support** - Updated to latest Ghidra version
  - Updated dependency to Ghidra 12.0 (20251205)
  - Verified API compatibility with new Ghidra release
- **Performance Optimizations** - Tools now use native Ghidra APIs for better performance
  - `ReadFunctionsTool` uses `SymbolTable.getSymbols()` and `getFunctions(Address, boolean)`
  - `ReadSymbolsTool` uses `scanSymbolsByName()` and native wildcard iterators
  - `ReadDataTypesTool` uses type-specific iterators (`getAllStructures()`, `getAllComposites()`)
  - `FindReferencesTool` uses `hasReferencesTo()`/`hasReferencesFrom()` for early exit
  - `ManageDataTypesTool` uses `getDataTypeCount(true)` for efficient counting
- **Tool Infrastructure** - Major refactoring for maintainability
  - Introduced `BaseMcpTool` base class replacing `IGhidraMcpSpecification`
  - Simplified error handling with centralized utility methods
  - All 24 tools updated to extend `BaseMcpTool`

### Fixed
- Improved pagination consistency across all listing tools
- Better cursor handling for large result sets

## [0.5.0] - 2025-11-07

### Added
- **JSON Schema Infrastructure** - New type-safe schema builders for tool definitions
  - Draft 7 schema builder with conditional support (if/then/else, allOf, anyOf)
  - Google AI API schema builder with format types
  - Comprehensive validation for both schema types
  - Trait interfaces for type-safe schema building
- **ReadListingTool** - New tool for viewing disassembly and data from program listing
  - Support for viewing by address, address range, or function
  - Pagination support for large listings
  - Detailed instruction and data information with labels, comments, and function context
- **ListingInfo Model** - New model for representing listing entries
  - Comprehensive instruction and data details
  - Function context and comment information
- **Comprehensive Test Suite** - Extensive tests for JSON Schema builders
  - Tests for Draft 7 schema builder (SchemaBuilderTest, ValidationTest)
  - Tests for Google AI API schema builder (SchemaBuilderTest, ValidationTest)
  - Test assembly configuration for CI testing

### Changed
- **All Tools Migrated** - Updated all 24 tools to use new JSON Schema builders
  - Tools with conditionals use Draft 7 schema builder
  - Simple tools use Google AI API schema builder
  - Improved type safety and schema validation
- **FindReferencesTool** - Major improvements
  - Removed direction parameter - now returns all references regardless of direction
  - Added cursor-based pagination support
  - Improved performance for large reference sets
- **DecompileCodeTool** - Enhanced error handling
  - Better error messages for addresses within functions
  - Suggests decompiling containing function when address is not entry point
- **Build Configuration** - Enhanced build system
  - Added ci-tests profile for building test JAR with dependencies
  - Test assembly configuration for headless testing
  - Updated Module.manifest
- **Extension Properties** - Version visibility improvements
  - Version now displayed in extension description in Ghidra UI
  - Fixed version field to use project.version instead of ghidra.version

### Removed
- **Deprecated JsonSchemaBuilder** - Removed old schema builder implementation
  - Replaced by google.SchemaBuilder and draft7.SchemaBuilder
  - Old format type enums moved to google package
  - Old JsonSchemaValidationTest replaced by new validation tests

### Fixed
- Version now visible in Ghidra extension manager UI
- Improved schema validation and error handling across all tools

## [0.4.3] - 2025-01-27

### Added
- **Function Graph Models** - New models for control flow analysis
  - `FunctionGraph` model for representing function control flow
  - `FunctionGraphNode` model for basic blocks and control flow nodes
  - `FunctionGraphEdge` model for control flow connections
  - Support for structured function analysis and visualization
- **Data Type ID Support** - Enhanced data type identification and cross-referencing
  - Added `dataTypeId` field to `BaseDataTypeDetails` with JSON serialization
  - Include data type IDs in `ListDataTypesTool` output for easier reference
  - Enable direct ID-based lookups using `DataTypeManager.getDataType(long)`

### Changed
- **Data Type Resolution** - Major refactoring to use Ghidra's official APIs
  - Replaced custom `DataTypeUtils.java` with Ghidra's `DataTypeUtilities`
  - Use `DataTypeManager` as primary resolver with `DataTypeUtilities` as fallback
  - Support category path resolution with `DataTypeManager.getDataType(CategoryPath, String)`
  - Consolidated resolution logic into single `resolveDataTypeWithFallback` method
- **Enhanced Error Handling** - Rich, contextual error messages with actionable guidance
  - Added comprehensive `createDataTypeError()` method with smart type suggestions
  - Enhanced `ManageDataTypesTool` with contextual suggestions for failed type names
  - Improved `ManageFunctionsTool` error handling for return types and parameter types
  - Smart suggestions for unsigned types (`ulonglong`, `uint`, `ushort`, `ubyte`)
  - Path-based suggestions for absolute paths, category paths, and relative paths
  - Actionable guidance pointing users to `list_data_types` for discovery

### Removed
- **Custom Data Type Utilities** - Removed custom implementation in favor of official APIs
  - Deleted `DataTypeUtils.java` (187 lines) - replaced with Ghidra's built-in utilities
  - Removed redundant try-catch blocks and simplified error handling
  - Eliminated custom data type resolution in favor of official `DataTypeUtilities`

### Fixed
- Improved data type resolution reliability by using Ghidra's official APIs
- Enhanced user experience with detailed error context and resolution hints
- Better maintainability by leveraging Ghidra's built-in capabilities

## [0.4.2] - 2025-09-30

### Changed
- **RTTIAnalysisResult Model** - Simplified sealed interface implementation
  - Removed redundant `additionalInfo` field from all record variants
  - Removed `rttiTypeName` tracking (redundant with `rttiType()` method)
  - Factory methods now throw `InvalidDataTypeException` instead of catching internally
  - Cleaner exception propagation to calling code
- **Model Enhancements** - Enhanced metadata in core model classes
  - Added `signature` and `callingConvention` fields to `FunctionInfo`
  - Added additional symbol metadata to `SymbolInfo`
- **Tool Improvements** - Better performance and error handling
  - Refactored `ListSymbolsTool` for improved performance
  - Updated RTTI tools for simplified `RTTIAnalysisResult` structure
  - Improved symbol and function management tool implementations

### Added
- Jackson JDK8 module dependency for proper `Optional` serialization support

## [0.4.1] - 2025-09-29

### Added
- **Microsoft Ghidra Feature Support** - Added support for Microsoft-specific Ghidra features
  - MicrosoftCodeAnalyzer.jar for enhanced RTTI analysis capabilities
  - MicrosoftDemangler.jar for improved Microsoft symbol demangling
  - MicrosoftDmang.jar for additional Microsoft-specific demangling support
  - Access to Rtti4Model and other Microsoft RTTI analysis tools

### Changed
- **GitHub Actions CI/CD** - Updated build pipeline for latest Ghidra version
  - Updated to Ghidra 11.4.2 (20250826) for latest features and compatibility
  - Enhanced JAR dependency management for Microsoft features
  - Improved build consistency across development and CI environments

## [0.4.0] - 2025-09-29

### Added
- **UndoRedoTool** - Comprehensive undo/redo operations for Ghidra programs
  - Support for undo, redo, and info actions
  - Transaction-based operations with proper error handling
  - Detailed operation status and program state information
  - Structured error handling following established patterns
- **Enhanced ListProgramsTool** - Major improvements to program listing capabilities
  - Added pagination support with cursor-based navigation
  - Added format filtering (PE, ELF, MACH_O, COFF, RAW)
  - Added name filtering for program search
  - Enhanced ProgramFileInfo with additional metadata
  - Support for both open and closed program discovery

### Changed
- **Core Infrastructure** - Enhanced IGhidraMcpSpecification for headless mode support
  - Use AppInfo.getActiveProject() instead of tool.getProject() for headless compatibility
  - Added recursive project file search to find closed programs
  - Improved error messages with better context
  - Support both open and closed program access across entire project
- **Plugin Configuration** - Improved GhidraMcpPlugin initialization and configuration
  - Changed to ApplicationLevelOnlyPlugin for better integration
  - Updated package name and category for proper plugin registration
  - Improved server startup timing with SwingUtilities.invokeLater
  - Fix options change listener registration
- **Documentation** - Updated README with application-level configuration instructions
  - Added new Configuration section with step-by-step navigation
  - Updated configuration path to Browser → Edit → Tool Options → Miscellaneous
  - Clarified that settings are now at application level, not tool-specific

### Fixed
- Improved plugin initialization timing to prevent service registration issues
- Enhanced error handling and user guidance for server configuration
- Better integration with Ghidra's application-level plugin system

## [0.3.0] - 2025-09-28

### Added
- **DemanglerTool** - Comprehensive C++ symbol demangling using Ghidra's DemanglerUtil API
  - Support for various mangling formats (GCC, MSVC, Borland, etc.)
  - Multiple fallback demangling approaches for better compatibility
  - Detailed symbol analysis and format detection
  - Structured error handling with helpful suggestions
- **FindReferencesTool** - Find code and data references to addresses or symbols
- **ListAnalysisOptionsTool** - List available analysis options for programs
- **ListDataTypesTool** - List program data types with pagination support
- **ListFunctionsTool** - List program functions with comprehensive information
- **ListMemoryBlocksTool** - List memory blocks and segments
- **ListSymbolsTool** - List program symbols with detailed metadata
- **FunctionVariableInfo** model - Enhanced function variable information

### Changed
- **SearchMemoryTool** - Major improvements to hex format validation and error handling
  - Fixed NullPointerException with TaskMonitor usage
  - Added comprehensive hex format validation with helpful suggestions
  - Improved error messages for common format mistakes (0x prefix, continuous hex)
  - Enhanced schema descriptions for better user guidance
- Enhanced error handling across all tools with structured GhidraMcpError responses
- Improved tool descriptions with detailed usage guidance for AI agents

### Fixed
- Fixed SearchMemoryTool NullPointerException when using GhidraMcpTaskMonitor
- Improved DemanglerTool compatibility with various mangling formats
- Enhanced error reporting and debugging information across tools

## [0.2.3] - 2025-09-26

### Changed
- Improved `manage_data_types` category handling, clarifying parent vs. destination paths and providing automatic swap detection when arguments are reversed.
- Streamlined `manage_symbols` pagination and iteration helpers to avoid stack overflows while keeping iterator-style composition.

## [0.2.2] - 2025-09-25

### Changed
- Updated MCP CallToolResult handling to use builder-based API
- Bumped server metadata to reflect new version

## [0.2.1] - 2025-09-25

### Added
- `ListFilesTool` for listing currently open project files with structured output
- `OpenFileInfo` model representing open file metadata

### Changed
- Updated service registration and project metadata to include the new tool
- Improved error suggestion messaging to reference `list_files`

## [0.2.0] - 2025-09-25

### Changed
- **BREAKING:** Complete migration from granular CRUD-style tools to semantic tools aligned with MCP best practices
- **BREAKING:** Replaced individual granular tools with 5 comprehensive semantic tools:
  - `AnalyzeFunctionsTool` - Comprehensive function analysis including creation, inspection, decompilation, and prototype management
  - `DecompileCodeTool` - Advanced decompilation and P-code analysis for functions and code regions
  - `ManageDataTypesTool` - Complete data type management operations for structures, enums, unions, typedefs, and more
  - `ManageMemoryTool` - Comprehensive memory operations including read/write, pattern searching, and segment analysis
  - `ManageSymbolsTool` - Full symbol management including creation, renaming, searching, and analysis
- Updated Ghidra version compatibility from 11.3.2 to 11.4.2
- Enhanced error handling with structured `GhidraMcpError` responses
- Improved tool descriptions with detailed usage guidance for AI agents

### Added
- New model classes for enhanced MCP operations:
  - `ComponentMemberInfo` - Structure/union member information
  - `DataTypeKind` - Data type categorization enum
  - `DecompilationResult` - Function decompilation results
  - `FunctionAnalysis` - Comprehensive function analysis data
  - `MemorySearchResult` - Memory search operation results
  - `OperationResult` - Generic result wrapper for MCP operations
- Enhanced utility classes for better data type handling and JSON schema support

### Removed
- **BREAKING:** All granular CRUD-style tools (112 tool classes removed)
- Legacy model classes replaced by enhanced versions
- Old grouped tool interfaces and implementations

### Fixed
- Improved transaction handling for database modifications
- Better validation and error reporting across all operations

## [0.1.1] - Previous Release

Initial release with granular tool architecture.
