# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to a custom versioning scheme suited for GhidraMCP.

## [Unreleased]

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
