# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to a custom versioning scheme suited for GhidraMCP.

## [Unreleased]

### Changed
- **Data Type Resolution** - Refactored to use Ghidra's `DataTypeParser`
  - Now uses Ghidra's standard `DataTypeParser` for consistent type resolution
  - Supports all Ghidra data type syntax: pointers (`byte*`, `byte**`), arrays (`byte[5]`), templates, namespaces
  - Maintains backward compatibility with MCP client path formats (paths starting with `/`)
  - Follows patterns from Ghidra's `DataTypeParserTest` for maximum compatibility

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
