package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import com.themixednuts.models.SymbolInfo;

import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@GhidraMcpTool(
    name = "Manage Symbols",
    description = "Comprehensive symbol management including creating, renaming, deleting, searching, and analyzing symbols.",
    mcpName = "manage_symbols",
    mcpDescription = """
        <use_case>
        Comprehensive symbol management for reverse engineering. Create labels, rename functions and variables,
        search for symbols, analyze symbol relationships, and manage symbol namespaces. Essential for
        organizing analysis results and improving code readability.
        </use_case>

        <important_notes>
        - Supports multiple symbol identification methods (name, address, symbol ID)
        - Handles namespace organization and symbol scoping
        - Validates symbol names according to Ghidra rules
        - Provides detailed symbol information including type and context
        </important_notes>

        <examples>
        Create a label:
        {
          "fileName": "program.exe",
          "action": "create",
          "symbol_type": "label",
          "address": "0x401000",
          "name": "main_entry"
        }

        Search for symbols:
        {
          "fileName": "program.exe",
          "action": "search",
          "name_pattern": "decrypt.*",
          "symbol_type_filter": "function"
        }
        </examples>
        """
)
public class ManageSymbolsTool implements IGhidraMcpSpecification {

    /**
     * Structured result for symbol creation.
     */
    private record SymbolCreationResult(boolean success,
            String symbolType,
            String name,
            String address,
            String namespace) {}

    /**
     * Structured result for symbol reading.
     */
    private record SymbolReadResult(List<SymbolDetails> symbols, int total) {}

    /**
     * Structured result for symbol renaming.
     */
    private record SymbolRenameResult(boolean success,
            String oldName,
            String newName,
            String address,
            String namespace) {}

    /**
     * Structured result for symbol deletion.
     */
    private record SymbolDeletionResult(boolean success, String deletedSymbol, String address) {}

    /**
     * Structured response for symbol search.
     */
    private record SymbolSearchResponse(String pattern,
            boolean caseSensitive,
            String typeFilter,
            PaginatedResult<SymbolListItem> results,
            int totalFound,
            int returnedCount,
            int pageSize) {}

    /**
     * Structured response for symbol listing.
     */
    private record SymbolListResponse(PaginatedResult<SymbolListItem> symbols,
            int displayedCount,
            int pageSize,
            int totalAvailable) {}

    /**
     * Structured analysis summary.
     */
    private record SymbolAnalysisSummary(String mostCommonType,
            String largestNamespace,
            double userDefinedPercentage) {}

    /**
     * Structured analysis result.
     */
    private record SymbolAnalysisResult(long totalSymbols,
            long userDefinedSymbols,
            Map<String, Long> symbolTypes,
            Map<String, Long> namespaces,
            SymbolAnalysisSummary analysisSummary) {}

    /**
     * Structured list item for symbol.
     */
    private record SymbolListItem(long id,
            String name,
            String address,
            String type,
            String namespace,
            String source,
            boolean primary) {}

    /**
     * Structured details for symbol.
     */
    private record SymbolDetails(long id,
            SymbolInfo info,
            boolean primary,
            boolean pinned) {}

    public static final String ARG_ACTION = "action";
    public static final String ARG_SYMBOL_TYPE = "symbol_type";
    public static final String ARG_NAME_PATTERN = "name_pattern";
    public static final String ARG_SYMBOL_TYPE_FILTER = "symbol_type_filter";
    public static final String ARG_CURRENT_NAME = "current_name";
    public static final String ARG_NEW_NAME = "new_name";
    public static final String ARG_NAMESPACE = "namespace";
    public static final String ARG_CASE_SENSITIVE = "case_sensitive";
    public static final String ARG_MAX_RESULTS = "max_results";
    public static final String ARG_PAGE_SIZE = "page_size";
    private static final int DEFAULT_PAGE_SIZE = 100;

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ACTION, JsonSchemaBuilder.string(mapper)
                .enumValues("create", "read", "update", "delete", "search", "list", "analyze")
                .description("Action to perform on symbols"));

        schemaRoot.property(ARG_SYMBOL_TYPE, JsonSchemaBuilder.string(mapper)
                .enumValues("label", "function", "parameter", "local_variable", "global_variable", "namespace")
                .description("Type of symbol for creation or filtering"));

        schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
                .description("Memory address for symbol operations")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
                .description("Symbol name for creation or identification"));

        schemaRoot.property(ARG_CURRENT_NAME, JsonSchemaBuilder.string(mapper)
                .description("Current symbol name for update operations"));

        schemaRoot.property(ARG_NEW_NAME, JsonSchemaBuilder.string(mapper)
                .description("New symbol name for update operations"));

        schemaRoot.property(ARG_NAMESPACE, JsonSchemaBuilder.string(mapper)
                .description("Namespace for symbol organization"));

        schemaRoot.property(ARG_SYMBOL_ID, JsonSchemaBuilder.integer(mapper)
                .description("Unique symbol ID for precise identification"));

        schemaRoot.property(ARG_NAME_PATTERN, JsonSchemaBuilder.string(mapper)
                .description("Pattern for symbol name matching (regex supported)"));

        schemaRoot.property(ARG_SYMBOL_TYPE_FILTER, JsonSchemaBuilder.string(mapper)
                .enumValues("Function", "Label", "Parameter", "LocalVariable", "GlobalVariable", "Class", "Namespace")
                .description("Filter symbols by type"));

        schemaRoot.property(ARG_CASE_SENSITIVE, JsonSchemaBuilder.bool(mapper)
                .description("Case sensitive name matching")
                .defaultValue(false));

        schemaRoot.property(ARG_MAX_RESULTS, JsonSchemaBuilder.integer(mapper)
                .description("Maximum results to return")
                .minimum(1)
                .maximum(1000)
                .defaultValue(100));

        schemaRoot.property(ARG_PAGE_SIZE, JsonSchemaBuilder.integer(mapper)
                .description("Maximum number of results per page for list/search actions")
                .minimum(1)
                .maximum(500)
                .defaultValue(DEFAULT_PAGE_SIZE));

        schemaRoot.requiredProperty(ARG_FILE_NAME)
                .requiredProperty(ARG_ACTION);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String action = getRequiredStringArgument(args, ARG_ACTION);

            return switch (action.toLowerCase()) {
                case "create" -> handleCreate(program, args, annotation);
                case "read" -> handleRead(program, args, annotation);
                case "update" -> handleUpdate(program, args, annotation);
                case "delete" -> handleDelete(program, args, annotation);
                case "search" -> handleSearch(program, args, annotation);
                case "list" -> handleList(program, args, annotation);
                case "analyze" -> handleAnalyze(program, args, annotation);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid action: " + action)
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "action validation",
                            args,
                            Map.of(ARG_ACTION, action),
                            Map.of("validActions", List.of("create", "read", "update", "delete", "search", "list", "analyze"))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid action",
                                "Choose from: create, read, update, delete, search, list, analyze",
                                List.of("create", "read", "update", "delete", "search", "list", "analyze"),
                                null)))
                        .build();
                    yield Mono.error(new GhidraMcpException(error));
                }
            };
        });
    }

    private Mono<? extends Object> handleCreate(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String symbolType = getRequiredStringArgument(args, ARG_SYMBOL_TYPE);
        String name = getRequiredStringArgument(args, ARG_NAME);
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
        Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);

        return executeInTransaction(program, "MCP - Create " + symbolType + " " + name, () -> {
            // Validate symbol name
            try {
                SymbolUtilities.validateName(name);
            } catch (InvalidInputException e) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Invalid symbol name: " + e.getMessage())
                    .context(new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        "name validation",
                        args,
                        Map.of(ARG_NAME, name),
                        Map.of("validationError", e.getMessage())))
                    .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                            "Use valid symbol name format",
                            "Symbol names must be valid identifiers",
                            List.of("my_symbol", "Symbol_123", "importantFunction"),
                            null)))
                    .build();
                throw new GhidraMcpException(error);
            }

            // Parse address
            Address address;
            try {
                address = program.getAddressFactory().getAddress(addressStr);
                if (address == null) {
                    throw new IllegalArgumentException("Invalid address format");
                }
            } catch (Exception e) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                    .message("Failed to parse address: " + e.getMessage())
                    .build();
                throw new GhidraMcpException(error);
            }

            // Create symbol based on type
            return switch (symbolType.toLowerCase()) {
                case "label" -> createLabel(program, name, address, namespaceOpt, annotation);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Unsupported symbol type for creation: " + symbolType)
                        .build();
                    throw new GhidraMcpException(error);
                }
            };
        });
    }

    private Object createLabel(Program program, String name, Address address,
                              Optional<String> namespaceOpt, GhidraMcpTool annotation) throws GhidraMcpException {
        AddLabelCmd cmd = new AddLabelCmd(address, name, SourceType.USER_DEFINED);

        if (!cmd.applyTo(program)) {
            GhidraMcpError error = GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to create label: " + cmd.getStatusMsg())
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "label creation",
                    Map.of(ARG_NAME, name, ARG_ADDRESS, address.toString()),
                    Map.of("commandStatus", cmd.getStatusMsg()),
                    Map.of("commandFailed", true)))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                        "Check if label already exists at address",
                        "Verify address doesn't already have a conflicting symbol",
                        null,
                        null)))
                .build();
            throw new GhidraMcpException(error);
        }

        return new SymbolCreationResult(true,
                "label",
                name,
                address.toString(),
                namespaceOpt.orElse("global"));
    }

    private Mono<? extends Object> handleRead(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
            Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
            Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);

            if (addressOpt.isEmpty() && symbolIdOpt.isEmpty() && nameOpt.isEmpty()) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                    .message("At least one identifier must be provided")
                    .build();
                throw new GhidraMcpException(error);
            }

            SymbolTable symbolTable = program.getSymbolTable();
            List<Symbol> symbols = new ArrayList<>();

            if (symbolIdOpt.isPresent()) {
                Symbol symbol = symbolTable.getSymbol(symbolIdOpt.get());
                if (symbol != null) {
                    symbols.add(symbol);
                }
            } else if (addressOpt.isPresent()) {
                try {
                    Address address = program.getAddressFactory().getAddress(addressOpt.get());
                    if (address != null) {
                        Symbol[] addressSymbols = symbolTable.getSymbols(address);
                        symbols.addAll(Arrays.asList(addressSymbols));
                    }
                } catch (Exception e) {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                        .message("Failed to parse address: " + e.getMessage())
                        .build();
                    throw new GhidraMcpException(error);
                }
            } else if (nameOpt.isPresent()) {
                SymbolIterator symbolIter = symbolTable.getSymbolIterator(nameOpt.get(), true);
                while (symbolIter.hasNext()) {
                    symbols.add(symbolIter.next());
                }
            }

            if (symbols.isEmpty()) {
                return new SymbolReadResult(List.of(), 0);
            }

            List<SymbolDetails> symbolDetails = symbols.stream()
                .map(symbol -> new SymbolDetails(
                    symbol.getID(),
                    new SymbolInfo(symbol),
                    symbol.isPrimary(),
                    symbol.isPinned()))
                .collect(Collectors.toList());

            return new SymbolReadResult(symbolDetails, symbolDetails.size());
        });
    }

    private Mono<? extends Object> handleUpdate(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String currentName = getRequiredStringArgument(args, ARG_CURRENT_NAME);
        String newName = getRequiredStringArgument(args, ARG_NEW_NAME);
        Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);

        return executeInTransaction(program, "MCP - Rename Symbol " + currentName + " to " + newName, () -> {
            SymbolTable symbolTable = program.getSymbolTable();

            // Find symbol by name
            SymbolIterator symbolIter = symbolTable.getSymbolIterator(currentName, true);
            if (!symbolIter.hasNext()) {
                GhidraMcpError error = GhidraMcpError.resourceNotFound()
                    .errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
                    .message("Symbol not found: " + currentName)
                    .build();
                throw new GhidraMcpException(error);
            }

            Symbol symbol = symbolIter.next();
            if (symbolIter.hasNext()) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
                    .message("Multiple symbols found with name: " + currentName)
                    .build();
                throw new GhidraMcpException(error);
            }

            // Determine target namespace
            Namespace targetNamespace = program.getGlobalNamespace();
            if (namespaceOpt.isPresent() && !namespaceOpt.get().isBlank() &&
                !namespaceOpt.get().equalsIgnoreCase("global")) {
                targetNamespace = symbolTable.getNamespace(namespaceOpt.get(), null);
            }

            RenameLabelCmd cmd = new RenameLabelCmd(symbol, newName, targetNamespace, SourceType.USER_DEFINED);
            if (!cmd.applyTo(program)) {
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to rename symbol: " + cmd.getStatusMsg())
                    .build();
                throw new GhidraMcpException(error);
            }

            return new SymbolRenameResult(true,
                    currentName,
                    newName,
                    symbol.getAddress().toString(),
                    targetNamespace.getName(true));
        });
    }

    private Mono<? extends Object> handleDelete(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return executeInTransaction(program, "MCP - Delete Symbol", () -> {
            Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
            Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);
            Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);

            if (addressOpt.isEmpty() && nameOpt.isEmpty() && symbolIdOpt.isEmpty()) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                    .message("At least one identifier must be provided")
                    .build();
                throw new GhidraMcpException(error);
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol symbolToDelete = null;

            if (symbolIdOpt.isPresent()) {
                symbolToDelete = symbolTable.getSymbol(symbolIdOpt.get());
            } else if (addressOpt.isPresent()) {
                try {
                    Address address = program.getAddressFactory().getAddress(addressOpt.get());
                    if (address != null) {
                        symbolToDelete = symbolTable.getPrimarySymbol(address);
                    }
                } catch (Exception e) {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                        .message("Failed to parse address: " + e.getMessage())
                        .build();
                    throw new GhidraMcpException(error);
                }
            } else if (nameOpt.isPresent()) {
                SymbolIterator symbolIter = symbolTable.getSymbolIterator(nameOpt.get(), true);
                if (symbolIter.hasNext()) {
                    symbolToDelete = symbolIter.next();
                    if (symbolIter.hasNext()) {
                        GhidraMcpError error = GhidraMcpError.validation()
                            .errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
                            .message("Multiple symbols found with name: " + nameOpt.get())
                            .build();
                        throw new GhidraMcpException(error);
                    }
                }
            }

            if (symbolToDelete == null) {
                GhidraMcpError error = GhidraMcpError.resourceNotFound()
                    .errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
                    .message("Symbol not found")
                    .build();
                throw new GhidraMcpException(error);
            }

            DeleteLabelCmd cmd = new DeleteLabelCmd(symbolToDelete.getAddress(), symbolToDelete.getName(), symbolToDelete.getParentNamespace());
            if (!cmd.applyTo(program)) {
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to delete symbol: " + cmd.getStatusMsg())
                    .build();
                throw new GhidraMcpException(error);
            }

            return new SymbolDeletionResult(true,
                    symbolToDelete.getName(),
                    symbolToDelete.getAddress().toString());
        });
    }

    private Mono<? extends Object> handleSearch(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String namePattern = getOptionalStringArgument(args, ARG_NAME_PATTERN).orElse(".*");
        Optional<String> typeFilterOpt = getOptionalStringArgument(args, ARG_SYMBOL_TYPE_FILTER);
        boolean caseSensitive = getOptionalBooleanArgument(args, ARG_CASE_SENSITIVE).orElse(false);
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
        int pageSize = getOptionalIntArgument(args, ARG_PAGE_SIZE).orElse(DEFAULT_PAGE_SIZE);

        return Mono.fromCallable(() -> {
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbolIter = symbolTable.getAllSymbols(true);

            List<Symbol> allSymbols = StreamSupport.stream(symbolIter.spliterator(), false)
                .filter(symbol -> {
                    String symbolName = symbol.getName();
                    String pattern = caseSensitive ? namePattern : namePattern.toLowerCase();
                    String name = caseSensitive ? symbolName : symbolName.toLowerCase();

                    return name.matches(pattern);
                })
                .filter(symbol -> {
                    if (typeFilterOpt.isEmpty()) return true;
                    SymbolType symbolType = symbol.getSymbolType();
                    return symbolType != null && symbolType.toString().equalsIgnoreCase(typeFilterOpt.get());
                })
                .sorted(Comparator.comparingLong(Symbol::getID))
                .collect(Collectors.toList());

            long cursorId = cursorOpt.map(Long::parseLong).orElse(0L);

            List<Symbol> pageBuffer = allSymbols.stream()
                .filter(symbol -> symbol.getID() > cursorId)
                .limit((long) pageSize + 1)
                .collect(Collectors.toList());

            String nextCursor = null;
            if (pageBuffer.size() > pageSize) {
                nextCursor = String.valueOf(pageBuffer.get(pageSize).getID());
            }

            List<SymbolListItem> results = pageBuffer.stream()
                .limit(pageSize)
                .map(symbol -> new SymbolListItem(
                    symbol.getID(),
                    symbol.getName(),
                    symbol.getAddress().toString(),
                    symbol.getSymbolType().toString(),
                    symbol.getParentNamespace().getName(true),
                    symbol.getSource().toString(),
                    symbol.isPrimary()))
                .collect(Collectors.toList());

            PaginatedResult<SymbolListItem> paginated = new PaginatedResult<>(results, nextCursor);

            return new SymbolSearchResponse(
                namePattern,
                caseSensitive,
                typeFilterOpt.orElse("all"),
                paginated,
                allSymbols.size(),
                results.size(),
                pageSize);
        });
    }

    private Mono<? extends Object> handleList(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
        int pageSize = getOptionalIntArgument(args, ARG_PAGE_SIZE).orElse(DEFAULT_PAGE_SIZE);

        return Mono.fromCallable(() -> {
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbolIter = symbolTable.getAllSymbols(true);

            List<Symbol> allSymbols = StreamSupport.stream(symbolIter.spliterator(), false)
                .sorted(Comparator.comparingLong(Symbol::getID))
                .collect(Collectors.toList());

            long cursorId = cursorOpt.map(Long::parseLong).orElse(0L);

            List<Symbol> pageBuffer = allSymbols.stream()
                .filter(symbol -> symbol.getID() > cursorId)
                .limit((long) pageSize + 1)
                .collect(Collectors.toList());

            String nextCursor = null;
            if (pageBuffer.size() > pageSize) {
                nextCursor = String.valueOf(pageBuffer.get(pageSize).getID());
            }

            List<SymbolListItem> symbols = pageBuffer.stream()
                .limit(pageSize)
                .map(symbol -> new SymbolListItem(
                    symbol.getID(),
                    symbol.getName(),
                    symbol.getAddress().toString(),
                    symbol.getSymbolType().toString(),
                    symbol.getParentNamespace().getName(true),
                    symbol.getSource().toString(),
                    symbol.isPrimary()))
                .collect(Collectors.toList());

            PaginatedResult<SymbolListItem> paginated = new PaginatedResult<>(symbols, nextCursor);

            return new SymbolListResponse(paginated,
                symbols.size(),
                pageSize,
                allSymbols.size());
        });
    }

    private Mono<? extends Object> handleAnalyze(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            SymbolTable symbolTable = program.getSymbolTable();

            Map<SymbolType, Long> symbolTypeCounts = new HashMap<>();
            Map<String, Long> namespaceCounts = new HashMap<>();
            long totalSymbols = 0;
            long userDefinedSymbols = 0;

            SymbolIterator symbolIter = symbolTable.getAllSymbols(true);
            while (symbolIter.hasNext()) {
                Symbol symbol = symbolIter.next();
                totalSymbols++;

                // Count by type
                SymbolType symbolType = symbol.getSymbolType();
                symbolTypeCounts.merge(symbolType, 1L, Long::sum);

                // Count by namespace
                String namespaceName = symbol.getParentNamespace().getName(true);
                if (namespaceName.isEmpty()) namespaceName = "Global";
                namespaceCounts.merge(namespaceName, 1L, Long::sum);

                // Count user-defined
                if (symbol.getSource() == SourceType.USER_DEFINED) {
                    userDefinedSymbols++;
                }
            }

            Map<String, Long> symbolTypes = symbolTypeCounts.entrySet().stream()
                    .collect(Collectors.toMap(
                            entry -> entry.getKey().toString(),
                            Map.Entry::getValue));
            SymbolAnalysisSummary summary = new SymbolAnalysisSummary(
                    symbolTypeCounts.entrySet().stream()
                            .max(Map.Entry.comparingByValue())
                            .map(entry -> entry.getKey().toString())
                            .orElse("none"),
                    namespaceCounts.entrySet().stream()
                            .max(Map.Entry.comparingByValue())
                            .map(Map.Entry::getKey)
                            .orElse("none"),
                    totalSymbols > 0 ? (double) userDefinedSymbols / totalSymbols * 100.0 : 0.0);
            return new SymbolAnalysisResult(totalSymbols,
                    userDefinedSymbols,
                    symbolTypes,
                    namespaceCounts,
                    summary);
        });
    }
}