package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

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

    public static final String ARG_ACTION = "action";
    public static final String ARG_SYMBOL_TYPE = "symbol_type";
    public static final String ARG_NAME_PATTERN = "name_pattern";
    public static final String ARG_SYMBOL_TYPE_FILTER = "symbol_type_filter";
    public static final String ARG_CURRENT_NAME = "current_name";
    public static final String ARG_NEW_NAME = "new_name";
    public static final String ARG_NAMESPACE = "namespace";
    public static final String ARG_CASE_SENSITIVE = "case_sensitive";
    public static final String ARG_MAX_RESULTS = "max_results";

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

        return Map.of(
            "success", true,
            "symbol_type", "label",
            "name", name,
            "address", address.toString(),
            "namespace", namespaceOpt.orElse("global")
        );
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
                return Map.of("symbols", List.of(), "total", 0);
            }

            List<Map<String, Object>> symbolData = symbols.stream()
                .map(symbol -> Map.<String, Object>of(
                    "id", symbol.getID(),
                    "name", symbol.getName(),
                    "address", symbol.getAddress().toString(),
                    "type", symbol.getSymbolType().toString(),
                    "namespace", symbol.getParentNamespace().getName(true),
                    "source", symbol.getSource().toString(),
                    "primary", symbol.isPrimary(),
                    "pinned", symbol.isPinned()
                ))
                .collect(Collectors.toList());

            return Map.of(
                "symbols", symbolData,
                "total", symbolData.size()
            );
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

            return Map.of(
                "success", true,
                "old_name", currentName,
                "new_name", newName,
                "address", symbol.getAddress().toString(),
                "namespace", targetNamespace.getName(true)
            );
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

            return Map.of(
                "success", true,
                "deleted_symbol", symbolToDelete.getName(),
                "address", symbolToDelete.getAddress().toString()
            );
        });
    }

    private Mono<? extends Object> handleSearch(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String namePattern = getOptionalStringArgument(args, ARG_NAME_PATTERN).orElse(".*");
        Optional<String> typeFilterOpt = getOptionalStringArgument(args, ARG_SYMBOL_TYPE_FILTER);
        boolean caseSensitive = getOptionalBooleanArgument(args, ARG_CASE_SENSITIVE).orElse(false);
        int maxResults = getOptionalIntArgument(args, ARG_MAX_RESULTS).orElse(100);

        return Mono.fromCallable(() -> {
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbolIter = symbolTable.getAllSymbols(true);

            List<Symbol> matchingSymbols = StreamSupport.stream(symbolIter.spliterator(), false)
                .filter(symbol -> {
                    String symbolName = symbol.getName();
                    String pattern = caseSensitive ? namePattern : namePattern.toLowerCase();
                    String name = caseSensitive ? symbolName : symbolName.toLowerCase();

                    return name.matches(pattern);
                })
                .filter(symbol -> {
                    if (typeFilterOpt.isEmpty()) return true;
                    SymbolType symbolType = symbol.getSymbolType();
                    return symbolType != null &&
                           symbolType.toString().equalsIgnoreCase(typeFilterOpt.get());
                })
                .limit(maxResults)
                .collect(Collectors.toList());

            List<Map<String, Object>> results = matchingSymbols.stream()
                .map(symbol -> Map.<String, Object>of(
                    "id", symbol.getID(),
                    "name", symbol.getName(),
                    "address", symbol.getAddress().toString(),
                    "type", symbol.getSymbolType().toString(),
                    "namespace", symbol.getParentNamespace().getName(true),
                    "source", symbol.getSource().toString(),
                    "primary", symbol.isPrimary()
                ))
                .collect(Collectors.toList());

            return Map.of(
                "pattern", namePattern,
                "case_sensitive", caseSensitive,
                "type_filter", typeFilterOpt.orElse("all"),
                "results", results,
                "total_found", results.size(),
                "max_results", maxResults
            );
        });
    }

    private Mono<? extends Object> handleList(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        int maxResults = getOptionalIntArgument(args, ARG_MAX_RESULTS).orElse(100);

        return Mono.fromCallable(() -> {
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbolIter = symbolTable.getAllSymbols(true);

            List<Map<String, Object>> symbols = StreamSupport.stream(symbolIter.spliterator(), false)
                .limit(maxResults)
                .map(symbol -> Map.<String, Object>of(
                    "id", symbol.getID(),
                    "name", symbol.getName(),
                    "address", symbol.getAddress().toString(),
                    "type", symbol.getSymbolType().toString(),
                    "namespace", symbol.getParentNamespace().getName(true),
                    "source", symbol.getSource().toString(),
                    "primary", symbol.isPrimary()
                ))
                .collect(Collectors.toList());

            return Map.of(
                "symbols", symbols,
                "displayed_count", symbols.size(),
                "max_results", maxResults
            );
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

            return Map.of(
                "total_symbols", totalSymbols,
                "user_defined_symbols", userDefinedSymbols,
                "symbol_types", symbolTypeCounts.entrySet().stream()
                    .collect(Collectors.toMap(
                        entry -> entry.getKey().toString(),
                        Map.Entry::getValue)),
                "namespaces", namespaceCounts,
                "analysis_summary", Map.of(
                    "most_common_type", symbolTypeCounts.entrySet().stream()
                        .max(Map.Entry.comparingByValue())
                        .map(entry -> entry.getKey().toString())
                        .orElse("none"),
                    "largest_namespace", namespaceCounts.entrySet().stream()
                        .max(Map.Entry.comparingByValue())
                        .map(Map.Entry::getKey)
                        .orElse("none"),
                    "user_defined_percentage", totalSymbols > 0 ?
                        (double) userDefinedSymbols / totalSymbols * 100.0 : 0.0
                )
            );
        });
    }
}