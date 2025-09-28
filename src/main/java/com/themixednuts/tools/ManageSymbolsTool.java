package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.models.OperationResult;

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
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterator;
import java.util.Spliterators;

@GhidraMcpTool(
    name = "Manage Symbols",
    description = "Symbol CRUD operations: create, read, update, and delete symbols and labels.",
    mcpName = "manage_symbols",
    mcpDescription = """
        <use_case>
        Symbol CRUD operations for reverse engineering. Create labels, read symbol information,
        rename functions and variables, update symbol properties, and delete symbols. Essential
        for organizing analysis results and improving code readability.
        </use_case>

        <important_notes>
        - Supports multiple symbol identification methods (name, address, symbol ID)
        - Handles namespace organization and symbol scoping
        - Validates symbol names according to Ghidra rules
        - Provides detailed symbol information including type and context
        - Use ListSymbolsTool for browsing symbols with filtering
        - Use FindSymbolTool for finding specific symbols
        - Use SearchMemoryTool for pattern-based symbol searching
        - Use '.*' to match any characters, escape special regex characters if needed
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

        Search for symbols containing specific text:
        {
          "fileName": "program.exe",
          "action": "search",
          "name_pattern": "s_typeId",
          "symbol_type_filter": "Label"
        }

        Search for symbols starting with specific text:
        {
          "fileName": "program.exe",
          "action": "search",
          "name_pattern": "CanvasAsset.*",
          "max_results": 10
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
    public static final String ARG_PAGE_SIZE = "page_size";
    private static final int DEFAULT_PAGE_SIZE = 100;

    private static final String ACTION_CREATE = "create";
    private static final String ACTION_READ = "read";
    private static final String ACTION_UPDATE = "update";
    private static final String ACTION_DELETE = "delete";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ACTION, JsonSchemaBuilder.string(mapper)
                .enumValues(
                        ACTION_CREATE,
                        ACTION_READ,
                        ACTION_UPDATE,
                        ACTION_DELETE)
                .description("Action to perform on symbols"));

        schemaRoot.property(ARG_SYMBOL_TYPE, JsonSchemaBuilder.string(mapper)
                .enumValues("label", "function", "parameter", "local_variable", "global_variable", "namespace", "class")
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
                .description("Regular expression pattern for symbol name matching. The entire symbol name must match the pattern. Examples: '.*s_typeId.*' matches any symbol containing 's_typeId', 'CanvasAsset.*s_typeId' matches symbols starting with 'CanvasAsset' and ending with 's_typeId', '.*' matches all symbols."));

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
                case ACTION_CREATE -> handleCreate(program, args, annotation);
                case ACTION_READ -> handleRead(program, args, annotation);
                case ACTION_UPDATE -> handleUpdate(program, args, annotation);
                case ACTION_DELETE -> handleDelete(program, args, annotation);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid action: " + action)
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "action validation",
                            args,
                            Map.of(ARG_ACTION, action),
                            Map.of("validActions", List.of(
                                    ACTION_CREATE,
                                    ACTION_READ,
                                    ACTION_UPDATE,
                                    ACTION_DELETE))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid action",
                                "Choose from: create, read, update, delete",
                                List.of(
                                        ACTION_CREATE,
                                        ACTION_READ,
                                        ACTION_UPDATE,
                                        ACTION_DELETE),
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
        Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);

        // Address is optional for class and namespace symbols (they use NO_ADDRESS)
        String addressStr = (symbolType.equalsIgnoreCase("class") || symbolType.equalsIgnoreCase("namespace")) ?
            null : getRequiredStringArgument(args, ARG_ADDRESS);

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

            // Parse address (skip for class symbols)
            Address address = null;
            if (addressStr != null) {
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
            }

            // Create symbol based on type
            return switch (symbolType.toLowerCase()) {
                case "label" -> createLabel(program, name, address, namespaceOpt, annotation);
                case "class" -> createClass(program, name, namespaceOpt, annotation);
                case "namespace" -> createNamespace(program, name, namespaceOpt, annotation);
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

        // Get the created symbol to return its info
        Symbol[] symbols = program.getSymbolTable().getSymbols(address);
        Symbol createdSymbol = null;
        for (Symbol symbol : symbols) {
            if (symbol.getName().equals(name)) {
                createdSymbol = symbol;
                break;
            }
        }

        if (createdSymbol == null) {
            // This shouldn't happen if creation succeeded, but handle it
            GhidraMcpError error = GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                .message("Symbol created but could not be retrieved")
                .build();
            throw new GhidraMcpException(error);
        }

        return new SymbolInfo(createdSymbol);
    }

    private Object createClass(Program program, String name, Optional<String> namespaceOpt,
                              GhidraMcpTool annotation) throws GhidraMcpException {
        SymbolTable symbolTable = program.getSymbolTable();

        // Validate class name
        try {
            SymbolUtilities.validateName(name);
        } catch (InvalidInputException e) {
            GhidraMcpError error = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Invalid class name: " + e.getMessage())
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "class name validation",
                    Map.of(ARG_NAME, name),
                    Map.of("validationError", e.getMessage()),
                    Map.of("nameValid", false)))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                        "Use a valid class name",
                        "Class names must follow Ghidra symbol naming conventions",
                        List.of("Use alphanumeric characters and underscores", "Avoid reserved keywords"),
                        null)))
                .build();
            throw new GhidraMcpException(error);
        }

        // Resolve parent namespace
        Namespace parentNamespace;
        if (namespaceOpt.isPresent()) {
            parentNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
        } else {
            parentNamespace = program.getGlobalNamespace();
        }

        // Create class namespace
        try {
            Namespace classNamespace = symbolTable.createClass(parentNamespace, name, SourceType.USER_DEFINED);
            Symbol classSymbol = classNamespace.getSymbol();
            return new SymbolInfo(classSymbol);
        } catch (Exception e) {
            GhidraMcpError error = GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to create class: " + e.getMessage())
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "class creation",
                    Map.of(ARG_NAME, name, ARG_NAMESPACE, namespaceOpt.orElse("global")),
                    Map.of("exceptionType", e.getClass().getSimpleName()),
                    Map.of("creationFailed", true)))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                        "Check if class already exists",
                        "Verify class name doesn't conflict with existing symbols",
                        null,
                        null)))
                .build();
            throw new GhidraMcpException(error);
        }
    }

    private Object createNamespace(Program program, String name, Optional<String> namespaceOpt,
                                  GhidraMcpTool annotation) throws GhidraMcpException {
        SymbolTable symbolTable = program.getSymbolTable();

        // Validate namespace name
        try {
            SymbolUtilities.validateName(name);
        } catch (InvalidInputException e) {
            GhidraMcpError error = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Invalid namespace name: " + e.getMessage())
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "namespace name validation",
                    Map.of(ARG_NAME, name),
                    Map.of("validationError", e.getMessage()),
                    Map.of("nameValid", false)))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                        "Use a valid namespace name",
                        "Namespace names must follow Ghidra symbol naming conventions",
                        List.of("Use alphanumeric characters and underscores", "Avoid reserved keywords"),
                        null)))
                .build();
            throw new GhidraMcpException(error);
        }

        // Resolve parent namespace
        Namespace parentNamespace;
        if (namespaceOpt.isPresent()) {
            parentNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
        } else {
            parentNamespace = program.getGlobalNamespace();
        }

        // Create namespace
        try {
            Namespace namespace = symbolTable.createNameSpace(parentNamespace, name, SourceType.USER_DEFINED);
            Symbol namespaceSymbol = namespace.getSymbol();
            return new SymbolInfo(namespaceSymbol);
        } catch (Exception e) {
            GhidraMcpError error = GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to create namespace: " + e.getMessage())
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "namespace creation",
                    Map.of(ARG_NAME, name, ARG_NAMESPACE, namespaceOpt.orElse("global")),
                    Map.of("exceptionType", e.getClass().getSimpleName()),
                    Map.of("creationFailed", true)))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                        "Check if namespace already exists",
                        "Verify namespace name doesn't conflict with existing symbols",
                        null,
                        null)))
                .build();
            throw new GhidraMcpException(error);
        }
    }

    private Mono<? extends Object> handleRead(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            SymbolTable symbolTable = program.getSymbolTable();

            // Apply precedence: symbol_id > address > name
            if (args.containsKey(ARG_SYMBOL_ID)) {
                Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
                if (symbolId != null) {
                    Symbol symbol = symbolTable.getSymbol(symbolId);
                    if (symbol != null) {
                        return new SymbolInfo(symbol);
                    }
                }
                throw new GhidraMcpException(createSymbolNotFoundError(annotation.mcpName(), "symbol_id", symbolId.toString()));
            } else if (args.containsKey(ARG_ADDRESS)) {
                String address = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
                if (address != null && !address.trim().isEmpty()) {
                    try {
                        Address addr = program.getAddressFactory().getAddress(address);
                        if (addr != null) {
                            Symbol[] symbols = symbolTable.getSymbols(addr);
                            if (symbols.length > 0) {
                                return new SymbolInfo(symbols[0]); // Return first symbol at address
                            }
                        }
                        throw new GhidraMcpException(createSymbolNotFoundError(annotation.mcpName(), "address", address));
                    } catch (Exception e) {
                        throw new GhidraMcpException(createInvalidAddressError(address, e));
                    }
                }
                throw new GhidraMcpException(createMissingParameterError(annotation.mcpName()));
            } else if (args.containsKey(ARG_NAME)) {
                String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
                if (name != null && !name.trim().isEmpty()) {
                    // First try exact match
                    SymbolIterator exactIter = symbolTable.getSymbolIterator(name, true);
                    if (exactIter.hasNext()) {
                        return new SymbolInfo(exactIter.next());
                    }

                    // Then try regex
                    try {
                        Symbol firstMatch = StreamSupport.stream(symbolTable.getAllSymbols(true).spliterator(), false)
                            .filter(s -> s.getName().matches(name))
                            .findFirst()
                            .orElse(null);

                        if (firstMatch != null) {
                            return new SymbolInfo(firstMatch);
                        }
                        throw new GhidraMcpException(createSymbolNotFoundError(annotation.mcpName(), "name", name));
                    } catch (Exception e) {
                        throw new GhidraMcpException(createInvalidRegexError(name, e));
                    }
                }
                throw new GhidraMcpException(createMissingParameterError(annotation.mcpName()));
            } else {
                throw new GhidraMcpException(createMissingParameterError(annotation.mcpName()));
            }
        });
    }

    private Mono<? extends Object> handleUpdate(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
        Optional<String> currentNameOpt = getOptionalStringArgument(args, ARG_CURRENT_NAME);
        Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
        Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);
        String newName = getRequiredStringArgument(args, ARG_NEW_NAME);

        boolean hasSymbolId = symbolIdOpt.isPresent();
        boolean hasCurrentName = currentNameOpt.filter(name -> !name.isBlank()).isPresent();
        boolean hasAddress = addressOpt.filter(addr -> !addr.isBlank()).isPresent();

        // Count provided identifiers
        int identifierCount = (hasSymbolId ? 1 : 0) + (hasCurrentName ? 1 : 0) + (hasAddress ? 1 : 0);
        
        if (identifierCount > 1) {
            return Mono.error(multipleIdentifierError(args, symbolIdOpt, currentNameOpt, addressOpt));
        }

        if (identifierCount == 0) {
            return Mono.error(missingIdentifierError(args));
        }

        return executeInTransaction(program, "MCP - Rename Symbol", () -> {
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolResolveResult resolveResult = resolveSymbolForRename(symbolTable, program, args, symbolIdOpt, currentNameOpt, addressOpt, namespaceOpt);

            // Check if the new name already exists in the target namespace
            SymbolIterator existingSymbolIterator = symbolTable.getSymbolIterator(newName, true);
            List<Symbol> existingSymbols = new ArrayList<>();
            while (existingSymbolIterator.hasNext()) {
                Symbol existingSymbol = existingSymbolIterator.next();
                if (existingSymbol.getParentNamespace().equals(resolveResult.targetNamespace())) {
                    existingSymbols.add(existingSymbol);
                }
            }
            
            // If there's already a symbol with the same name in the target namespace, provide detailed info
            if (!existingSymbols.isEmpty()) {
                Map<String, Object> conflictInfo = new HashMap<>();
                List<Map<String, Object>> conflictingSymbols = existingSymbols.stream()
                    .map(symbol -> {
                        Map<String, Object> symbolInfo = new HashMap<>();
                        symbolInfo.put("id", symbol.getID());
                        symbolInfo.put("name", symbol.getName());
                        symbolInfo.put("address", symbol.getAddress().toString());
                        symbolInfo.put("type", symbol.getSymbolType().toString());
                        symbolInfo.put("namespace", symbol.getParentNamespace().getName(false));
                        symbolInfo.put("source", symbol.getSource().toString());
                        return symbolInfo;
                    })
                    .collect(Collectors.toList());
                
                conflictInfo.put("conflictingSymbols", conflictingSymbols);
                conflictInfo.put("targetNamespace", resolveResult.targetNamespace().getName(false));
                
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Symbol already exists: " + newName)
                    .context(new GhidraMcpError.ErrorContext(
                        this.getMcpName(),
                        "rename symbol conflict",
                        args,
                        Map.of("symbolId", resolveResult.symbol().getID(), ARG_NEW_NAME, newName),
                        conflictInfo
                    ))
                    .suggestions(List.of(new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                        "Choose a different name",
                        "Provide a unique name that doesn't conflict with existing symbols",
                        List.of("CanvasAsset::s_typeId_v2", "CanvasAsset_s_typeId_new"),
                        null)))
                    .build();
                throw new GhidraMcpException(error);
            }

            RenameLabelCmd cmd = new RenameLabelCmd(resolveResult.symbol(), newName, resolveResult.targetNamespace(), SourceType.USER_DEFINED);
            if (!cmd.applyTo(program)) {
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to rename symbol: " + cmd.getStatusMsg())
                    .context(new GhidraMcpError.ErrorContext(
                        this.getMcpName(),
                        "rename symbol",
                        args,
                        Map.of("symbolId", resolveResult.symbol().getID(), ARG_NEW_NAME, newName, "targetNamespace", resolveResult.targetNamespace().getName(false)),
                        Map.of("commandStatus", cmd.getStatusMsg())
                    ))
                    .build();
                throw new GhidraMcpException(error);
            }

            // Return the updated symbol info
            return new SymbolInfo(resolveResult.symbol());
        });
    }

    private SymbolResolveResult resolveSymbolForRename(SymbolTable symbolTable,
            Program program,
            Map<String, Object> args,
            Optional<Long> symbolIdOpt,
            Optional<String> currentNameOpt,
            Optional<String> addressOpt,
            Optional<String> namespaceOpt) throws GhidraMcpException {

        if (symbolIdOpt.isPresent()) {
            Symbol symbol = symbolTable.getSymbol(symbolIdOpt.get());
            if (symbol == null) {
                throw symbolNotFoundById(symbolIdOpt.get(), args);
            }

            Namespace targetNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
            return new SymbolResolveResult(symbol, symbol.getName(false), targetNamespace);
        }

        if (addressOpt.isPresent()) {
            try {
                Address address = program.getAddressFactory().getAddress(addressOpt.get());
                if (address == null) {
                    throw new IllegalArgumentException("Invalid address format: " + addressOpt.get());
                }
                
                Symbol primarySymbol = symbolTable.getPrimarySymbol(address);
                if (primarySymbol == null) {
                    throw symbolNotFoundByAddress(addressOpt.get(), args);
                }
                
                Namespace targetNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
                return new SymbolResolveResult(primarySymbol, primarySymbol.getName(false), targetNamespace);
            } catch (Exception e) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                    .message("Failed to parse address: " + e.getMessage())
                    .context(new GhidraMcpError.ErrorContext(
                        this.getMcpName(),
                        "address parsing",
                        args,
                        Map.of(ARG_ADDRESS, addressOpt.get()),
                        Map.of("parseError", e.getMessage())))
                    .build();
                throw new GhidraMcpException(error);
            }
        }

        String currentName = currentNameOpt.map(String::trim).orElse("");

        List<Symbol> matchingSymbols = findSymbolsByName(symbolTable, currentName);

        if (matchingSymbols.isEmpty()) {
            throw symbolNotFoundByName(currentName, namespaceOpt, args);
        }

        Namespace targetNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
        Symbol selectedSymbol = selectSymbolWithinNamespace(matchingSymbols, targetNamespace, args);

        return new SymbolResolveResult(selectedSymbol, currentName, targetNamespace);
    }

    private Namespace resolveTargetNamespace(SymbolTable symbolTable, Program program, Optional<String> namespaceOpt) throws GhidraMcpException {
        if (namespaceOpt.isEmpty() || namespaceOpt.get().isBlank() || namespaceOpt.get().equalsIgnoreCase("global")) {
            return program.getGlobalNamespace();
        }

        Namespace namespace = symbolTable.getNamespace(namespaceOpt.get(), null);
        if (namespace == null) {
            throw namespaceNotFound(namespaceOpt.get());
        }
        return namespace;
    }

    private List<Symbol> findSymbolsByName(SymbolTable symbolTable, String currentName) {
        SymbolIterator iterator = symbolTable.getSymbolIterator(currentName, true);
        return StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(iterator, Spliterator.ORDERED), false)
            .collect(Collectors.toList());
    }

    private Symbol selectSymbolWithinNamespace(List<Symbol> symbols, Namespace targetNamespace, Map<String, Object> args) throws GhidraMcpException {
        List<Symbol> scopedMatches = symbols.stream()
            .filter(symbol -> symbol.getParentNamespace().equals(targetNamespace))
            .collect(Collectors.toList());

        if (scopedMatches.size() == 1) {
            return scopedMatches.get(0);
        }

        if (scopedMatches.isEmpty() && symbols.size() == 1) {
            return symbols.get(0);
        }

        List<String> conflicting = symbols.stream()
            .map(symbol -> symbol.getName(false) + " (ID=" + symbol.getID() + ")")
            .collect(Collectors.toList());

        throw ambiguousSymbolError(args, conflicting);
    }

    private GhidraMcpException multipleIdentifierError(Map<String, Object> args, Optional<Long> symbolIdOpt, Optional<String> currentNameOpt, Optional<String> addressOpt) {
        List<String> providedIdentifiers = new ArrayList<>();
        Map<String, Object> providedValues = new HashMap<>();
        
        if (symbolIdOpt.isPresent()) {
            providedIdentifiers.add(ARG_SYMBOL_ID);
            providedValues.put(ARG_SYMBOL_ID, symbolIdOpt.get());
        }
        if (currentNameOpt.filter(name -> !name.isBlank()).isPresent()) {
            providedIdentifiers.add(ARG_CURRENT_NAME);
            providedValues.put(ARG_CURRENT_NAME, currentNameOpt.get());
        }
        if (addressOpt.filter(addr -> !addr.isBlank()).isPresent()) {
            providedIdentifiers.add(ARG_ADDRESS);
            providedValues.put(ARG_ADDRESS, addressOpt.get());
        }
        
        GhidraMcpError error = GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
            .message("Provide only one identifier: " + String.join(", ", providedIdentifiers))
            .context(new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                "symbol rename identifier selection",
                args,
                providedValues,
                Map.of("identifiersProvided", providedIdentifiers.size())))
            .suggestions(List.of(new GhidraMcpError.ErrorSuggestion(
                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                "Choose a single identifier",
                "Use only one of: " + String.join(", ", providedIdentifiers),
                List.of(
                    "\"" + ARG_SYMBOL_ID + "\": 12345",
                    "\"" + ARG_CURRENT_NAME + "\": \"MySymbol\"",
                    "\"" + ARG_ADDRESS + "\": \"0x401000\""),
                null)))
            .build();
        return new GhidraMcpException(error);
    }

    private GhidraMcpException missingIdentifierError(Map<String, Object> args) {
        Map<String, Object> providedIdentifiers = Map.of(
            ARG_SYMBOL_ID, args.getOrDefault(ARG_SYMBOL_ID, "not provided"),
            ARG_CURRENT_NAME, args.getOrDefault(ARG_CURRENT_NAME, "not provided"),
            ARG_ADDRESS, args.getOrDefault(ARG_ADDRESS, "not provided")
        );

        GhidraMcpError error = GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
            .message("Provide either '" + ARG_SYMBOL_ID + "', '" + ARG_CURRENT_NAME + "', or '" + ARG_ADDRESS + "' to identify the symbol")
            .context(new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                "symbol rename identifiers",
                args,
                providedIdentifiers,
                Map.of("identifiersProvided", 0, "minimumRequired", 1)
            ))
            .suggestions(List.of(new GhidraMcpError.ErrorSuggestion(
                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                "Include at least one identifier",
                "Provide one of: " + ARG_SYMBOL_ID + ", " + ARG_CURRENT_NAME + ", or " + ARG_ADDRESS,
                List.of("\"" + ARG_SYMBOL_ID + "\": 12345", "\"" + ARG_CURRENT_NAME + "\": \"FunctionName\"", "\"" + ARG_ADDRESS + "\": \"0x401000\""),
                null)))
            .build();
        return new GhidraMcpException(error);
    }

    private GhidraMcpException symbolNotFoundById(long symbolId, Map<String, Object> args) {
        GhidraMcpError error = GhidraMcpError.resourceNotFound()
            .errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
            .message("Symbol not found for ID: " + symbolId)
            .context(new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                "symbol lookup",
                args,
                Map.of(ARG_SYMBOL_ID, symbolId),
                Map.of("matched", false)))
            .build();
        return new GhidraMcpException(error);
    }

    private GhidraMcpException symbolNotFoundByName(String currentName, Optional<String> namespaceOpt, Map<String, Object> args) {
        GhidraMcpError error = GhidraMcpError.resourceNotFound()
            .errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
            .message("Symbol not found: " + currentName)
            .context(new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                "symbol lookup",
                args,
                Map.of(ARG_CURRENT_NAME, currentName, ARG_NAMESPACE, namespaceOpt.orElse("global")),
                Map.of("matchesFound", 0)))
            .suggestions(List.of(new GhidraMcpError.ErrorSuggestion(
                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                "List symbols",
                "Use the 'manage_symbols' tool with action 'list' to inspect available symbols",
                null,
                List.of("manage_symbols"))))
            .build();
        return new GhidraMcpException(error);
    }

    private GhidraMcpException namespaceNotFound(String namespaceName) {
        GhidraMcpError error = GhidraMcpError.resourceNotFound()
            .errorCode(GhidraMcpError.ErrorCode.NAMESPACE_NOT_FOUND)
            .message("Namespace not found: " + namespaceName)
            .context(new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                "namespace lookup",
                Map.of(ARG_NAMESPACE, namespaceName),
                Map.of(ARG_NAMESPACE, namespaceName),
                Map.of("namespaceExists", false)))
            .suggestions(List.of(new GhidraMcpError.ErrorSuggestion(
                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                "List namespaces",
                "Use symbol listing or program tree to confirm the namespace name",
                null,
                List.of("manage_symbols"))))
            .build();
        return new GhidraMcpException(error);
    }

    private GhidraMcpException symbolNotFoundByAddress(String address, Map<String, Object> args) {
        GhidraMcpError error = GhidraMcpError.resourceNotFound()
            .errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
            .message("No symbol found at address: " + address)
            .context(new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                "symbol lookup by address",
                args,
                Map.of(ARG_ADDRESS, address),
                Map.of("symbolFound", false)))
            .suggestions(List.of(new GhidraMcpError.ErrorSuggestion(
                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                "Verify the address has symbols",
                "Check if the address contains any symbols or data",
                null,
                List.of("manage_symbols"))))
            .build();
        return new GhidraMcpException(error);
    }

    private GhidraMcpException ambiguousSymbolError(Map<String, Object> args, List<String> candidates) {
        GhidraMcpError error = GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
            .message("Multiple symbols matched the provided criteria")
            .context(new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                "symbol disambiguation",
                args,
                Map.of("candidates", candidates),
                Map.of("matchCount", candidates.size())))
            .suggestions(List.of(new GhidraMcpError.ErrorSuggestion(
                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                "Disambiguate the symbol",
                "Provide the 'symbolId' or a fully qualified name via 'namespace'",
                List.of("\"symbolId\": 12345", "\"namespace\": \"MyNamespace\""),
                null)))
            .build();
        return new GhidraMcpException(error);
    }

    private record SymbolResolveResult(Symbol symbol, String originalDisplayName, Namespace targetNamespace) {}

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

            return OperationResult
                .success("delete_symbol", symbolToDelete.getAddress().toString(), "Symbol deleted successfully")
                .setMetadata(Map.of(
                    "name", symbolToDelete.getName(),
                    "address", symbolToDelete.getAddress().toString()));
        });
    }

    private GhidraMcpError createSymbolNotFoundError(String toolOperation, String searchType, String searchValue) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
            .message("Symbol not found using " + searchType + ": " + searchValue)
            .context(new GhidraMcpError.ErrorContext(
                toolOperation,
                "symbol resolution",
                Map.of(searchType, searchValue),
                Map.of(),
                Map.of("searchMethod", searchType)))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Verify the symbol exists",
                    "Check that the symbol identifier is correct",
                    List.of(
                        "\"symbol_id\": 12345",
                        "\"address\": \"0x401000\"",
                        "\"name\": \"main\""
                    ),
                    null)))
            .build();
    }

    private GhidraMcpError createInvalidAddressError(String addressStr, Exception cause) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
            .message("Invalid address format: " + addressStr)
            .context(new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                "address parsing",
                Map.of(ARG_ADDRESS, addressStr),
                Map.of(),
                Map.of("parseError", cause.getMessage())))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Use valid hexadecimal address format",
                    "Provide address in proper format",
                    List.of("0x401000", "401000", "0x00401000"),
                    null)))
            .build();
    }

    private GhidraMcpError createInvalidRegexError(String pattern, Exception cause) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
            .message("Invalid regex pattern: " + cause.getMessage())
            .context(new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                "regex compilation",
                Map.of(ARG_NAME, pattern),
                Map.of(),
                Map.of("regexError", cause.getMessage())))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Provide a valid Java regex pattern",
                    "Use proper regex syntax for pattern matching",
                    List.of(".*main.*", "decrypt_.*", "^get.*"),
                    null)))
            .build();
    }

    private GhidraMcpError createMissingParameterError(String toolOperation) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
            .message("No search parameters provided")
            .context(new GhidraMcpError.ErrorContext(
                toolOperation,
                "parameter validation",
                Map.of(),
                Map.of(),
                Map.of("availableParameters", List.of(ARG_SYMBOL_ID, ARG_ADDRESS, ARG_NAME))))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Provide at least one search parameter",
                    "Use symbol_id, address, or name parameter",
                    List.of(
                        "\"symbol_id\": 12345",
                        "\"address\": \"0x401000\"",
                        "\"name\": \"main\"",
                        "\"name\": \".*decrypt.*\""
                    ),
                    null)))
            .build();
    }
}