package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@GhidraMcpTool(name = "Read Functions", description = "Read a single function or list functions in a Ghidra program with pagination and filtering options.", mcpName = "read_functions", mcpDescription = """
        <use_case>
        Read a single function by identifier (symbol_id, address, name) or browse/list functions
        in Ghidra programs with optional filtering by name pattern and pagination support.
        Returns detailed function information including addresses, signatures, and metadata.
        </use_case>

        <important_notes>
        - Supports two modes: single function read (provide symbol_id/address/name) or list mode (no identifiers)
        - When reading a single function, returns FunctionInfo object directly
        - When listing functions, returns paginated results with cursor support
        - Supports filtering by name patterns (regex) in list mode
        - Functions are sorted by entry point address for consistent ordering
        - Name-based lookup supports regex matching with disambiguation for multiple matches
        </important_notes>

        <examples>
        Read a single function by address:
        {
          "fileName": "program.exe",
          "address": "0x401000"
        }

        Read a single function by name:
        {
          "fileName": "program.exe",
          "name": "main"
        }

        Read a single function by symbol ID:
        {
          "fileName": "program.exe",
          "symbol_id": 12345
        }

        List all functions (first page):
        {
          "fileName": "program.exe"
        }

        List functions matching pattern:
        {
          "fileName": "program.exe",
          "name_pattern": ".*decrypt.*"
        }

        Get next page of results:
        {
          "fileName": "program.exe",
          "cursor": "0x401000:main"
        }
        </examples>
        """)
public class ReadFunctionsTool implements IGhidraMcpSpecification {

    public static final String ARG_SYMBOL_ID = "symbol_id";
    public static final String ARG_ADDRESS = "address";
    public static final String ARG_NAME = "name";
    public static final String ARG_NAME_PATTERN = "name_pattern";

    private static final int DEFAULT_PAGE_LIMIT = 50;

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_SYMBOL_ID, JsonSchemaBuilder.integer(mapper)
                .description("Symbol ID to identify a specific function (single read mode)"));

        schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
                .description("Function address to identify a specific function (single read mode)")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
                .description("Function name for single function lookup (supports regex matching)"));

        schemaRoot.property(ARG_NAME_PATTERN,
                JsonSchemaBuilder.string(mapper)
                        .description("Optional regex pattern to filter function names (list mode)"));

        schemaRoot.property(ARG_CURSOR,
                JsonSchemaBuilder.string(mapper)
                        .description("Pagination cursor from previous request (list mode)"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool).flatMap(program -> {
            // Check if this is a single function read or a list operation
            boolean hasSingleIdentifier = args.containsKey(ARG_SYMBOL_ID) ||
                    args.containsKey(ARG_ADDRESS) ||
                    args.containsKey(ARG_NAME);

            if (hasSingleIdentifier) {
                return handleRead(program, args);
            } else {
                return Mono.fromCallable(() -> listFunctions(program, args));
            }
        });
    }

    private Mono<? extends Object> handleRead(Program program, Map<String, Object> args) {
        return Mono.fromCallable(() -> {
            FunctionManager functionManager = program.getFunctionManager();
            GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

            // Apply precedence: symbol_id > address > name
            if (args.containsKey(ARG_SYMBOL_ID)) {
                Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
                if (symbolId != null) {
                    Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
                    if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
                        Function function = functionManager.getFunctionAt(symbol.getAddress());
                        if (function != null) {
                            return new FunctionInfo(function);
                        }
                    }
                }
                throw new GhidraMcpException(
                        createFunctionNotFoundError(annotation.mcpName(), "symbol_id", symbolId.toString()));
            } else if (args.containsKey(ARG_ADDRESS)) {
                String address = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
                if (address != null && !address.trim().isEmpty()) {
                    try {
                        Address functionAddress = program.getAddressFactory().getAddress(address);
                        if (functionAddress != null) {
                            Function function = functionManager.getFunctionAt(functionAddress);
                            if (function != null) {
                                return new FunctionInfo(function);
                            }
                        }
                    } catch (Exception e) {
                        throw new GhidraMcpException(createInvalidAddressError(address, e));
                    }
                }
                throw new GhidraMcpException(createFunctionNotFoundError(annotation.mcpName(), "address", address));
            } else if (args.containsKey(ARG_NAME)) {
                String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
                if (name != null && !name.trim().isEmpty()) {
                    // First try exact match
                    Optional<Function> exactMatch = StreamSupport
                            .stream(functionManager.getFunctions(true).spliterator(), false)
                            .filter(f -> f.getName().equals(name))
                            .findFirst();

                    if (exactMatch.isPresent()) {
                        return new FunctionInfo(exactMatch.get());
                    }

                    // Then try regex match
                    try {
                        List<Function> regexMatches = StreamSupport
                                .stream(functionManager.getFunctions(true).spliterator(), false)
                                .filter(f -> f.getName().matches(name))
                                .collect(Collectors.toList());

                        if (regexMatches.size() == 1) {
                            return new FunctionInfo(regexMatches.get(0));
                        } else if (regexMatches.size() > 1) {
                            throw new GhidraMcpException(
                                    createMultipleFunctionsFoundError(annotation.mcpName(), name, regexMatches));
                        }
                    } catch (Exception e) {
                        throw new GhidraMcpException(createInvalidRegexError(name, e));
                    }
                }
                throw new GhidraMcpException(createFunctionNotFoundError(annotation.mcpName(), "name", name));
            } else {
                throw new GhidraMcpException(createMissingParameterError());
            }
        });
    }

    private PaginatedResult<FunctionInfo> listFunctions(Program program, Map<String, Object> args)
            throws GhidraMcpException {
        FunctionManager functionManager = program.getFunctionManager();

        Optional<String> namePatternOpt = getOptionalStringArgument(args, ARG_NAME_PATTERN);
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

        // Get all functions and apply name filter if provided
        List<FunctionInfo> allFunctions = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                .filter(function -> {
                    if (namePatternOpt.isEmpty())
                        return true;
                    try {
                        return function.getName().matches(namePatternOpt.get());
                    } catch (Exception e) {
                        return false;
                    }
                })
                .sorted((f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()))
                .map(FunctionInfo::new)
                .collect(Collectors.toList());

        // Apply cursor-based pagination
        final String finalCursorStr = cursorOpt.orElse(null);

        List<FunctionInfo> paginatedFunctions = allFunctions.stream()
                .dropWhile(funcInfo -> {
                    if (finalCursorStr == null)
                        return false;

                    // Cursor format: "address:name"
                    String[] parts = finalCursorStr.split(":", 2);
                    String cursorAddress = parts[0];
                    String cursorName = parts.length > 1 ? parts[1] : "";

                    int addressCompare = funcInfo.getAddress().compareTo(cursorAddress);
                    if (addressCompare < 0)
                        return true;
                    if (addressCompare == 0) {
                        return funcInfo.getName().compareTo(cursorName) <= 0;
                    }
                    return false;
                })
                .limit(DEFAULT_PAGE_LIMIT + 1)
                .collect(Collectors.toList());

        boolean hasMore = paginatedFunctions.size() > DEFAULT_PAGE_LIMIT;
        List<FunctionInfo> resultsForPage = paginatedFunctions.subList(0,
                Math.min(paginatedFunctions.size(), DEFAULT_PAGE_LIMIT));

        String nextCursor = null;
        if (hasMore && !resultsForPage.isEmpty()) {
            FunctionInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
            nextCursor = lastItem.getAddress() + ":" + lastItem.getName();
        }

        return new PaginatedResult<>(resultsForPage, nextCursor);
    }

    private GhidraMcpError createFunctionNotFoundError(String toolOperation, String searchType, String searchValue) {
        return GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                .message("Function not found using " + searchType + ": " + searchValue)
                .context(new GhidraMcpError.ErrorContext(
                        toolOperation,
                        "function resolution",
                        Map.of(searchType, searchValue),
                        Map.of(),
                        Map.of("searchMethod", searchType)))
                .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Verify the function exists",
                                "Check that the function identifier is correct",
                                List.of(
                                        "\"symbol_id\": 12345",
                                        "\"address\": \"0x401000\"",
                                        "\"name\": \"main\""),
                                null)))
                .build();
    }

    private GhidraMcpError createMultipleFunctionsFoundError(String toolOperation, String searchValue,
            List<Function> functions) {
        List<String> functionNames = functions.stream()
                .map(Function::getName)
                .limit(5)
                .collect(Collectors.toList());

        return GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Multiple functions found for name pattern: " + searchValue)
                .context(new GhidraMcpError.ErrorContext(
                        toolOperation,
                        "function resolution",
                        Map.of("name", searchValue),
                        Map.of("matchCount", functions.size()),
                        Map.of("firstFiveMatches", functionNames)))
                .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a more specific function identifier",
                                "Consider using symbol_id or address for exact identification",
                                List.of(
                                        "\"symbol_id\": 12345",
                                        "\"address\": \"0x401000\"",
                                        "\"name\": \"exact_function_name\""),
                                null)))
                .build();
    }

    private GhidraMcpError createInvalidAddressError(String addressStr, Exception cause) {
        return GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                .message("Invalid address format: " + addressStr)
                .context(new GhidraMcpError.ErrorContext(
                        this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
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
                        this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
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

    private GhidraMcpError createMissingParameterError() {
        return GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                .message("No search parameters provided")
                .context(new GhidraMcpError.ErrorContext(
                        this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
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
                                        "\"name\": \".*decrypt.*\""),
                                null)))
                .build();
    }
}
