package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@GhidraMcpTool(
    name = "Read Functions",
    description = "Read a single function or list functions in a Ghidra program with pagination and filtering options.",
    mcpName = "read_functions",
    title = "Read Functions",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription = """
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
          "file_name": "program.exe",
          "address": "0x401000"
        }

        Read a single function by name:
        {
          "file_name": "program.exe",
          "name": "main"
        }

        Read a single function by symbol ID:
        {
          "file_name": "program.exe",
          "symbol_id": 12345
        }

        List all functions (first page):
        {
          "file_name": "program.exe"
        }

        List functions matching pattern:
        {
          "file_name": "program.exe",
          "name_pattern": ".*decrypt.*"
        }

        Get next page of results:
        {
          "file_name": "program.exe",
          "cursor": "0x401000:main"
        }
        </examples>
        """
)
public class ReadFunctionsTool extends BaseMcpTool {

    @Override
    public JsonSchema schema() {
        var schemaRoot = createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                SchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_SYMBOL_ID, SchemaBuilder.integer(mapper)
                .description("Symbol ID to identify a specific function (single read mode)"));

        schemaRoot.property(ARG_ADDRESS, SchemaBuilder.string(mapper)
                .description("Function address to identify a specific function (single read mode)")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_NAME, SchemaBuilder.string(mapper)
                .description("Function name for single function lookup (supports regex matching)"));

        schemaRoot.property(ARG_NAME_PATTERN,
                SchemaBuilder.string(mapper)
                        .description("Optional regex pattern to filter function names (list mode)"));

        schemaRoot.property(ARG_CURSOR,
                SchemaBuilder.string(mapper)
                        .description("Pagination cursor from previous request (list mode)"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool).flatMap(program -> {
            boolean hasSingleIdentifier = args.containsKey(ARG_SYMBOL_ID) ||
                    args.containsKey(ARG_ADDRESS) ||
                    args.containsKey(ARG_NAME);

            if (hasSingleIdentifier) {
                return readSingleFunction(program, args);
            } else {
                return Mono.fromCallable(() -> listFunctions(program, args));
            }
        });
    }

    private Mono<FunctionInfo> readSingleFunction(Program program, Map<String, Object> args) {
        return Mono.fromCallable(() -> {
            FunctionManager functionManager = program.getFunctionManager();

            // Apply precedence: symbol_id > address > name
            if (args.containsKey(ARG_SYMBOL_ID)) {
                return readBySymbolId(program, functionManager, args);
            } else if (args.containsKey(ARG_ADDRESS)) {
                return readByAddress(program, functionManager, args);
            } else if (args.containsKey(ARG_NAME)) {
                return readByName(functionManager, args);
            } else {
                throw new GhidraMcpException(GhidraMcpError.missing("symbol_id, address, or name"));
            }
        });
    }

    private FunctionInfo readBySymbolId(Program program, FunctionManager functionManager, Map<String, Object> args)
            throws GhidraMcpException {
        Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
        if (symbolId == null) {
            throw new GhidraMcpException(GhidraMcpError.missing(ARG_SYMBOL_ID));
        }

        Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
        if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
            Function function = functionManager.getFunctionAt(symbol.getAddress());
            if (function != null) {
                return new FunctionInfo(function);
            }
        }

        throw new GhidraMcpException(GhidraMcpError.notFound("function", "symbol_id=" + symbolId));
    }

    private FunctionInfo readByAddress(Program program, FunctionManager functionManager, Map<String, Object> args)
            throws GhidraMcpException {
        String addressStr = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
        if (addressStr == null || addressStr.isBlank()) {
            throw new GhidraMcpException(GhidraMcpError.missing(ARG_ADDRESS));
        }

        try {
            Address functionAddress = program.getAddressFactory().getAddress(addressStr);
            if (functionAddress != null) {
                Function function = functionManager.getFunctionAt(functionAddress);
                if (function != null) {
                    return new FunctionInfo(function);
                }
            }
        } catch (Exception e) {
            throw new GhidraMcpException(GhidraMcpError.parse("address", addressStr));
        }

        throw new GhidraMcpException(GhidraMcpError.notFound("function", "address=" + addressStr));
    }

    private FunctionInfo readByName(FunctionManager functionManager, Map<String, Object> args)
            throws GhidraMcpException {
        String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
        if (name == null || name.isBlank()) {
            throw new GhidraMcpException(GhidraMcpError.missing(ARG_NAME));
        }

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
                        GhidraMcpError.conflict("Multiple functions found for name pattern: " + name));
            }
        } catch (GhidraMcpException e) {
            throw e;
        } catch (Exception e) {
            throw new GhidraMcpException(GhidraMcpError.invalid("pattern", name, e.getMessage()));
        }

        throw new GhidraMcpException(GhidraMcpError.notFound("function", "name=" + name));
    }

    private List<FunctionInfo> listFunctions(Program program, Map<String, Object> args) {
        FunctionManager functionManager = program.getFunctionManager();

        Optional<String> namePatternOpt = getOptionalStringArgument(args, ARG_NAME_PATTERN);
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

        // Get all functions and apply name filter if provided
        List<FunctionInfo> allFunctions = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                .filter(function -> {
                    if (namePatternOpt.isEmpty()) return true;
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
        final String cursorStr = cursorOpt.orElse(null);

        List<FunctionInfo> paginatedFunctions = allFunctions.stream()
                .dropWhile(funcInfo -> {
                    if (cursorStr == null) return false;

                    String[] parts = cursorStr.split(":", 2);
                    String cursorAddress = parts[0];
                    String cursorName = parts.length > 1 ? parts[1] : "";

                    int addressCompare = funcInfo.getAddress().compareTo(cursorAddress);
                    if (addressCompare < 0) return true;
                    if (addressCompare == 0) {
                        return funcInfo.getName().compareTo(cursorName) <= 0;
                    }
                    return false;
                })
                .limit(DEFAULT_PAGE_LIMIT + 1)
                .collect(Collectors.toList());

        boolean hasMore = paginatedFunctions.size() > DEFAULT_PAGE_LIMIT;
        return paginatedFunctions.subList(0, Math.min(paginatedFunctions.size(), DEFAULT_PAGE_LIMIT));
    }
}
