package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@GhidraMcpTool(
    name = "List Functions",
    description = "List functions in a Ghidra program with pagination and filtering options.",
    mcpName = "list_functions",
    mcpDescription = """
    <use_case>
    Browse and list functions in Ghidra programs with optional filtering by name pattern
    and pagination support. Returns paginated results with function details including
    addresses, signatures, and metadata.
    </use_case>

    <important_notes>
    - Results are paginated to prevent overwhelming responses
    - Supports filtering by name patterns (regex)
    - Functions are sorted by entry point address for consistent ordering
    - Returns detailed function information including signatures when available
    </important_notes>

    <examples>
    List first page of functions:
    {
      "fileName": "program.exe"
    }

    List functions matching pattern:
    {
      "fileName": "program.exe",
      "namePattern": ".*decrypt.*"
    }

    Get next page of results:
    {
      "fileName": "program.exe",
      "cursor": "0x401000:main"
    }
    </examples>
    """
)
public class ListFunctionsTool implements IGhidraMcpSpecification {

    public static final String ARG_NAME_PATTERN = "namePattern";
    public static final String ARG_CURSOR = "cursor";

    private static final int DEFAULT_PAGE_LIMIT = 50;

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_NAME_PATTERN,
                JsonSchemaBuilder.string(mapper)
                        .description("Optional regex pattern to filter function names"));

        schemaRoot.property(ARG_CURSOR,
                JsonSchemaBuilder.string(mapper)
                        .description("Pagination cursor from previous request"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool).flatMap(program -> {
            return Mono.fromCallable(() -> listFunctions(program, args));
        });
    }

    private PaginatedResult<FunctionInfo> listFunctions(Program program, Map<String, Object> args) throws GhidraMcpException {
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
                    return false; // Skip functions with invalid regex
                }
            })
            .sorted((f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()))
            .map(FunctionInfo::new)
            .collect(Collectors.toList());

        // Apply cursor-based pagination
        final String finalCursorStr = cursorOpt.orElse(null);

        List<FunctionInfo> paginatedFunctions = allFunctions.stream()
            .dropWhile(funcInfo -> {
                if (finalCursorStr == null) return false;

                // Cursor format: "address:name"
                String[] parts = finalCursorStr.split(":", 2);
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
        List<FunctionInfo> resultsForPage = paginatedFunctions.subList(0,
            Math.min(paginatedFunctions.size(), DEFAULT_PAGE_LIMIT));

        String nextCursor = null;
        if (hasMore && !resultsForPage.isEmpty()) {
            FunctionInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
            nextCursor = lastItem.getAddress() + ":" + lastItem.getName();
        }

        return new PaginatedResult<>(resultsForPage, nextCursor);
    }
}