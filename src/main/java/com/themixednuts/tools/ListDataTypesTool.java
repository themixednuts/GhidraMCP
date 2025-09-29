package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DataTypeInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterator;
import java.util.Spliterators;

@GhidraMcpTool(
    name = "List Data Types",
    description = "List data types in a Ghidra program with pagination and filtering options.",
    mcpName = "list_data_types",
    mcpDescription = """
    <use_case>
    Browse and list data types in Ghidra programs with optional filtering by name pattern,
    category path, and data type kind. Returns paginated results with detailed data type
    information including structure, union, enum, and other type details.
    </use_case>

    <important_notes>
    - Results are paginated to prevent overwhelming responses
    - Supports filtering by name patterns, category paths, and type kinds
    - Data types are sorted by path name for consistent ordering
    - Returns detailed data type information including type-specific details
    </important_notes>

    <examples>
    List first page of data types:
    {
      "fileName": "program.exe"
    }

    List data types with name filter:
    {
      "fileName": "program.exe",
      "nameFilter": "struct"
    }

    Filter by category:
    {
      "fileName": "program.exe",
      "categoryFilter": "/winapi"
    }

    Get next page of results:
    {
      "fileName": "program.exe",
      "cursor": "struct_name:/winapi/STRUCT"
    }
    </examples>
    """
)
public class ListDataTypesTool implements IGhidraMcpSpecification {

    public static final String ARG_NAME_FILTER = "nameFilter";
    public static final String ARG_CATEGORY_FILTER = "categoryFilter";
    public static final String ARG_TYPE_KIND = "typeKind";
    public static final String ARG_CURSOR = "cursor";

    private static final int DEFAULT_PAGE_LIMIT = 50;

    /**
     * Defines the JSON input schema for listing data types.
     * 
     * @return The JsonSchema defining the expected input arguments
     */
    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_NAME_FILTER,
                JsonSchemaBuilder.string(mapper)
                        .description("Filter data types by name (case-insensitive substring match)"));

        schemaRoot.property(ARG_CATEGORY_FILTER,
                JsonSchemaBuilder.string(mapper)
                        .description("Filter by category path (e.g., '/winapi', '/custom')"));

        schemaRoot.property(ARG_TYPE_KIND,
                JsonSchemaBuilder.string(mapper)
                        .description("Filter by data type kind (e.g., 'structure', 'union', 'enum', 'typedef', 'pointer')"));

        schemaRoot.property(ARG_CURSOR,
                JsonSchemaBuilder.string(mapper)
                        .description("Pagination cursor from previous request"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);

        return schemaRoot.build();
    }

    /**
     * Executes the data type listing operation.
     * 
     * @param context The MCP transport context
     * @param args The tool arguments containing fileName and optional filters
     * @param tool The Ghidra PluginTool context
     * @return A Mono emitting a PaginatedResult containing DataTypeInfo objects
     */
    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool).flatMap(program -> {
            return Mono.fromCallable(() -> listDataTypes(program, args));
        });
    }

    /**
     * Lists data types in the program with optional filtering and pagination.
     * 
     * @param program The Ghidra program to list data types from
     * @param args The arguments containing optional filters and cursor
     * @return A PaginatedResult containing DataTypeInfo objects
     * @throws GhidraMcpException If there's an error processing the data types
     */
    private PaginatedResult<DataTypeInfo> listDataTypes(Program program, Map<String, Object> args) throws GhidraMcpException {
        DataTypeManager dataTypeManager = program.getDataTypeManager();

        Optional<String> nameFilterOpt = getOptionalStringArgument(args, ARG_NAME_FILTER);
        Optional<String> categoryFilterOpt = getOptionalStringArgument(args, ARG_CATEGORY_FILTER);
        Optional<String> typeKindOpt = getOptionalStringArgument(args, ARG_TYPE_KIND);
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

        // Get all data types and apply filters
        Iterator<DataType> dataTypeIterator = dataTypeManager.getAllDataTypes();
        List<DataTypeInfo> allDataTypes = StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(dataTypeIterator, Spliterator.ORDERED), false)
            .filter(dataType -> {
                // Apply name filter
                if (nameFilterOpt.isPresent() && !nameFilterOpt.get().isEmpty()) {
                    if (!dataType.getName().toLowerCase().contains(nameFilterOpt.get().toLowerCase())) {
                        return false;
                    }
                }

                // Apply category filter
                if (categoryFilterOpt.isPresent() && !categoryFilterOpt.get().isEmpty()) {
                    String categoryPath = dataType.getCategoryPath().getPath();
                    if (!categoryPath.toLowerCase().contains(categoryFilterOpt.get().toLowerCase())) {
                        return false;
                    }
                }

                // Apply type kind filter
                if (typeKindOpt.isPresent() && !typeKindOpt.get().isEmpty()) {
                    String typeKind = typeKindOpt.get().toLowerCase();
                    String dataTypeName = dataType.getClass().getSimpleName().toLowerCase();

                    // Map common type kinds to class names
                    boolean matches = switch (typeKind) {
                        case "structure", "struct" -> dataTypeName.contains("structure");
                        case "union" -> dataTypeName.contains("union");
                        case "enum" -> dataTypeName.contains("enum");
                        case "typedef" -> dataTypeName.contains("typedef");
                        case "pointer" -> dataTypeName.contains("pointer");
                        case "array" -> dataTypeName.contains("array");
                        case "function" -> dataTypeName.contains("function");
                        default -> dataTypeName.contains(typeKind);
                    };

                    if (!matches) {
                        return false;
                    }
                }

                return true;
            })
            .sorted((dt1, dt2) -> dt1.getPathName().compareToIgnoreCase(dt2.getPathName()))
            .map(DataTypeInfo::new)
            .collect(Collectors.toList());

        // Apply cursor-based pagination
        final String finalCursorStr = cursorOpt.orElse(null);

        List<DataTypeInfo> paginatedDataTypes = allDataTypes.stream()
            .dropWhile(dataTypeInfo -> {
                if (finalCursorStr == null) return false;

                // Cursor format: "name:pathName"
                String[] parts = finalCursorStr.split(":", 2);
                String cursorName = parts[0];
                String cursorPathName = parts.length > 1 ? parts[1] : "";

                int nameCompare = dataTypeInfo.getDetails().getName().compareToIgnoreCase(cursorName);
                if (nameCompare < 0) return true;
                if (nameCompare == 0) {
                    return dataTypeInfo.getDetails().getPath().compareTo(cursorPathName) <= 0;
                }
                return false;
            })
            .limit(DEFAULT_PAGE_LIMIT + 1)
            .collect(Collectors.toList());

        boolean hasMore = paginatedDataTypes.size() > DEFAULT_PAGE_LIMIT;
        List<DataTypeInfo> resultsForPage = paginatedDataTypes.subList(0,
            Math.min(paginatedDataTypes.size(), DEFAULT_PAGE_LIMIT));

        String nextCursor = null;
        if (hasMore && !resultsForPage.isEmpty()) {
            DataTypeInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
            nextCursor = lastItem.getDetails().getName() + ":" + lastItem.getDetails().getPath();
        }

        return new PaginatedResult<>(resultsForPage, nextCursor);
    }
}