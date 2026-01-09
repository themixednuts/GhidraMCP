package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DataTypeInfo;
import com.themixednuts.models.DataTypeReadResult;
import com.themixednuts.models.DataTypeReadResult.DataTypeComponentDetail;
import com.themixednuts.models.DataTypeReadResult.DataTypeEnumValue;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.RTTIAnalysisResult;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.util.datatype.microsoft.RTTI0DataType;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;

@GhidraMcpTool(name = "Read Data Types", description = "Read a single data type or list data types in a Ghidra program with pagination and filtering options.", mcpName = "read_data_types", mcpDescription = """
        <use_case>
        Read a single data type with detailed information (components, enum values, etc.) or browse/list
        data types in Ghidra programs with optional filtering by name pattern, category path, and type kind.
        Returns detailed data type information including structure members, enum values, and type metadata.
        </use_case>

        <important_notes>
        - Supports two modes: single data type read (provide name/data_type_id/address) or list mode (no identifiers)
        - When reading a single data type, returns DataTypeReadResult with full details
        - When listing data types, returns paginated results with cursor support
        - Supports filtering by name patterns, category paths, and type kinds in list mode
        - For RTTI types, can analyze at specific addresses when address parameter is provided
        - Data types are sorted by path name for consistent ordering
        </important_notes>

        <examples>
        Read a single data type by ID:
        {
          "fileName": "program.exe",
          "data_type_kind": "struct",
          "data_type_id": 12345
        }

        Read a single data type by name:
        {
          "fileName": "program.exe",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "category_path": "/MyTypes"
        }

        Analyze RTTI at address:
        {
          "fileName": "program.exe",
          "data_type_kind": "rtti0",
          "address": "0x401000"
        }

        List all data types (first page):
        {
          "fileName": "program.exe"
        }

        List data types with name filter:
        {
          "fileName": "program.exe",
          "name_filter": "struct"
        }

        Get next page of results:
        {
          "fileName": "program.exe",
          "cursor": "struct_name:/winapi/STRUCT"
        }
        </examples>
        """)
public class ReadDataTypesTool extends BaseMcpTool {

    public static final String ARG_DATA_TYPE_KIND = "data_type_kind";
    public static final String ARG_NAME_FILTER = "name_filter";
    public static final String ARG_CATEGORY_FILTER = "category_filter";
    public static final String ARG_TYPE_KIND = "type_kind";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                SchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_DATA_TYPE_KIND, SchemaBuilder.string(mapper)
                .description("Type of data type (for single read mode)"));

        schemaRoot.property(ARG_NAME, SchemaBuilder.string(mapper)
                .description("Name of the data type (for single read mode)"));

        schemaRoot.property(ARG_CATEGORY_PATH, SchemaBuilder.string(mapper)
                .description("Category path of the data type (for single read mode)")
                .defaultValue("/"));

        schemaRoot.property(ARG_DATA_TYPE_ID, SchemaBuilder.integer(mapper)
                .description("Data type ID for direct lookup (for single read mode)"));

        schemaRoot.property(ARG_ADDRESS, SchemaBuilder.string(mapper)
                .description("Address to analyze for RTTI structure information (for RTTI read mode)")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_NAME_FILTER,
                SchemaBuilder.string(mapper)
                        .description("Filter data types by name (case-insensitive substring match, list mode)"));

        schemaRoot.property(ARG_CATEGORY_FILTER,
                SchemaBuilder.string(mapper)
                        .description("Filter by category path (e.g., '/winapi', '/custom', list mode)"));

        schemaRoot.property(ARG_TYPE_KIND,
                SchemaBuilder.string(mapper)
                        .description(
                                "Filter by data type kind (e.g., 'structure', 'union', 'enum', 'typedef', 'pointer', list mode)"));

        schemaRoot.property(ARG_CURSOR,
                SchemaBuilder.string(mapper)
                        .description("Pagination cursor from previous request (list mode)"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool).flatMap(program -> {
            // Check if this is a single data type read or a list operation
            boolean hasSingleIdentifier = args.containsKey(ARG_DATA_TYPE_KIND) &&
                    (args.containsKey(ARG_NAME) || args.containsKey(ARG_DATA_TYPE_ID) || args.containsKey(ARG_ADDRESS));

            if (hasSingleIdentifier) {
                return handleRead(program, args);
            } else {
                return Mono.fromCallable(() -> listDataTypes(program, args));
            }
        });
    }

    private Mono<? extends Object> handleRead(Program program, Map<String, Object> args) {
        return Mono.fromCallable(() -> {
            String dataTypeKind = getRequiredStringArgument(args, ARG_DATA_TYPE_KIND);

            // Check if this is an RTTI analysis request
            Optional<String> analyzeAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
            if (analyzeAddressOpt.isPresent()) {
                return analyzeRTTIAtAddress(program, analyzeAddressOpt.get(), dataTypeKind);
            }

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = null;

            // Try data type ID lookup first (most direct)
            Optional<Long> dataTypeIdOpt = getOptionalLongArgument(args, ARG_DATA_TYPE_ID);
            if (dataTypeIdOpt.isPresent()) {
                dataType = dtm.getDataType(dataTypeIdOpt.get());
            }

            // Fallback to name-based lookup if ID wasn't provided or didn't find anything
            Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);
            if (dataType == null && nameOpt.isPresent()) {
                CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
                        .map(CategoryPath::new).orElse(CategoryPath.ROOT);
                dataType = dtm.getDataType(categoryPath, nameOpt.get());
            }

            if (dataType == null) {
                String identifier = nameOpt
                        .or(() -> dataTypeIdOpt.map(String::valueOf))
                        .orElse("unknown");
                throw new GhidraMcpException(
                        GhidraMcpError.notFound("Data type", identifier,
                                "Use read_data_types without identifiers to see what's available"));
            }

            List<DataTypeComponentDetail> components = null;
            List<DataTypeEnumValue> enumValues = null;
            int componentCount = 0;
            int valueCount = 0;

            if (dataType instanceof Structure struct) {
                components = Arrays.stream(struct.getComponents())
                        .map(comp -> new DataTypeComponentDetail(
                                Optional.ofNullable(comp.getFieldName()).orElse(""),
                                comp.getDataType().getName(),
                                comp.getOffset(),
                                comp.getLength()))
                        .collect(Collectors.toList());
                componentCount = struct.getNumComponents();
            } else if (dataType instanceof ghidra.program.model.data.Enum enumType) {
                enumValues = Arrays.stream(enumType.getNames())
                        .map(valueName -> new DataTypeEnumValue(valueName, enumType.getValue(valueName)))
                        .collect(Collectors.toList());
                valueCount = enumType.getCount();
            } else if (dataType instanceof Union union) {
                components = Arrays.stream(union.getComponents())
                        .map(comp -> new DataTypeComponentDetail(
                                Optional.ofNullable(comp.getFieldName()).orElse(""),
                                comp.getDataType().getName(),
                                null,
                                comp.getLength()))
                        .collect(Collectors.toList());
                componentCount = union.getNumComponents();
            } else if (dataType instanceof RTTI0DataType) {
                components = List.of(
                        new DataTypeComponentDetail("vfTablePointer", "Pointer", 0, 8),
                        new DataTypeComponentDetail("dataPointer", "Pointer", 8, 8),
                        new DataTypeComponentDetail("name", "NullTerminatedString", 16, -1));
                componentCount = 3;
            }

            return new DataTypeReadResult(
                    dataType.getName(),
                    dataType.getPathName(),
                    getDataTypeKind(dataType),
                    dataType.getLength(),
                    dataType.getDescription(),
                    components,
                    enumValues,
                    componentCount,
                    valueCount);
        });
    }

    private PaginatedResult<DataTypeInfo> listDataTypes(Program program, Map<String, Object> args)
            throws GhidraMcpException {
        DataTypeManager dtm = program.getDataTypeManager();

        Optional<String> nameFilterOpt = getOptionalStringArgument(args, ARG_NAME_FILTER);
        Optional<String> categoryFilterOpt = getOptionalStringArgument(args, ARG_CATEGORY_FILTER);
        Optional<String> typeKindOpt = getOptionalStringArgument(args, ARG_TYPE_KIND);
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

        // Parse cursor for pagination
        String cursorPath = null;
        if (cursorOpt.isPresent()) {
            String[] parts = cursorOpt.get().split(":", 2);
            cursorPath = parts.length > 1 ? parts[1] : parts[0];
        }

        // Use type-specific iterators when type_kind is specified for better performance
        Iterator<? extends DataType> dataTypeIterator = getTypeSpecificIterator(dtm, typeKindOpt);

        // If name filter is specified, use native findDataTypes with wildcard support
        List<DataType> searchResults = null;
        if (nameFilterOpt.isPresent() && !nameFilterOpt.get().isEmpty() && typeKindOpt.isEmpty()) {
            searchResults = new ArrayList<>();
            // Use wildcard pattern for native search - supports * and ?
            String searchPattern = "*" + nameFilterOpt.get() + "*";
            dtm.findDataTypes(searchPattern, searchResults, false, TaskMonitor.DUMMY);
        }

        List<DataTypeInfo> results = new ArrayList<>();
        final String finalCursorPath = cursorPath;
        final String finalCategoryFilter = categoryFilterOpt.orElse(null);
        final String finalNameFilter = nameFilterOpt.orElse(null);
        final String finalTypeKind = typeKindOpt.orElse(null);
        boolean passedCursor = (cursorPath == null);

        // Process either search results or iterator
        if (searchResults != null) {
            // Sort search results by path name for consistent ordering
            searchResults.sort((dt1, dt2) -> dt1.getPathName().compareToIgnoreCase(dt2.getPathName()));

            for (DataType dataType : searchResults) {
                if (results.size() > DEFAULT_PAGE_LIMIT) break;

                // Skip past cursor
                if (!passedCursor) {
                    if (dataType.getPathName().compareToIgnoreCase(finalCursorPath) <= 0) {
                        continue;
                    }
                    passedCursor = true;
                }

                // Apply category filter
                if (finalCategoryFilter != null && !finalCategoryFilter.isEmpty()) {
                    if (!dataType.getCategoryPath().getPath().toLowerCase()
                            .contains(finalCategoryFilter.toLowerCase())) {
                        continue;
                    }
                }

                DataTypeInfo info = new DataTypeInfo(dataType);
                info.getDetails().setDataTypeId(dtm.getID(dataType));
                results.add(info);
            }
        } else {
            // Process iterator directly
            while (dataTypeIterator.hasNext() && results.size() <= DEFAULT_PAGE_LIMIT) {
                DataType dataType = dataTypeIterator.next();

                // Skip past cursor (comparing by path name)
                if (!passedCursor) {
                    if (dataType.getPathName().compareToIgnoreCase(finalCursorPath) <= 0) {
                        continue;
                    }
                    passedCursor = true;
                }

                // Apply name filter if not using search
                if (finalNameFilter != null && !finalNameFilter.isEmpty()) {
                    if (!dataType.getName().toLowerCase().contains(finalNameFilter.toLowerCase())) {
                        continue;
                    }
                }

                // Apply category filter
                if (finalCategoryFilter != null && !finalCategoryFilter.isEmpty()) {
                    if (!dataType.getCategoryPath().getPath().toLowerCase()
                            .contains(finalCategoryFilter.toLowerCase())) {
                        continue;
                    }
                }

                // Apply type kind filter for non-specialized iterators
                if (finalTypeKind != null && !matchesTypeKind(dataType, finalTypeKind)) {
                    continue;
                }

                DataTypeInfo info = new DataTypeInfo(dataType);
                info.getDetails().setDataTypeId(dtm.getID(dataType));
                results.add(info);
            }
        }

        // Sort results by path name for consistent ordering
        results.sort((d1, d2) -> d1.getDetails().getPath().compareToIgnoreCase(d2.getDetails().getPath()));

        // Determine if there are more results
        boolean hasMore = results.size() > DEFAULT_PAGE_LIMIT;
        if (hasMore) {
            results = results.subList(0, DEFAULT_PAGE_LIMIT);
        }

        String nextCursor = null;
        if (hasMore && !results.isEmpty()) {
            DataTypeInfo lastItem = results.get(results.size() - 1);
            nextCursor = lastItem.getDetails().getName() + ":" + lastItem.getDetails().getPath();
        }

        return new PaginatedResult<>(results, nextCursor);
    }

    /**
     * Get type-specific iterator for better performance when filtering by type kind.
     * Uses native Ghidra iterators: getAllStructures(), getAllComposites(), getAllFunctionDefinitions()
     */
    private Iterator<? extends DataType> getTypeSpecificIterator(DataTypeManager dtm, Optional<String> typeKindOpt) {
        if (typeKindOpt.isEmpty()) {
            return dtm.getAllDataTypes();
        }

        String typeKind = typeKindOpt.get().toLowerCase();
        return switch (typeKind) {
            case "structure", "struct" -> dtm.getAllStructures();
            case "composite" -> dtm.getAllComposites();  // Structures + Unions
            case "function", "function_definition" -> dtm.getAllFunctionDefinitions();
            default -> dtm.getAllDataTypes();  // Fall back to all types for other filters
        };
    }

    private boolean matchesTypeKind(DataType dataType, String typeKind) {
        String kind = typeKind.toLowerCase();
        return switch (kind) {
            case "structure", "struct" -> dataType instanceof Structure;
            case "union" -> dataType instanceof Union;
            case "composite" -> dataType instanceof Composite;
            case "enum" -> dataType instanceof ghidra.program.model.data.Enum;
            case "typedef" -> dataType instanceof TypeDef;
            case "pointer" -> dataType instanceof Pointer;
            case "array" -> dataType instanceof Array;
            case "function", "function_definition" -> dataType instanceof FunctionDefinition;
            default -> dataType.getClass().getSimpleName().toLowerCase().contains(kind);
        };
    }

    private RTTIAnalysisResult analyzeRTTIAtAddress(Program program, String addressStr, String dataTypeKind)
            throws GhidraMcpException {
        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                throw new GhidraMcpException(
                        GhidraMcpError.invalid("address", addressStr, "Could not parse as valid address"));
            }

            DataTypeManager dtm = program.getDataTypeManager();
            RTTI0DataType rtti0 = new RTTI0DataType(dtm);

            if (!rtti0.isValid(program, address, null)) {
                return RTTIAnalysisResult.invalid(
                        RTTIAnalysisResult.RttiType.RTTI0,
                        addressStr,
                        "No valid RTTI0 structure found at address");
            }

            return RTTIAnalysisResult.from(rtti0, program, address);

        } catch (Exception e) {
            throw new GhidraMcpException(
                    GhidraMcpError.failed("RTTI analysis", e.getMessage()));
        }
    }

    private String getDataTypeKind(DataType dataType) {
        if (dataType == null) {
            return "unknown";
        }

        if (dataType instanceof Structure)
            return "struct";
        if (dataType instanceof ghidra.program.model.data.Enum)
            return "enum";
        if (dataType instanceof Union)
            return "union";
        if (dataType instanceof TypeDef)
            return "typedef";
        if (dataType instanceof Pointer)
            return "pointer";
        if (dataType instanceof FunctionDefinitionDataType)
            return "function_definition";
        if (dataType instanceof Array)
            return "array";

        return dataType.getClass().getSimpleName().toLowerCase();
    }

}
