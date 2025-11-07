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
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

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
public class ReadDataTypesTool implements IGhidraMcpSpecification {

    public static final String ARG_DATA_TYPE_KIND = "data_type_kind";
    public static final String ARG_NAME = "name";
    public static final String ARG_CATEGORY_PATH = "category_path";
    public static final String ARG_DATA_TYPE_ID = "data_type_id";
    public static final String ARG_ADDRESS = "address";
    public static final String ARG_NAME_FILTER = "name_filter";
    public static final String ARG_CATEGORY_FILTER = "category_filter";
    public static final String ARG_TYPE_KIND = "type_kind";

    private static final int DEFAULT_PAGE_LIMIT = 50;

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

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
                throw new GhidraMcpException(createDataTypeError(
                        GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND,
                        "Data type not found: " + identifier,
                        "Reading data type",
                        args,
                        identifier,
                        dtm));
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
                .map(dataType -> {
                    DataTypeInfo info = new DataTypeInfo(dataType);
                    info.getDetails().setDataTypeId(dataTypeManager.getID(dataType));
                    return info;
                })
                .collect(Collectors.toList());

        // Apply cursor-based pagination
        final String finalCursorStr = cursorOpt.orElse(null);

        List<DataTypeInfo> paginatedDataTypes = allDataTypes.stream()
                .dropWhile(dataTypeInfo -> {
                    if (finalCursorStr == null)
                        return false;

                    // Cursor format: "name:pathName"
                    String[] parts = finalCursorStr.split(":", 2);
                    String cursorName = parts[0];
                    String cursorPathName = parts.length > 1 ? parts[1] : "";

                    int nameCompare = dataTypeInfo.getDetails().getName().compareToIgnoreCase(cursorName);
                    if (nameCompare < 0)
                        return true;
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

    private RTTIAnalysisResult analyzeRTTIAtAddress(Program program, String addressStr, String dataTypeKind)
            throws GhidraMcpException {
        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                throw new GhidraMcpException(GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid address: " + addressStr)
                        .build());
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
            throw new GhidraMcpException(GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to analyze RTTI at address: " + e.getMessage())
                    .build());
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

    private GhidraMcpError createDataTypeError(GhidraMcpError.ErrorCode errorCode, String message,
            String context, Map<String, Object> args,
            String failedTypeName, DataTypeManager dtm) {
        return GhidraMcpError.dataTypeParsing()
                .errorCode(errorCode)
                .message(message)
                .context(new GhidraMcpError.ErrorContext(
                        this.getMcpName(),
                        context,
                        args,
                        Map.of("failedTypeName", failedTypeName),
                        Map.of()))
                .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Browse available data types",
                                "Use read_data_types without identifiers to see what's available",
                                null,
                                null)))
                .build();
    }
}
