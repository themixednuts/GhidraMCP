package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DataTypeInfo;
import com.themixednuts.models.DataTypeReadResult;
import com.themixednuts.models.DataTypeReadResult.DataTypeComponentDetail;
import com.themixednuts.models.DataTypeReadResult.DataTypeEnumValue;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.RTTIAnalysisResult;
import com.themixednuts.utils.OpaqueCursorCodec;
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
import java.util.*;
import java.util.stream.Collectors;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Read Data Types",
    description =
        "Read a single data type or list data types in a Ghidra program with pagination and"
            + " filtering options.",
    mcpName = "read_data_types",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
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
          "file_name": "program.exe",
          "data_type_kind": "struct",
          "data_type_id": 12345
        }

        Read a single data type by name:
        {
          "file_name": "program.exe",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "category_path": "/MyTypes"
        }

        Analyze RTTI at address:
        {
          "file_name": "program.exe",
          "data_type_kind": "rtti0",
          "address": "0x401000"
        }

        List all data types (first page):
        {
          "file_name": "program.exe"
        }

        List data types with name filter:
        {
          "file_name": "program.exe",
          "name_filter": "struct"
        }

        Get next page of results:
        {
          "file_name": "program.exe",
          "cursor": "v1:c3RydWN0X25hbWU:L3dpbmFwaS9TVFJVQ1Q"
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

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_DATA_TYPE_KIND,
        SchemaBuilder.string(mapper).description("Type of data type (for single read mode)"));

    schemaRoot.property(
        ARG_NAME,
        SchemaBuilder.string(mapper).description("Name of the data type (for single read mode)"));

    schemaRoot.property(
        ARG_CATEGORY_PATH,
        SchemaBuilder.string(mapper)
            .description("Category path of the data type (for single read mode)")
            .defaultValue("/"));

    schemaRoot.property(
        ARG_DATA_TYPE_ID,
        SchemaBuilder.integer(mapper)
            .description("Data type ID for direct lookup (for single read mode)"));

    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Address to analyze for RTTI structure information (for RTTI read mode)")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_NAME_FILTER,
        SchemaBuilder.string(mapper)
            .description(
                "Filter data types by name (case-insensitive substring match, list mode)"));

    schemaRoot.property(
        ARG_CATEGORY_FILTER,
        SchemaBuilder.string(mapper)
            .description("Filter by category path (e.g., '/winapi', '/custom', list mode)"));

    schemaRoot.property(
        ARG_TYPE_KIND,
        SchemaBuilder.string(mapper)
            .description(
                "Filter by data type kind (e.g., 'structure', 'union', 'enum', 'typedef',"
                    + " 'pointer', list mode)"));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper)
            .description(
                "Pagination cursor from previous request (list mode, format:"
                    + " v1:<base64url_data_type_name>:<base64url_data_type_path>)"));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description(
                "Number of data types to return per page (default: "
                    + DEFAULT_PAGE_LIMIT
                    + ", max: "
                    + MAX_PAGE_LIMIT
                    + ")")
            .minimum(1)
            .maximum(MAX_PAGE_LIMIT));

    schemaRoot.requiredProperty(ARG_FILE_NAME);

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return getProgram(args, tool)
        .flatMap(
            program -> {
              // Check if this is a single data type read or a list operation
              boolean hasSingleIdentifier =
                  args.containsKey(ARG_DATA_TYPE_KIND)
                      && (args.containsKey(ARG_NAME)
                          || args.containsKey(ARG_DATA_TYPE_ID)
                          || args.containsKey(ARG_ADDRESS));

              if (hasSingleIdentifier) {
                return handleRead(program, args);
              } else {
                return Mono.fromCallable(() -> listDataTypes(program, args));
              }
            });
  }

  private Mono<? extends Object> handleRead(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
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
            CategoryPath categoryPath =
                getOptionalStringArgument(args, ARG_CATEGORY_PATH)
                    .map(CategoryPath::new)
                    .orElse(CategoryPath.ROOT);
            dataType = dtm.getDataType(categoryPath, nameOpt.get());
          }

          if (dataType == null) {
            String identifier =
                nameOpt.or(() -> dataTypeIdOpt.map(String::valueOf)).orElse("unknown");
            throw new GhidraMcpException(
                GhidraMcpError.notFound(
                    "Data type",
                    identifier,
                    "Use read_data_types without identifiers to see what's available"));
          }

          List<DataTypeComponentDetail> components = null;
          List<DataTypeEnumValue> enumValues = null;
          int componentCount = 0;
          int valueCount = 0;

          if (dataType instanceof Structure struct) {
            components =
                Arrays.stream(struct.getComponents())
                    .map(
                        comp ->
                            new DataTypeComponentDetail(
                                Optional.ofNullable(comp.getFieldName()).orElse(""),
                                comp.getDataType().getName(),
                                comp.getOffset(),
                                comp.getLength()))
                    .collect(Collectors.toList());
            componentCount = struct.getNumComponents();
          } else if (dataType instanceof ghidra.program.model.data.Enum enumType) {
            enumValues =
                Arrays.stream(enumType.getNames())
                    .map(
                        valueName -> new DataTypeEnumValue(valueName, enumType.getValue(valueName)))
                    .collect(Collectors.toList());
            valueCount = enumType.getCount();
          } else if (dataType instanceof Union union) {
            components =
                Arrays.stream(union.getComponents())
                    .map(
                        comp ->
                            new DataTypeComponentDetail(
                                Optional.ofNullable(comp.getFieldName()).orElse(""),
                                comp.getDataType().getName(),
                                null,
                                comp.getLength()))
                    .collect(Collectors.toList());
            componentCount = union.getNumComponents();
          } else if (dataType instanceof RTTI0DataType) {
            components =
                List.of(
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
    int pageSize =
        getOptionalIntArgument(args, ARG_PAGE_SIZE)
            .filter(size -> size > 0)
            .map(size -> Math.min(size, MAX_PAGE_LIMIT))
            .orElse(DEFAULT_PAGE_LIMIT);

    Optional<String> nameFilterOpt = getOptionalStringArgument(args, ARG_NAME_FILTER);
    Optional<String> categoryFilterOpt = getOptionalStringArgument(args, ARG_CATEGORY_FILTER);
    Optional<String> typeKindOpt = getOptionalStringArgument(args, ARG_TYPE_KIND);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

    String cursorPath = cursorOpt.map(this::parseCursorPath).orElse(null);

    Iterator<? extends DataType> dataTypeIterator = getTypeSpecificIterator(dtm, typeKindOpt);

    List<DataType> candidates = new ArrayList<>();
    if (nameFilterOpt.isPresent() && !nameFilterOpt.get().isEmpty() && typeKindOpt.isEmpty()) {
      String searchPattern = "*" + nameFilterOpt.get() + "*";
      dtm.findDataTypes(searchPattern, candidates, false, TaskMonitor.DUMMY);
    } else {
      dataTypeIterator.forEachRemaining(candidates::add);
    }

    String normalizedNameFilter = nameFilterOpt.map(String::toLowerCase).orElse(null);
    String normalizedCategoryFilter = categoryFilterOpt.map(String::toLowerCase).orElse(null);
    String normalizedTypeKind = typeKindOpt.map(String::toLowerCase).orElse(null);
    List<DataTypeInfo> allMatches =
        candidates.stream()
            .filter(
                dataType -> {
                  if (normalizedNameFilter != null
                      && !dataType.getName().toLowerCase().contains(normalizedNameFilter)) {
                    return false;
                  }

                  if (normalizedCategoryFilter != null
                      && !dataType
                          .getCategoryPath()
                          .getPath()
                          .toLowerCase()
                          .contains(normalizedCategoryFilter)) {
                    return false;
                  }

                  if (normalizedTypeKind != null
                      && !matchesTypeKind(dataType, normalizedTypeKind)) {
                    return false;
                  }

                  return true;
                })
            .map(
                dataType -> {
                  DataTypeInfo info = new DataTypeInfo(dataType);
                  info.getDetails().setDataTypeId(dtm.getID(dataType));
                  return info;
                })
            .sorted(
                Comparator.comparing(
                    dataTypeInfo -> dataTypeInfo.getDetails().getPath(),
                    String.CASE_INSENSITIVE_ORDER))
            .toList();

    int startIndex = 0;
    if (cursorPath != null && !cursorPath.isBlank()) {
      boolean cursorMatched = false;
      for (int i = 0; i < allMatches.size(); i++) {
        if (allMatches.get(i).getDetails().getPath().equalsIgnoreCase(cursorPath)) {
          startIndex = i + 1;
          cursorMatched = true;
          break;
        }
      }

      if (!cursorMatched) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR,
                cursorOpt.orElse(cursorPath),
                "cursor is invalid or no longer present in this data type listing"));
      }
    }

    int endExclusive = Math.min(allMatches.size(), startIndex + pageSize + 1);
    List<DataTypeInfo> paginatedMatches = new ArrayList<>(allMatches.subList(startIndex, endExclusive));

    boolean hasMore = paginatedMatches.size() > pageSize;
    List<DataTypeInfo> results =
        hasMore
            ? new ArrayList<>(paginatedMatches.subList(0, pageSize))
            : new ArrayList<>(paginatedMatches);

    String nextCursor = null;
    if (hasMore && !results.isEmpty()) {
      DataTypeInfo lastItem = results.get(results.size() - 1);
      nextCursor = encodeCursor(lastItem.getDetails().getName(), lastItem.getDetails().getPath());
    }

    return new PaginatedResult<>(results, nextCursor);
  }

  private String parseCursorPath(String cursorValue) {
    List<String> parts =
        OpaqueCursorCodec.decodeV1(
            cursorValue,
            2,
            ARG_CURSOR,
            "v1:<base64url_data_type_name>:<base64url_data_type_path>");
    return parts.get(1);
  }

  private String encodeCursor(String dataTypeName, String dataTypePath) {
    return OpaqueCursorCodec.encodeV1(dataTypeName, dataTypePath);
  }

  /**
   * Get type-specific iterator for better performance when filtering by type kind. Uses native
   * Ghidra iterators: getAllStructures(), getAllComposites(), getAllFunctionDefinitions()
   */
  private Iterator<? extends DataType> getTypeSpecificIterator(
      DataTypeManager dtm, Optional<String> typeKindOpt) {
    if (typeKindOpt.isEmpty()) {
      return dtm.getAllDataTypes();
    }

    String typeKind = typeKindOpt.get().toLowerCase();
    return switch (typeKind) {
      case "structure", "struct" -> dtm.getAllStructures();
      case "composite" -> dtm.getAllComposites(); // Structures + Unions
      case "function", "function_definition" -> dtm.getAllFunctionDefinitions();
      default -> dtm.getAllDataTypes(); // Fall back to all types for other filters
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

  private RTTIAnalysisResult analyzeRTTIAtAddress(
      Program program, String addressStr, String dataTypeKind) throws GhidraMcpException {
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
      throw new GhidraMcpException(GhidraMcpError.failed("RTTI analysis", e.getMessage()));
    }
  }

  private String getDataTypeKind(DataType dataType) {
    if (dataType == null) {
      return "unknown";
    }

    if (dataType instanceof Structure) return "struct";
    if (dataType instanceof ghidra.program.model.data.Enum) return "enum";
    if (dataType instanceof Union) return "union";
    if (dataType instanceof TypeDef) return "typedef";
    if (dataType instanceof Pointer) return "pointer";
    if (dataType instanceof FunctionDefinitionDataType) return "function_definition";
    if (dataType instanceof Array) return "array";

    return dataType.getClass().getSimpleName().toLowerCase();
  }
}
