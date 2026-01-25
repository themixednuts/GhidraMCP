package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.CreateDataTypeResult;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.RTTIAnalysisResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import ghidra.app.util.datatype.microsoft.RTTI0DataType;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Manage Data Types",
    description =
        "Data type operations: create and update structs, enums, unions, typedefs, and categories."
            + " Use 'update' to preserve existing references.",
    mcpName = "manage_data_types",
    mcpDescription =
        """
        <use_case>
        Data type operations for Ghidra programs. Create and update
        structures, enums, unions, typedefs, pointers, function definitions, and categories. Essential for
        reverse engineering when you need to define custom data structures and organize type information.
        </use_case>

        <important_notes>
        - Supports complex operations like creating structs with all members in one call
        - Handles category organization and type resolution automatically
        - Validates data types and provides detailed error messages
        - Uses transactions for safe modifications
        - Use ReadDataTypesTool for reading/browsing data types with filtering
        - Use DeleteDataTypeTool to delete data types
        - CRITICAL: Use 'update' action instead of 'delete' + 'create' to preserve existing references
        </important_notes>

        <member_data_type_resolution>
        For struct/union members, data type resolution follows this precedence order:
        1. PRIMARY: 'data_type_id' - Direct lookup by internal ID (most efficient)
        2. SECONDARY: 'data_type_path' - String-based resolution (e.g., "int", "char *", "/MyCategory/MyStruct")
        3. FALLBACK: Category path + name combination (legacy support)

        At least one of 'data_type_id' or 'data_type_path' must be provided for each member.
        Use 'data_type_id' when available for better performance and reliability.
        </member_data_type_resolution>

        <examples>
        Create a struct with members (using data_type_path):
        {
          "fileName": "program.exe",
          "action": "create",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "members": [
            {"name": "field1", "data_type_path": "int"},
            {"name": "field2", "data_type_path": "char *"}
          ]
        }

        Create a struct with members (using data_type_id for better performance):
        {
          "fileName": "program.exe",
          "action": "create",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "members": [
            {"name": "field1", "data_type_id": 12345},
            {"name": "field2", "data_type_path": "char *"}
          ]
        }

        Update an existing struct (RECOMMENDED over delete+create):
        {
          "fileName": "program.exe",
          "action": "update",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "members": [
            {"name": "field1", "data_type_path": "int"},
            {"name": "field2", "data_type_path": "char *"},
            {"name": "field3", "data_type_path": "float"}
          ]
        }
        </examples>
        """)
public class ManageDataTypesTool extends BaseMcpTool {

  public static final String ARG_DATA_TYPE_KIND = "data_type_kind";
  public static final String ARG_MEMBERS = "members";
  public static final String ARG_ENTRIES = "entries";
  public static final String ARG_BASE_TYPE = "base_type";
  public static final String ARG_RETURN_TYPE = "return_type";
  public static final String ARG_PARAMETERS = "parameters";
  public static final String ARG_TYPE = "type";
  public static final String ARG_NEW_CATEGORY_PATH = "new_category_path";

  private static final String ACTION_CREATE = "create";
  private static final String ACTION_UPDATE = "update";

  /**
   * Defines the JSON input schema for data type management operations.
   *
   * @return The JsonSchema defining the expected input arguments
   */
  @Override
  public JsonSchema schema() {
    // Use Draft 7 builder with additive property approach
    // See docs/MANAGE_DATA_TYPES_PARAMETER_MATRIX.md for parameter usage matrix
    var schemaRoot = createDraft7SchemaNode();

    // === COMMON PROPERTIES (available to all data_type_kinds) ===
    schemaRoot.property(
        ARG_FILE_NAME,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .enumValues(ACTION_CREATE, ACTION_UPDATE)
            .description("Action to perform on data types"));

    schemaRoot.property(
        ARG_DATA_TYPE_KIND,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .enumValues(
                "struct",
                "enum",
                "union",
                "typedef",
                "pointer",
                "function_definition",
                "category",
                "rtti0")
            .description("Type of data type to work with"));

    schemaRoot.property(
        ARG_NAME,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description("Name of the data type"));

    schemaRoot.property(
        ARG_CATEGORY_PATH,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description(
                "For non-category data types: full category path. For category operations: parent"
                    + " category path (default '/').")
            .defaultValue("/"));

    // Note: ARG_COMMENT is defined conditionally for each data_type_kind (not for
    // rtti0)

    schemaRoot.property(
        ARG_NEW_CATEGORY_PATH,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description("Destination parent path when moving a category"));

    schemaRoot.property(
        ARG_DATA_TYPE_ID,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
            .description("Optional: Data type ID for direct lookup by internal ID"));

    schemaRoot
        .requiredProperty(ARG_FILE_NAME)
        .requiredProperty(ARG_ACTION)
        .requiredProperty(ARG_DATA_TYPE_KIND);

    // === CONDITIONAL PROPERTY DEFINITIONS ===
    // Add type-specific properties ONLY when the corresponding data_type_kind is
    // selected
    schemaRoot.allOf(
        // === STRUCT: Add size, packing_value, alignment_value, members, comment ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_DATA_TYPE_KIND,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue("struct")),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_COMMENT,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Comment/description for the data type"))
                    .property(
                        ARG_SIZE,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
                            .minimum(0)
                            .description("Size in bytes (0 for growable struct)"))
                    .property(
                        "packing_value",
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
                            .description("Packing: -1=default, 0=disabled, >0=explicit"))
                    .property(
                        "alignment_value",
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
                            .description("Alignment: -1=default, 0=machine, >0=explicit"))
                    .property(
                        ARG_MEMBERS,
                        SchemaBuilder.array(mapper)
                            .items(
                                SchemaBuilder.object(mapper)
                                    .property(
                                        ARG_NAME,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Member name"))
                                    .property(
                                        ARG_DATA_TYPE_PATH,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Member data type path"))
                                    .property(
                                        ARG_DATA_TYPE_ID,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .integer(mapper)
                                            .description("Member data type ID"))
                                    .property(
                                        ARG_OFFSET,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .integer(mapper)
                                            .description("Offset (-1 for append)"))
                                    .property(
                                        ARG_COMMENT,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Member comment"))
                                    .requiredProperty(ARG_NAME))
                            .description("Struct members"))),

        // === ENUM: Add size (constrained), entries, comment ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_DATA_TYPE_KIND,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue("enum")),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_COMMENT,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Comment/description for the data type"))
                    .property(
                        ARG_SIZE,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
                            .enumValues(1, 2, 4, 8)
                            .description("Enum size MUST be 1, 2, 4, or 8 bytes"))
                    .property(
                        ARG_ENTRIES,
                        SchemaBuilder.array(mapper)
                            .items(
                                SchemaBuilder.object(mapper)
                                    .property(
                                        ARG_NAME,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Entry name"))
                                    .property(
                                        ARG_VALUE,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .integer(mapper)
                                            .description("Entry value"))
                                    .requiredProperty(ARG_NAME)
                                    .requiredProperty(ARG_VALUE))
                            .description("Enum entries"))),

        // === UNION: Add members, comment ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_DATA_TYPE_KIND,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue("union")),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_COMMENT,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Comment/description for the data type"))
                    .property(
                        ARG_MEMBERS,
                        SchemaBuilder.array(mapper)
                            .items(
                                SchemaBuilder.object(mapper)
                                    .property(
                                        ARG_NAME,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Member name"))
                                    .property(
                                        ARG_DATA_TYPE_PATH,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Member data type path"))
                                    .property(
                                        ARG_DATA_TYPE_ID,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .integer(mapper)
                                            .description("Member data type ID"))
                                    .property(
                                        ARG_COMMENT,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Member comment"))
                                    .requiredProperty(ARG_NAME))
                            .description("Union members"))),

        // === TYPEDEF: Add base_type (required) - NO COMMENT (Ghidra limitation) ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_DATA_TYPE_KIND,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue("typedef")),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_BASE_TYPE,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Base type for typedef"))
                    .requiredProperty(ARG_BASE_TYPE)),

        // === POINTER: Add base_type (required) - NO COMMENT (Ghidra limitation) ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_DATA_TYPE_KIND,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue("pointer")),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_BASE_TYPE,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Base type for pointer"))
                    .requiredProperty(ARG_BASE_TYPE)),

        // === FUNCTION_DEFINITION: Add return_type, parameters, comment ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_DATA_TYPE_KIND,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue("function_definition")),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_COMMENT,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Comment/description for the data type"))
                    .property(
                        ARG_RETURN_TYPE,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Return type for function definition"))
                    .property(
                        ARG_PARAMETERS,
                        SchemaBuilder.array(mapper)
                            .items(
                                SchemaBuilder.object(mapper)
                                    .property(
                                        ARG_NAME,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Parameter name"))
                                    .property(
                                        ARG_TYPE,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Parameter type"))
                                    .requiredProperty(ARG_TYPE))
                            .description("Function parameters"))),

        // === RTTI0: Add address (NO COMMENT - Ghidra limitation) ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_DATA_TYPE_KIND,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue("rtti0")),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ADDRESS,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Address to analyze for RTTI0 structure"))),

        // === CATEGORY: Add comment (category paths handled by root-level properties)
        // ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_DATA_TYPE_KIND,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue("category")),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_COMMENT,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Comment/description for the data type"))
                    .not(
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                            .requiredProperty(ARG_DATA_TYPE_ID))),

        // === ACTION-BASED REQUIREMENTS ===
        // action=create requires name
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_CREATE)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_NAME)),

        // action=update requires name
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_UPDATE)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_NAME)));

    return schemaRoot.build();
  }

  /**
   * Executes the data type management operation.
   *
   * @param context The MCP transport context
   * @param args The tool arguments containing fileName, action, and action-specific parameters
   * @param tool The Ghidra PluginTool context
   * @return A Mono emitting the result of the data type operation
   */
  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

    return getProgram(args, tool)
        .flatMap(
            program -> {
              String action = getRequiredStringArgument(args, ARG_ACTION);
              String dataTypeKind = getRequiredStringArgument(args, ARG_DATA_TYPE_KIND);

              return switch (action.toLowerCase()) {
                case ACTION_CREATE -> handleCreate(program, args, annotation, dataTypeKind);
                case ACTION_UPDATE -> handleUpdate(program, args, annotation, dataTypeKind);
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          ARG_ACTION,
                          action,
                          "Must be one of: " + ACTION_CREATE + ", " + ACTION_UPDATE);
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  private Object buildUpdateResult(
      String dataTypeKind,
      DataType existing,
      DataTypeManager dtm,
      Map<String, Object> args,
      GhidraMcpTool annotation)
      throws GhidraMcpException {
    return switch (dataTypeKind.toLowerCase(Locale.ROOT)) {
      case "struct" -> updateStruct(dtm, (Structure) existing, args, annotation);
      case "enum" -> updateEnum(dtm, (ghidra.program.model.data.Enum) existing, args, annotation);
      case "union" -> updateUnion(dtm, (Union) existing, args, annotation);
      case "typedef" -> updateTypedef(dtm, (TypeDef) existing, args, annotation);
      case "pointer" -> updatePointer(dtm, (TypeDef) existing, args, annotation);
      case "function_definition" ->
          updateFunctionDefinition(dtm, (FunctionDefinition) existing, args, annotation);
      case "category" -> updateCategory(dtm, args, annotation);
      case "rtti" -> updateRTTI(dtm, (RTTI0DataType) existing, args, annotation);
      default ->
          OperationResult.failure(
              "update_data_type",
              dataTypeKind,
              "Update not supported for data type kind: " + dataTypeKind);
    };
  }

  private Mono<? extends Object> handleCreate(
      Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
    return Mono.defer(
        () -> {
          String name = getOptionalStringArgument(args, "name").orElse("NewDataType");
          String transactionName = "Create " + dataTypeKind + ": " + name;

          return executeInTransaction(
                  program,
                  transactionName,
                  () -> {
                    CreateDataTypeResult createResult =
                        switch (dataTypeKind) {
                          case "struct" -> createStruct(args, program, name);
                          case "enum" -> createEnum(args, program, name);
                          case "union" -> createUnion(args, program, name);
                          case "typedef" -> createTypedef(args, program, name);
                          case "pointer" -> createPointer(args, program, name);
                          case "function_definition" ->
                              createFunctionDefinition(args, program, name);
                          case "category" -> createCategory(args, program, name);
                          case "rtti0" -> createRTTI0(args, program, name);
                          default ->
                              throw new IllegalArgumentException(
                                  "Unsupported data type kind for creation: " + dataTypeKind);
                        };
                    return createResult;
                  })
              .map(
                  result -> {
                    CreateDataTypeResult createResult = (CreateDataTypeResult) result;
                    return OperationResult.success(
                            "create_data_type", dataTypeKind, createResult.getMessage())
                        .setResult(createResult);
                  });
        });
  }

  private CreateDataTypeResult createStruct(Map<String, Object> args, Program program, String name)
      throws GhidraMcpException {
    DataTypeManager dtm = program.getDataTypeManager();
    CategoryPath categoryPath =
        getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new)
            .orElse(CategoryPath.ROOT);

    ensureCategoryExists(dtm, categoryPath);
    checkDataTypeExists(dtm, categoryPath, name);

    int size = getOptionalIntArgument(args, "size").orElse(0);
    StructureDataType newStruct = new StructureDataType(categoryPath, name, size, dtm);

    // Handle packing
    getOptionalIntArgument(args, "packing_value")
        .ifPresent(
            packingValue -> {
              switch (packingValue) {
                case -1 -> {
                  newStruct.setToDefaultPacking();
                  newStruct.setPackingEnabled(true);
                }
                case 0 -> newStruct.setPackingEnabled(false);
                default -> {
                  newStruct.setExplicitPackingValue(packingValue);
                  newStruct.setPackingEnabled(true);
                }
              }
            });

    // Handle alignment
    getOptionalIntArgument(args, "alignment_value")
        .ifPresent(
            alignmentValue -> {
              switch (alignmentValue) {
                case -1 -> newStruct.setToDefaultAligned();
                case 0 -> newStruct.setToMachineAligned();
                default -> newStruct.setExplicitMinimumAlignment(alignmentValue);
              }
            });

    DataType addedStruct = dtm.addDataType(newStruct, DataTypeConflictHandler.REPLACE_HANDLER);
    if (addedStruct == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("add struct", "data type manager returned null"));
    }

    // Set comment if provided
    getOptionalStringArgument(args, "comment").ifPresent(addedStruct::setDescription);

    // Add members if provided
    List<Map<String, Object>> members = getOptionalListArgument(args, ARG_MEMBERS).orElse(null);
    processStructMembers(members, dtm, (Structure) addedStruct);

    return new CreateDataTypeResult(
        "struct",
        addedStruct.getName(),
        addedStruct.getPathName(),
        "Successfully created struct",
        Map.of(
            "member_count", members != null ? members.size() : 0, "size", addedStruct.getLength()));
  }

  private CreateDataTypeResult createEnum(Map<String, Object> args, Program program, String name)
      throws GhidraMcpException {
    DataTypeManager dtm = program.getDataTypeManager();
    CategoryPath categoryPath =
        getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new)
            .orElse(CategoryPath.ROOT);

    ensureCategoryExists(dtm, categoryPath);
    checkDataTypeExists(dtm, categoryPath, name);

    int size = getOptionalIntArgument(args, "size").orElse(1);
    validateEnumSize(size);

    EnumDataType newEnum = new EnumDataType(categoryPath, name, size, dtm);

    // Add entries if provided
    List<Map<String, Object>> entries = getOptionalListArgument(args, ARG_ENTRIES).orElse(null);
    Optional.ofNullable(entries)
        .ifPresent(
            entryList ->
                entryList.stream()
                    .filter(
                        entry ->
                            getOptionalStringArgument(entry, ARG_NAME).isPresent()
                                && getOptionalIntArgument(entry, ARG_VALUE).isPresent())
                    .forEach(
                        entry -> {
                          String entryName = getRequiredStringArgument(entry, ARG_NAME);
                          Integer entryValue = getRequiredIntArgument(entry, ARG_VALUE);
                          newEnum.add(entryName, entryValue.longValue());
                        }));

    DataType addedEnum = dtm.addDataType(newEnum, DataTypeConflictHandler.REPLACE_HANDLER);
    if (addedEnum == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("add enum", "data type manager returned null"));
    }

    getOptionalStringArgument(args, "comment").ifPresent(addedEnum::setDescription);

    return new CreateDataTypeResult(
        "enum",
        addedEnum.getName(),
        addedEnum.getPathName(),
        "Successfully created enum",
        Map.of("entry_count", entries != null ? entries.size() : 0, "size", addedEnum.getLength()));
  }

  private CreateDataTypeResult createUnion(Map<String, Object> args, Program program, String name)
      throws GhidraMcpException {
    DataTypeManager dtm = program.getDataTypeManager();
    CategoryPath categoryPath =
        getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new)
            .orElse(CategoryPath.ROOT);

    ensureCategoryExists(dtm, categoryPath);
    checkDataTypeExists(dtm, categoryPath, name);

    UnionDataType newUnion = new UnionDataType(categoryPath, name, dtm);

    // Add members if provided
    List<Map<String, Object>> members = getOptionalListArgument(args, ARG_MEMBERS).orElse(null);
    processUnionMembers(members, dtm, newUnion);

    DataType addedUnion = dtm.addDataType(newUnion, DataTypeConflictHandler.REPLACE_HANDLER);
    if (addedUnion == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("add union", "data type manager returned null"));
    }

    getOptionalStringArgument(args, "comment").ifPresent(addedUnion::setDescription);

    return new CreateDataTypeResult(
        "union",
        addedUnion.getName(),
        addedUnion.getPathName(),
        "Successfully created union",
        Map.of(
            "member_count", members != null ? members.size() : 0, "size", addedUnion.getLength()));
  }

  private CreateDataTypeResult createTypedef(Map<String, Object> args, Program program, String name)
      throws GhidraMcpException {
    DataTypeManager dtm = program.getDataTypeManager();
    CategoryPath categoryPath =
        getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new)
            .orElse(CategoryPath.ROOT);

    ensureCategoryExists(dtm, categoryPath);

    String baseType = getRequiredStringArgument(args, "base_type");
    DataType baseDataType = resolveDataTypeWithFallback(dtm, baseType);
    if (baseDataType == null) {
      throw new GhidraMcpException(GhidraMcpError.parse("base type", baseType));
    }

    TypedefDataType newTypedef = new TypedefDataType(categoryPath, name, baseDataType, dtm);
    DataType addedTypedef = dtm.addDataType(newTypedef, DataTypeConflictHandler.REPLACE_HANDLER);
    if (addedTypedef == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("add typedef", "data type manager returned null"));
    }

    getOptionalStringArgument(args, "comment").ifPresent(addedTypedef::setDescription);

    return new CreateDataTypeResult(
        "typedef",
        addedTypedef.getName(),
        addedTypedef.getPathName(),
        "Successfully created typedef",
        Map.of("base_type", baseType));
  }

  private CreateDataTypeResult createPointer(Map<String, Object> args, Program program, String name)
      throws GhidraMcpException {
    DataTypeManager dtm = program.getDataTypeManager();
    CategoryPath categoryPath =
        getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new)
            .orElse(CategoryPath.ROOT);

    ensureCategoryExists(dtm, categoryPath);

    String baseType = getRequiredStringArgument(args, "base_type");
    DataType baseDataType = resolveDataTypeWithFallback(dtm, baseType);
    if (baseDataType == null) {
      throw new GhidraMcpException(GhidraMcpError.parse("base type", baseType));
    }

    Pointer pointer = PointerDataType.getPointer(baseDataType, dtm);
    TypedefDataType pointerTypedef = new TypedefDataType(categoryPath, name, pointer, dtm);

    DataType addedPointer =
        dtm.addDataType(pointerTypedef, DataTypeConflictHandler.REPLACE_HANDLER);
    if (addedPointer == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("add pointer type", "data type manager returned null"));
    }

    getOptionalStringArgument(args, "comment").ifPresent(addedPointer::setDescription);

    return new CreateDataTypeResult(
        "pointer",
        addedPointer.getName(),
        addedPointer.getPathName(),
        "Successfully created pointer",
        Map.of("base_type", baseType + "*"));
  }

  private CreateDataTypeResult createFunctionDefinition(
      Map<String, Object> args, Program program, String name) throws GhidraMcpException {
    DataTypeManager dtm = program.getDataTypeManager();
    CategoryPath categoryPath =
        getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new)
            .orElse(CategoryPath.ROOT);

    ensureCategoryExists(dtm, categoryPath);

    String returnType = getOptionalStringArgument(args, "return_type").orElse("void");
    DataType returnDataType = resolveDataTypeWithFallback(dtm, returnType);
    if (returnDataType == null) {
      throw new GhidraMcpException(GhidraMcpError.parse("return type", returnType));
    }

    FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(categoryPath, name, dtm);
    funcDef.setReturnType(returnDataType);

    // Add parameters if provided
    List<Map<String, Object>> parameters =
        getOptionalListArgument(args, ARG_PARAMETERS).orElse(null);
    try {
      Optional.ofNullable(parameters)
          .filter(list -> !list.isEmpty())
          .ifPresent(
              paramList -> {
                // Pre-validate all parameter types first to avoid partial state
                paramList.forEach(
                    param -> {
                      String paramType = getRequiredStringArgument(param, ARG_TYPE);
                      if (resolveDataTypeWithFallback(dtm, paramType) == null) {
                        throw new RuntimeException(
                            new GhidraMcpException(
                                GhidraMcpError.parse("parameter type", paramType)));
                      }
                    });

                // Now build the parameter definitions
                List<ParameterDefinition> defs =
                    IntStream.range(0, paramList.size())
                        .mapToObj(
                            i -> {
                              Map<String, Object> param = paramList.get(i);
                              String paramName =
                                  getOptionalStringArgument(param, ARG_NAME)
                                      .orElse("param" + (i + 1));
                              String paramType = getRequiredStringArgument(param, ARG_TYPE);

                              // This should not fail since we pre-validated
                              DataType paramDataType = resolveDataTypeWithFallback(dtm, paramType);
                              return new ParameterDefinitionImpl(paramName, paramDataType, null);
                            })
                        .collect(Collectors.toList());

                funcDef.setArguments(defs.toArray(new ParameterDefinition[0]));
              });
    } catch (RuntimeException e) {
      if (e.getCause() instanceof GhidraMcpException ghidraMcpException) {
        throw ghidraMcpException;
      }
      throw e;
    }

    DataType addedFuncDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);
    if (addedFuncDef == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("add function definition", "data type manager returned null"));
    }

    getOptionalStringArgument(args, "comment").ifPresent(addedFuncDef::setDescription);

    return new CreateDataTypeResult(
        "function_definition",
        addedFuncDef.getName(),
        addedFuncDef.getPathName(),
        "Successfully created function definition",
        Map.of(
            "parameter_count",
            parameters != null ? parameters.size() : 0,
            "return_type",
            returnType));
  }

  private CreateDataTypeResult createCategory(
      Map<String, Object> args, Program program, String name) throws GhidraMcpException {
    DataTypeManager dtm = program.getDataTypeManager();
    CategoryPath parentPath =
        getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new)
            .orElse(CategoryPath.ROOT);

    CategoryPath newCategoryPath = new CategoryPath(parentPath, name);

    if (dtm.getCategory(newCategoryPath) != null) {
      throw new RuntimeException("Category already exists: " + newCategoryPath.getPath());
    }

    Category category = dtm.createCategory(newCategoryPath);
    if (category == null) {
      throw new RuntimeException("Failed to create category: " + newCategoryPath.getPath());
    }

    return new CreateDataTypeResult(
        "category", name, newCategoryPath.getPath(), "Successfully created category", Map.of());
  }

  private CreateDataTypeResult createRTTI0(Map<String, Object> args, Program program, String name)
      throws GhidraMcpException {
    DataTypeManager dtm = program.getDataTypeManager();
    CategoryPath categoryPath =
        getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new)
            .orElse(CategoryPath.ROOT);

    ensureCategoryExists(dtm, categoryPath);
    checkDataTypeExists(dtm, categoryPath, name);

    // Create RTTI0DataType
    RTTI0DataType rttiType = new RTTI0DataType(dtm);

    // Add to data type manager
    DataType addedRTTI = dtm.addDataType(rttiType, DataTypeConflictHandler.REPLACE_HANDLER);
    if (addedRTTI == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("add RTTI0 data type", "data type manager returned null"));
    }

    // Set comment if provided
    getOptionalStringArgument(args, "comment").ifPresent(addedRTTI::setDescription);

    return new CreateDataTypeResult(
        "rtti0",
        addedRTTI.getName(),
        addedRTTI.getPathName(),
        "Successfully created RTTI0 data type",
        Map.of(
            "component_count",
            3, // RTTI0DataType has 3 components: vfTablePointer, dataPointer, name
            "size",
            addedRTTI.getLength()));
  }

  private Mono<? extends Object> handleUpdate(
      Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
    return executeInTransaction(
        program,
        "MCP - Update " + dataTypeKind,
        () -> {
          String name = getRequiredStringArgument(args, ARG_NAME);
          CategoryPath categoryPath =
              getOptionalStringArgument(args, ARG_CATEGORY_PATH)
                  .map(ManageDataTypesTool::normalizeParentPath)
                  .orElse(CategoryPath.ROOT);

          DataTypeManager dtm = program.getDataTypeManager();

          if ("category".equalsIgnoreCase(dataTypeKind)) {
            CategoryPath targetPath = buildCategoryPath(categoryPath, name);
            Category category = dtm.getCategory(targetPath);
            if (category == null) {
              Optional<String> swapCandidate =
                  getOptionalStringArgument(args, ARG_NEW_CATEGORY_PATH);
              if (swapCandidate.isPresent()) {
                CategoryPath swapParent = normalizeParentPath(swapCandidate.get());
                CategoryPath swappedPath = buildCategoryPath(swapParent, name);
                if (dtm.getCategory(swappedPath) != null) {
                  throw new GhidraMcpException(
                      GhidraMcpError.of(
                          "Category not found at provided category_path. It appears category_path"
                              + " and new_category_path might be swapped.",
                          "Swap the values: use '"
                              + swapParent.getPath()
                              + "' for category_path and '"
                              + categoryPath.getPath()
                              + "' for new_category_path"));
                }
              }
              throw new GhidraMcpException(
                  GhidraMcpError.notFound("category", targetPath.getPath()));
            }
            args.put(ARG_CATEGORY_PATH, targetPath.getPath());
            return updateCategory(dtm, args, annotation);
          }

          DataType existing = null;

          // Try data type ID lookup first (most direct)
          Optional<Long> dataTypeIdOpt = getOptionalLongArgument(args, ARG_DATA_TYPE_ID);
          if (dataTypeIdOpt.isPresent()) {
            existing = dtm.getDataType(dataTypeIdOpt.get());
          }

          // Fallback to name-based lookup
          if (existing == null) {
            existing = dtm.getDataType(categoryPath, name);
          }

          if (existing == null) {
            throw new GhidraMcpException(GhidraMcpError.notFound("data type", name));
          }

          return buildUpdateResult(dataTypeKind, existing, dtm, args, annotation);
        });
  }

  private static void ensureCategoryExists(DataTypeManager dtm, CategoryPath categoryPath) {
    if (categoryPath == null || categoryPath.equals(CategoryPath.ROOT)) {
      return;
    }
    if (dtm.getCategory(categoryPath) == null) {
      Category created = dtm.createCategory(categoryPath);
      if (created == null && dtm.getCategory(categoryPath) == null) {
        throw new RuntimeException("Failed to create category: " + categoryPath.getPath());
      }
    }
  }

  private OperationResult updateStruct(
      DataTypeManager dtm, Structure existing, Map<String, Object> args, GhidraMcpTool annotation)
      throws GhidraMcpException {
    Structure struct = existing;

    getOptionalStringArgument(args, ARG_COMMENT).ifPresent(struct::setDescription);

    List<Map<String, Object>> members = getOptionalListArgument(args, ARG_MEMBERS).orElse(null);
    if (members != null && !members.isEmpty()) {
      struct.deleteAll();
      for (Map<String, Object> member : members) {
        String memberName = getRequiredStringArgument(member, ARG_NAME);
        Integer offset = getOptionalIntArgument(member, ARG_OFFSET).orElse(null);
        String memberComment = getOptionalStringArgument(member, ARG_COMMENT).orElse(null);

        DataType memberDataType = resolveMemberDataType(dtm, member, memberName);
        if (memberDataType == null) {
          String dataTypePath =
              getOptionalStringArgument(member, ARG_DATA_TYPE_PATH).orElse("not provided");
          throw new GhidraMcpException(
              GhidraMcpError.parse("data type for member '" + memberName + "'", dataTypePath));
        }

        try {
          if (offset == null || offset == -1) {
            struct.add(memberDataType, memberName, memberComment);
          } else {
            struct.insertAtOffset(
                offset, memberDataType, memberDataType.getLength(), memberName, memberComment);
          }
        } catch (Exception e) {
          throw new GhidraMcpException(
              GhidraMcpError.failed("add member '" + memberName + "'", e.getMessage()));
        }
      }
    }

    return OperationResult.success("update_data_type", "struct", "Struct updated successfully");
  }

  private OperationResult updateEnum(
      DataTypeManager dtm,
      ghidra.program.model.data.Enum existing,
      Map<String, Object> args,
      GhidraMcpTool annotation)
      throws GhidraMcpException {
    // Set description if provided
    getOptionalStringArgument(args, ARG_COMMENT)
        .ifPresent(comment -> existing.setDescription(comment));

    // Handle resizing and get the final enum type to use
    final ghidra.program.model.data.Enum finalEnumType;
    Integer size = getOptionalIntArgument(args, ARG_SIZE).orElse(null);
    if (size != null && size != existing.getLength()) {
      ghidra.program.model.data.EnumDataType resized =
          new ghidra.program.model.data.EnumDataType(
              existing.getCategoryPath(), existing.getName(), size, dtm);
      Arrays.stream(existing.getNames())
          .forEach(name -> resized.add(name, existing.getValue(name), existing.getComment(name)));
      try {
        dtm.replaceDataType(existing, resized, true);
        finalEnumType = resized;
      } catch (DataTypeDependencyException e) {
        throw new GhidraMcpException(GhidraMcpError.failed("resize enum", e.getMessage()));
      }
    } else {
      finalEnumType = existing;
    }

    List<Map<String, Object>> entries = getOptionalListArgument(args, ARG_ENTRIES).orElse(null);
    Optional.ofNullable(entries)
        .ifPresent(
            entryList -> {
              ghidra.program.model.data.EnumDataType updated =
                  new ghidra.program.model.data.EnumDataType(
                      finalEnumType.getCategoryPath(),
                      finalEnumType.getName(),
                      finalEnumType.getLength(),
                      dtm);

              entryList.stream()
                  .filter(
                      entry ->
                          getOptionalStringArgument(entry, ARG_NAME).isPresent()
                              && getOptionalIntArgument(entry, ARG_VALUE).isPresent())
                  .forEach(
                      entry -> {
                        String entryName = getRequiredStringArgument(entry, ARG_NAME);
                        Integer value = getRequiredIntArgument(entry, ARG_VALUE);
                        String comment = getOptionalStringArgument(entry, ARG_COMMENT).orElse(null);

                        if (comment != null) {
                          updated.add(entryName, value.longValue(), comment);
                        } else {
                          updated.add(entryName, value.longValue());
                        }
                      });

              try {
                dtm.replaceDataType(finalEnumType, updated, true);
              } catch (DataTypeDependencyException e) {
                throw new RuntimeException("Failed to update enum entries: " + e.getMessage());
              }
            });

    return OperationResult.success("update_data_type", "enum", "Enum updated successfully");
  }

  private OperationResult updateUnion(
      DataTypeManager dtm, Union existing, Map<String, Object> args, GhidraMcpTool annotation)
      throws GhidraMcpException {
    Union union = existing;

    getOptionalStringArgument(args, ARG_COMMENT).ifPresent(union::setDescription);

    List<Map<String, Object>> members = getOptionalListArgument(args, ARG_MEMBERS).orElse(null);
    if (members != null && !members.isEmpty()) {
      UnionDataType updated = new UnionDataType(union.getCategoryPath(), union.getName(), dtm);

      for (Map<String, Object> member : members) {
        String memberName = getRequiredStringArgument(member, ARG_NAME);
        String memberComment = getOptionalStringArgument(member, ARG_COMMENT).orElse(null);

        DataType memberDataType = resolveMemberDataType(dtm, member, memberName);
        if (memberDataType == null) {
          String dataTypePath =
              getOptionalStringArgument(member, ARG_DATA_TYPE_PATH).orElse("not provided");
          throw new GhidraMcpException(
              GhidraMcpError.parse("data type for member '" + memberName + "'", dataTypePath));
        }

        updated.add(memberDataType, memberName, memberComment);
      }

      try {
        dtm.replaceDataType(union, updated, true);
      } catch (DataTypeDependencyException e) {
        throw new GhidraMcpException(GhidraMcpError.failed("update union members", e.getMessage()));
      }
    }

    return OperationResult.success("update_data_type", "union", "Union updated successfully");
  }

  private OperationResult updateTypedef(
      DataTypeManager dtm, TypeDef existing, Map<String, Object> args, GhidraMcpTool annotation)
      throws GhidraMcpException {
    String baseTypeName = getOptionalStringArgument(args, ARG_BASE_TYPE).orElse(null);
    TypeDef typedef = existing;

    if (baseTypeName != null) {
      DataType baseType = resolveDataTypeWithFallback(dtm, baseTypeName);
      if (baseType == null) {
        throw new GhidraMcpException(GhidraMcpError.parse("base type", baseTypeName));
      }
      typedef = new TypedefDataType(typedef.getCategoryPath(), typedef.getName(), baseType, dtm);
      try {
        dtm.replaceDataType(existing, typedef, true);
      } catch (DataTypeDependencyException e) {
        throw new GhidraMcpException(
            GhidraMcpError.failed("update typedef base type", e.getMessage()));
      }
    }

    TypeDef finalTypedef = typedef;
    getOptionalStringArgument(args, ARG_COMMENT).ifPresent(finalTypedef::setDescription);

    return OperationResult.success("update_data_type", "typedef", "Typedef updated successfully");
  }

  private OperationResult updatePointer(
      DataTypeManager dtm, TypeDef existing, Map<String, Object> args, GhidraMcpTool annotation)
      throws GhidraMcpException {
    String baseTypeName = getOptionalStringArgument(args, ARG_BASE_TYPE).orElse(null);
    TypeDef pointerTypedef = existing;

    if (baseTypeName != null) {
      DataType baseType = resolveDataTypeWithFallback(dtm, baseTypeName);
      if (baseType == null) {
        throw new GhidraMcpException(GhidraMcpError.parse("base type", baseTypeName));
      }
      DataType pointerType = PointerDataType.getPointer(baseType, dtm);
      pointerTypedef =
          new TypedefDataType(
              pointerTypedef.getCategoryPath(), pointerTypedef.getName(), pointerType, dtm);
      try {
        dtm.replaceDataType(existing, pointerTypedef, true);
      } catch (DataTypeDependencyException e) {
        throw new GhidraMcpException(
            GhidraMcpError.failed("update pointer typedef", e.getMessage()));
      }
    }

    TypeDef finalPointer = pointerTypedef;
    getOptionalStringArgument(args, ARG_COMMENT).ifPresent(finalPointer::setDescription);

    return OperationResult.success("update_data_type", "pointer", "Pointer updated successfully");
  }

  private OperationResult updateFunctionDefinition(
      DataTypeManager dtm,
      FunctionDefinition existing,
      Map<String, Object> args,
      GhidraMcpTool annotation)
      throws GhidraMcpException {
    String returnTypeName = getOptionalStringArgument(args, ARG_RETURN_TYPE).orElse(null);
    if (returnTypeName != null) {
      DataType returnType = resolveDataTypeWithFallback(dtm, returnTypeName);
      if (returnType == null) {
        throw new GhidraMcpException(GhidraMcpError.parse("return type", returnTypeName));
      }
      existing.setReturnType(returnType);
    }

    List<Map<String, Object>> parameters =
        getOptionalListArgument(args, ARG_PARAMETERS).orElse(null);
    Optional.ofNullable(parameters)
        .ifPresent(
            paramList -> {
              List<ParameterDefinition> defs =
                  IntStream.range(0, paramList.size())
                      .mapToObj(
                          i -> {
                            Map<String, Object> param = paramList.get(i);
                            String paramTypeName =
                                getOptionalStringArgument(param, ARG_TYPE).orElse(null);
                            if (paramTypeName == null) {
                              return null;
                            }

                            DataType paramType = resolveDataTypeWithFallback(dtm, paramTypeName);
                            if (paramType == null) {
                              throw new RuntimeException(
                                  "Could not resolve parameter type: " + paramTypeName);
                            }

                            String paramName =
                                getOptionalStringArgument(param, ARG_NAME)
                                    .filter(name -> !name.isBlank())
                                    .orElse("param" + (i + 1));

                            return new ParameterDefinitionImpl(paramName, paramType, null);
                          })
                      .filter(Objects::nonNull)
                      .collect(Collectors.toList());

              existing.setArguments(defs.toArray(new ParameterDefinition[0]));
            });

    getOptionalStringArgument(args, ARG_COMMENT).ifPresent(existing::setDescription);

    return OperationResult.success(
        "update_data_type", "function_definition", "Function definition updated successfully");
  }

  private OperationResult updateCategory(
      DataTypeManager dtm, Map<String, Object> args, GhidraMcpTool annotation)
      throws GhidraMcpException {
    String categoryPathStr = getRequiredStringArgument(args, ARG_CATEGORY_PATH);
    CategoryPath currentPath = new CategoryPath(categoryPathStr);

    if (currentPath.isRoot()) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CATEGORY_PATH, "/", "Cannot update the root category"));
    }

    Category category = dtm.getCategory(currentPath);
    if (category == null) {
      throw new GhidraMcpException(GhidraMcpError.notFound("category", categoryPathStr));
    }

    Optional<String> renameOpt = getOptionalStringArgument(args, ARG_NEW_NAME);
    Optional<String> moveOpt = getOptionalStringArgument(args, ARG_NEW_CATEGORY_PATH);

    boolean changed = false;

    if (renameOpt.isPresent()) {
      String newName = renameOpt.get();
      if (!newName.equals(category.getName())) {
        try {
          category.setName(newName);
          changed = true;
        } catch (InvalidNameException | DuplicateNameException e) {
          throw new GhidraMcpException(GhidraMcpError.failed("rename category", e.getMessage()));
        }
      }
    }

    if (moveOpt.isPresent()) {
      CategoryPath targetParentPath = normalizeParentPath(moveOpt.get());

      Category currentParent = category.getParent();
      CategoryPath currentParentPath =
          currentParent != null ? currentParent.getCategoryPath() : CategoryPath.ROOT;

      if (!targetParentPath.equals(currentParentPath)) {
        Category destinationParent = dtm.getCategory(targetParentPath);
        if (destinationParent == null) {
          destinationParent = dtm.createCategory(targetParentPath);
        }

        try {
          destinationParent.moveCategory(category, TaskMonitor.DUMMY);
        } catch (DuplicateNameException e) {
          throw new RuntimeException(
              new GhidraMcpException(GhidraMcpError.failed("move category", e.getMessage())));
        }

        CategoryPath destination = buildCategoryPath(targetParentPath, category.getName());
        Category refreshed = dtm.getCategory(destination);
        if (refreshed != null) {
          category = refreshed;
        }

        changed = true;
      }
    }

    if (!changed) {
      return OperationResult.success("update_data_type", "category", "Category already up to date");
    }

    return OperationResult.success("update_data_type", "category", "Category updated successfully");
  }

  private OperationResult updateRTTI(
      DataTypeManager dtm,
      RTTI0DataType existing,
      Map<String, Object> args,
      GhidraMcpTool annotation)
      throws GhidraMcpException {
    // RTTI data types are typically read-only in terms of structure
    // We can only update the description/comment
    getOptionalStringArgument(args, ARG_COMMENT).ifPresent(existing::setDescription);

    return OperationResult.success(
        "update_data_type", "rtti", "RTTI data type updated successfully");
  }

  private static CategoryPath normalizeParentPath(String path) {
    if (path == null) {
      return CategoryPath.ROOT;
    }
    String trimmed = path.trim();
    if (trimmed.isEmpty() || "/".equals(trimmed)) {
      return CategoryPath.ROOT;
    }
    if (!trimmed.startsWith("/")) {
      trimmed = "/" + trimmed;
    }
    return new CategoryPath(trimmed);
  }

  private static CategoryPath buildCategoryPath(CategoryPath parentPath, String name) {
    CategoryPath safeParent = parentPath == null ? CategoryPath.ROOT : parentPath;
    if (name == null || name.isBlank()) {
      return safeParent;
    }
    if (safeParent.toString().endsWith("/" + name)) {
      return safeParent;
    }
    return new CategoryPath(safeParent, name);
  }

  /** Helper method to validate enum size */
  private static void validateEnumSize(int size) throws GhidraMcpException {
    if (size != 1 && size != 2 && size != 4 && size != 8) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_SIZE, String.valueOf(size), "Must be 1, 2, 4, or 8 bytes"));
    }
  }

  /** Helper method to check if data type already exists */
  private static void checkDataTypeExists(
      DataTypeManager dtm, CategoryPath categoryPath, String name) throws GhidraMcpException {
    if (dtm.getDataType(categoryPath, name) != null) {
      throw new GhidraMcpException(
          GhidraMcpError.conflict(
              "Data type already exists: " + categoryPath.getPath() + "/" + name));
    }
  }

  /**
   * Helper method to process struct/union members with enhanced data type resolution. Resolution
   * priority: dataTypeId > dataTypePath > categoryPath + name
   */
  private void processStructMembers(
      List<Map<String, Object>> members, DataTypeManager dtm, Structure struct)
      throws GhidraMcpException {
    if (members != null && !members.isEmpty()) {
      for (Map<String, Object> member : members) {
        String memberName = getRequiredStringArgument(member, ARG_NAME);
        String memberComment = getOptionalStringArgument(member, ARG_COMMENT).orElse(null);
        Integer offset = getOptionalIntArgument(member, ARG_OFFSET).orElse(null);

        DataType memberDataType = resolveMemberDataType(dtm, member, memberName);
        if (memberDataType == null) {
          String dataTypePath =
              getOptionalStringArgument(member, ARG_DATA_TYPE_PATH).orElse("not provided");
          throw new GhidraMcpException(
              GhidraMcpError.parse("data type for member '" + memberName + "'", dataTypePath));
        }

        try {
          if (offset == null || offset == -1) {
            struct.add(memberDataType, memberName, memberComment);
          } else {
            struct.insertAtOffset(
                offset, memberDataType, memberDataType.getLength(), memberName, memberComment);
          }
        } catch (Exception e) {
          throw new GhidraMcpException(
              GhidraMcpError.failed("add member '" + memberName + "'", e.getMessage()));
        }
      }
    }
  }

  /**
   * Helper method to process union members with enhanced data type resolution. Resolution priority:
   * dataTypeId > dataTypePath > categoryPath + name
   */
  private void processUnionMembers(
      List<Map<String, Object>> members, DataTypeManager dtm, UnionDataType union)
      throws GhidraMcpException {
    if (members != null && !members.isEmpty()) {
      for (Map<String, Object> member : members) {
        String memberName = getRequiredStringArgument(member, ARG_NAME);
        String memberComment = getOptionalStringArgument(member, ARG_COMMENT).orElse(null);

        DataType memberDataType = resolveMemberDataType(dtm, member, memberName);
        if (memberDataType == null) {
          String dataTypePath =
              getOptionalStringArgument(member, ARG_DATA_TYPE_PATH).orElse("not provided");
          throw new GhidraMcpException(
              GhidraMcpError.parse("data type for member '" + memberName + "'", dataTypePath));
        }

        try {
          union.add(memberDataType, memberName, memberComment);
        } catch (Exception e) {
          throw new GhidraMcpException(
              GhidraMcpError.failed("add member '" + memberName + "'", e.getMessage()));
        }
      }
    }
  }

  /**
   * Enhanced member data type resolution with priority: dataTypeId > dataTypePath > categoryPath +
   * name Supports multiple ways to specify member data types for maximum flexibility.
   */
  private DataType resolveMemberDataType(
      DataTypeManager dtm, Map<String, Object> member, String memberName)
      throws GhidraMcpException {
    // Validate that at least one of data_type_id or data_type_path is provided
    Optional<Long> dataTypeIdOpt = getOptionalLongArgument(member, ARG_DATA_TYPE_ID);
    Optional<String> dataTypePathOpt = getOptionalStringArgument(member, ARG_DATA_TYPE_PATH);

    if (dataTypeIdOpt.isEmpty() && dataTypePathOpt.isEmpty()) {
      throw new GhidraMcpException(
          GhidraMcpError.of(
              "Member '" + memberName + "' requires either 'data_type_id' or 'data_type_path'",
              "Provide either data_type_id (numeric ID) or data_type_path (e.g., 'int',"
                  + " '/MyCategory/MyType')"));
    }

    // 1. PRIMARY: Try data type ID lookup (most direct)
    if (dataTypeIdOpt.isPresent()) {
      try {
        DataType result = dtm.getDataType(dataTypeIdOpt.get());
        if (result != null) {
          return result;
        }
      } catch (Exception e) {
        // Continue to next method
      }
    }

    // 2. PRIMARY: Try data type path (string-based resolution)
    if (dataTypePathOpt.isPresent()) {
      DataType result = resolveDataTypeWithFallback(dtm, dataTypePathOpt.get());
      if (result != null) {
        return result;
      }
    }

    // 3. FALLBACK: Try category path + name combination
    Optional<String> categoryPathOpt = getOptionalStringArgument(member, ARG_CATEGORY_PATH);
    Optional<String> typeNameOpt = getOptionalStringArgument(member, ARG_NAME);

    if (categoryPathOpt.isPresent() && typeNameOpt.isPresent()) {
      try {
        CategoryPath categoryPath = new CategoryPath(categoryPathOpt.get());
        DataType result = dtm.getDataType(categoryPath, typeNameOpt.get());
        if (result != null) {
          return result;
        }
      } catch (Exception e) {
        // Continue
      }
    }

    return null;
  }

  private RTTIAnalysisResult analyzeRTTIAtAddress(
      Program program, String addressStr, String dataTypeKind) throws GhidraMcpException {
    try {
      Address address = program.getAddressFactory().getAddress(addressStr);
      if (address == null) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(ARG_ADDRESS, addressStr, "Invalid address format"));
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
          GhidraMcpError.failed("analyze RTTI at address", e.getMessage()));
    }
  }

  /**
   * Resolves a data type using Ghidra's DataTypeParser. Supports all standard Ghidra data type
   * syntax including: - Basic types: byte, int, long, etc. - Pointers: byte*, byte**, pointer32* -
   * Arrays: byte[5], byte[10][20] - Templated names: templated_name<int, void*, custom_type> -
   * Namespaced types: A::B::C::typename - Category paths: /MyCategory/MyStruct (MCP client format)
   *
   * <p>MCP clients may send paths starting with "/" which need special handling.
   */
  private DataType resolveDataTypeWithFallback(DataTypeManager dtm, String typeName) {
    if (dtm == null || typeName == null || typeName.trim().isEmpty()) {
      return null;
    }

    String trimmedName = typeName.trim();

    // PRIMARY: Use Ghidra's DataTypeParser for standard type resolution
    // This handles: pointers, arrays, templates, namespaces, primitives, category
    // paths, etc.
    try {
      DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
      DataType result = parser.parse(trimmedName);
      if (result != null) {
        return result;
      }
    } catch (Exception e) {
      // If DataTypeParser fails, continue to fallback methods
    }

    // FALLBACK 1: Try without leading slash if it was present
    // DataTypeParser may not handle leading slashes in some contexts
    if (trimmedName.startsWith("/")) {
      String nameWithoutSlash = trimmedName.substring(1);
      try {
        DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
        DataType result = parser.parse(nameWithoutSlash);
        if (result != null) {
          return result;
        }
      } catch (Exception e) {
        // Continue to next fallback
      }
    }

    // FALLBACK 2: Direct DTM lookup (for exact matches)
    try {
      DataType result = dtm.getDataType(trimmedName);
      if (result != null) {
        return result;
      }
    } catch (Exception e) {
      // Continue to next fallback
    }

    // FALLBACK 3: Use DataTypeUtilities for namespace-qualified types
    // This handles cases like "ns1::ns2::type"
    if (trimmedName.contains("::")) {
      DataType result = DataTypeUtilities.findNamespaceQualifiedDataType(dtm, trimmedName, null);
      if (result != null) {
        return result;
      }
    }

    return null;
  }

  /**
   * Gets count of available data types for context. Uses native DataTypeManager.getDataTypeCount()
   * for efficiency.
   */
  private int getAvailableTypeCount(DataTypeManager dtm) {
    try {
      // Use native count method instead of iterating all types
      return dtm.getDataTypeCount(true); // true = include pointers and arrays
    } catch (Exception e) {
      return -1; // Unknown count
    }
  }

  /**
   * Gets a human-readable description of the data type kind. Uses DataTypeUtilities for enhanced
   * type analysis.
   */
  private String getDataTypeKind(DataType dataType) {
    if (dataType == null) {
      return "unknown";
    }

    // Use DataTypeUtilities to get base type for better classification
    DataType baseType = DataTypeUtilities.getBaseDataType(dataType);
    DataType typeToAnalyze = baseType != null ? baseType : dataType;

    if (typeToAnalyze instanceof Structure) return "struct";
    if (typeToAnalyze instanceof ghidra.program.model.data.Enum) return "enum";
    if (typeToAnalyze instanceof Union) return "union";
    if (typeToAnalyze instanceof TypeDef) return "typedef";
    if (typeToAnalyze instanceof Pointer) return "pointer";
    if (typeToAnalyze instanceof FunctionDefinitionDataType) return "function_definition";
    if (typeToAnalyze instanceof Array) return "array";

    // Check if it's a conflict data type
    if (DataTypeUtilities.isConflictDataType(typeToAnalyze)) {
      return "conflict_" + getBaseDataTypeKind(typeToAnalyze);
    }

    return getBaseDataTypeKind(typeToAnalyze);
  }

  /** Gets the base data type kind without conflict information. */
  private String getBaseDataTypeKind(DataType dataType) {
    String className = dataType.getClass().getSimpleName();
    return className.toLowerCase().replace("datatype", "").replace("db", "");
  }
}
