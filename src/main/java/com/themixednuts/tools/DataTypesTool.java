package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.CreateDataTypeResult;
import com.themixednuts.models.DataTypeListEntry;
import com.themixednuts.models.DataTypeReadResult;
import com.themixednuts.models.DataTypeReadResult.DataTypeComponentDetail;
import com.themixednuts.models.DataTypeReadResult.DataTypeEnumValue;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import ghidra.app.util.datatype.microsoft.RTTI0DataType;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Data Types",
    description =
        "Data type lifecycle: list, get, create, and update structs, enums, unions, typedefs,"
            + " and categories.",
    mcpName = "data_types",
    mcpDescription =
        """
        <use_case>
        Data type lifecycle operations for Ghidra programs. List and browse data types with filtering
        and pagination, get detailed data type info, create and update structures, enums, unions,
        typedefs, pointers, function definitions, and categories. Essential for reverse engineering
        when you need to define custom data structures and organize type information.
        </use_case>

        <important_notes>
        - Actions: list, get, create, update (no "create_category" — use create with data_type_kind="category")
        - list returns compact summary rows; use get to fetch full struct/union/enum/function details
        - Required param for create/update: data_type_kind (NOT "kind" or "type")
        - Struct/union members use "members" array (NOT "fields"), with "data_type_path" for types (NOT "type")
        - Enum values use "entries" array with "name" and "value" keys
        - Update with members defaults to replacing ALL existing members; use member_update_mode="patch" for granular edits (by offset for structs, by ordinal for unions)
        - Use 'update' instead of 'delete' + 'create' to preserve existing references
        - For browsing without filtering, use the ghidra://program/{name}/datatypes resource
        </important_notes>

        <member_format>
        Struct/union members: {"name": "field_name", "data_type_path": "int", "comment": "optional"}
        - data_type_path accepts: "int", "byte", "ushort", "char *", "/MyCategory/MyType", "int[10]"
        - Alternative: use "data_type_id" (numeric) instead of "data_type_path" for known types
        - For structs: optional "offset" (-1 or omit to append)
        - For struct patch mode: "offset" is required, only provided fields (name, data_type_path, comment) are updated
        Enum entries: {"name": "ENTRY_NAME", "value": 42, "comment": "optional"}
        Function parameters: {"name": "param1", "type": "int *"}
        </member_format>

        <examples>
        List all data types (first page):
        {
          "file_name": "program.exe",
          "action": "list"
        }

        List data types matching a regex pattern:
        {
          "file_name": "program.exe",
          "action": "list",
          "name_pattern": ".*MyStruct.*"
        }

        Get a single data type by name:
        {
          "file_name": "program.exe",
          "action": "get",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "category_path": "/MyTypes"
        }

        Get a single data type by ID:
        {
          "file_name": "program.exe",
          "action": "get",
          "data_type_kind": "struct",
          "data_type_id": 12345
        }

        Create a category:
        {
          "file_name": "program.exe",
          "action": "create",
          "data_type_kind": "category",
          "name": "MyCategory",
          "category_path": "/"
        }

        Create a struct with members:
        {
          "file_name": "program.exe",
          "action": "create",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "members": [
            {"name": "field1", "data_type_path": "int"},
            {"name": "field2", "data_type_path": "char *"}
          ]
        }

        Update an existing struct (RECOMMENDED over delete+create):
        {
          "file_name": "program.exe",
          "action": "update",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "members": [
            {"name": "field1", "data_type_path": "int"},
            {"name": "field2", "data_type_path": "char *"},
            {"name": "field3", "data_type_path": "float"}
          ]
        }

        Patch a struct member (rename field at offset 4):
        {
          "file_name": "program.exe",
          "action": "update",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "member_update_mode": "patch",
          "members": [
            {"offset": 4, "name": "new_field_name"}
          ]
        }

        Patch a struct member (change type and comment at offset 8):
        {
          "file_name": "program.exe",
          "action": "update",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "member_update_mode": "patch",
          "members": [
            {"offset": 8, "data_type_path": "long", "comment": "updated comment"}
          ]
        }
        </examples>
        """)
public class DataTypesTool extends BaseMcpTool {

  public static final String ARG_DATA_TYPE_KIND = "data_type_kind";
  public static final String ARG_TYPE_KIND = "type_kind";
  public static final String ARG_MEMBERS = "members";
  public static final String ARG_ENTRIES = "entries";
  public static final String ARG_BASE_TYPE = "base_type";
  public static final String ARG_RETURN_TYPE = "return_type";
  public static final String ARG_PARAMETERS = "parameters";
  public static final String ARG_TYPE = "type";
  public static final String ARG_NEW_CATEGORY_PATH = "new_category_path";
  public static final String ARG_MEMBER_UPDATE_MODE = "member_update_mode";

  private static final String ACTION_LIST = "list";
  private static final String ACTION_GET = "get";
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
            .enumValues(ACTION_LIST, ACTION_GET, ACTION_CREATE, ACTION_UPDATE)
            .description("Action to perform on data types"));

    schemaRoot.property(
        ARG_DATA_TYPE_KIND,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .enumValues(
                "struct", "enum", "union", "typedef", "pointer", "function_definition", "category")
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

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_ACTION);

    // === CONDITIONAL PROPERTY DEFINITIONS ===
    schemaRoot.allOf(
        // === ACTION=LIST: optional filtering and pagination ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_LIST)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_NAME_PATTERN,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Optional regex pattern to filter data type names"))
                    .property(
                        ARG_TYPE_KIND,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description(
                                "Filter by data type kind (e.g., 'structure', 'union', 'enum',"
                                    + " 'typedef', 'pointer')"))
                    .property(
                        ARG_CATEGORY_PATH,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Filter by category path (e.g., '/winapi', '/custom')"))
                    .property(
                        ARG_CURSOR,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description(
                                "Pagination cursor from previous request (format:"
                                    + " v1:<base64url_data_type_name>:<base64url_data_type_path>)"))
                    .property(
                        ARG_PAGE_SIZE,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
                            .description(
                                "Number of data types to return per page (default: "
                                    + DEFAULT_PAGE_LIMIT
                                    + ", max: "
                                    + MAX_PAGE_LIMIT
                                    + ")")
                            .minimum(1)
                            .maximum(MAX_PAGE_LIMIT))),

        // === ACTION=GET: requires data_type_id OR (name + category_path) ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_GET)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_DATA_TYPE_ID,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
                            .description("Data type ID for direct lookup"))
                    .property(
                        ARG_NAME,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Name of the data type"))
                    .property(
                        ARG_CATEGORY_PATH,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .description("Category path of the data type")
                            .defaultValue("/"))
                    .anyOf(
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                            .requiredProperty(ARG_DATA_TYPE_ID),
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                            .requiredProperty(ARG_NAME))),

        // === ACTION=CREATE: requires data_type_kind and name ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_CREATE)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_DATA_TYPE_KIND)
                    .requiredProperty(ARG_NAME)),

        // === ACTION=UPDATE: requires data_type_kind and name ===
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_UPDATE)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_DATA_TYPE_KIND)
                    .requiredProperty(ARG_NAME)),

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
                        ARG_MEMBER_UPDATE_MODE,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .enumValues("replace", "patch")
                            .description(
                                "Member update mode: 'replace' (default) deletes all members and"
                                    + " re-adds; 'patch' updates existing members by offset"))
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
                                            .description(
                                                "Offset (-1 for append in replace mode; required"
                                                    + " in patch mode)"))
                                    .property(
                                        ARG_COMMENT,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Member comment")))
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
                        ARG_MEMBER_UPDATE_MODE,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .enumValues("replace", "patch")
                            .description(
                                "Member update mode: 'replace' (default) replaces all members;"
                                    + " 'patch' updates existing members by ordinal"))
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
                                        "ordinal",
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .integer(mapper)
                                            .description(
                                                "Member ordinal index (required in patch mode,"
                                                    + " from get action)"))
                                    .property(
                                        ARG_COMMENT,
                                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                            .string(mapper)
                                            .description("Member comment")))
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
                            .requiredProperty(ARG_DATA_TYPE_ID))));

    return schemaRoot.build();
  }

  /**
   * Executes the data type management operation.
   *
   * @param context The MCP transport context
   * @param args The tool arguments containing file_name, action, and action-specific parameters
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

              return switch (action.toLowerCase(Locale.ROOT)) {
                case ACTION_LIST -> handleList(program, args);
                case ACTION_GET -> handleGet(program, args);
                case ACTION_CREATE -> {
                  String dataTypeKind =
                      getRequiredStringArgument(args, ARG_DATA_TYPE_KIND).toLowerCase(Locale.ROOT);
                  yield handleCreate(program, args, annotation, dataTypeKind);
                }
                case ACTION_UPDATE -> {
                  String dataTypeKind =
                      getRequiredStringArgument(args, ARG_DATA_TYPE_KIND).toLowerCase(Locale.ROOT);
                  yield handleUpdate(program, args, annotation, dataTypeKind);
                }
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          ARG_ACTION,
                          action,
                          "Must be one of: "
                              + ACTION_LIST
                              + ", "
                              + ACTION_GET
                              + ", "
                              + ACTION_CREATE
                              + ", "
                              + ACTION_UPDATE);
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  private Mono<PaginatedResult<DataTypeListEntry>> handleList(
      Program program, Map<String, Object> args) {
    return Mono.fromCallable(() -> listDataTypes(program, args));
  }

  private PaginatedResult<DataTypeListEntry> listDataTypes(
      Program program, Map<String, Object> args) throws GhidraMcpException {
    DataTypeManager dtm = program.getDataTypeManager();
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

    Optional<String> namePatternOpt = getOptionalStringArgument(args, ARG_NAME_PATTERN);
    Optional<String> categoryFilterOpt = getOptionalStringArgument(args, ARG_CATEGORY_PATH);
    Optional<String> typeKindOpt = getOptionalStringArgument(args, ARG_TYPE_KIND);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

    String cursorPath = cursorOpt.map(this::parseListCursorPath).orElse(null);

    Pattern namePattern = null;
    if (namePatternOpt.isPresent()) {
      try {
        namePattern = Pattern.compile(namePatternOpt.get());
      } catch (PatternSyntaxException e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(ARG_NAME_PATTERN, namePatternOpt.get(), e.getMessage()));
      }
    }

    Iterator<? extends DataType> dataTypeIterator = getTypeSpecificIterator(dtm, typeKindOpt);

    List<DataType> candidates = new ArrayList<>();
    dataTypeIterator.forEachRemaining(candidates::add);

    final Pattern finalNamePattern = namePattern;
    String normalizedCategoryFilter = categoryFilterOpt.map(String::toLowerCase).orElse(null);
    String normalizedTypeKind = typeKindOpt.map(String::toLowerCase).orElse(null);
    List<DataTypeListEntry> allMatches =
        candidates.stream()
            .filter(
                dataType -> {
                  if (finalNamePattern != null
                      && !finalNamePattern.matcher(dataType.getName()).find()) {
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
            .map(dataType -> createListEntry(dataType, dtm))
            .sorted(Comparator.comparing(DataTypeListEntry::getPath, String.CASE_INSENSITIVE_ORDER))
            .toList();

    int startIndex = 0;
    if (cursorPath != null && !cursorPath.isBlank()) {
      boolean cursorMatched = false;
      for (int i = 0; i < allMatches.size(); i++) {
        if (allMatches.get(i).getPath().equalsIgnoreCase(cursorPath)) {
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
    List<DataTypeListEntry> paginatedMatches =
        new ArrayList<>(allMatches.subList(startIndex, endExclusive));

    boolean hasMore = paginatedMatches.size() > pageSize;
    List<DataTypeListEntry> results =
        hasMore
            ? new ArrayList<>(paginatedMatches.subList(0, pageSize))
            : new ArrayList<>(paginatedMatches);

    String nextCursor = null;
    if (hasMore && !results.isEmpty()) {
      DataTypeListEntry lastItem = results.get(results.size() - 1);
      nextCursor = OpaqueCursorCodec.encodeV1(lastItem.getName(), lastItem.getPath());
    }

    return new PaginatedResult<>(results, nextCursor);
  }

  private DataTypeListEntry createListEntry(DataType dataType, DataTypeManager dtm) {
    String kind = classifyDataTypeKind(dataType);
    Integer memberCount = null;
    Integer entryCount = null;

    if (dataType instanceof Structure structure) {
      memberCount = structure.getNumComponents();
    } else if (dataType instanceof Union union) {
      memberCount = union.getNumComponents();
    } else if (dataType instanceof ghidra.program.model.data.Enum enumDt) {
      entryCount = (int) enumDt.getCount();
    }

    return new DataTypeListEntry(
        dataType.getDisplayName(),
        dataType.getPathName(),
        dtm.getID(dataType),
        kind,
        dataType.getAlignedLength(),
        memberCount,
        entryCount);
  }

  private String classifyDataTypeKind(DataType dataType) {
    if (dataType instanceof Structure) {
      return "struct";
    }
    if (dataType instanceof Union) {
      return "union";
    }
    if (dataType instanceof ghidra.program.model.data.Enum) {
      return "enum";
    }
    if (dataType instanceof TypeDef) {
      return "typedef";
    }
    if (dataType instanceof Pointer) {
      return "pointer";
    }
    if (dataType instanceof FunctionDefinitionDataType) {
      return "function_definition";
    }
    return "other";
  }

  private String parseListCursorPath(String cursorValue) {
    List<String> parts =
        decodeOpaqueCursorV1(
            cursorValue, 2, ARG_CURSOR, "v1:<base64url_data_type_name>:<base64url_data_type_path>");
    return parts.get(1);
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
      case "composite" -> dtm.getAllComposites();
      case "function", "function_definition" -> dtm.getAllFunctionDefinitions();
      default -> dtm.getAllDataTypes();
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

  private Mono<DataTypeReadResult> handleGet(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
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
                    "Use data_types with action 'list' to see what's available"));
          }

          List<DataTypeComponentDetail> components = null;
          List<DataTypeEnumValue> enumValues = null;
          int componentCount = 0;
          int valueCount = 0;

          if (dataType instanceof Structure struct) {
            DataTypeComponent[] comps = struct.getComponents();
            components =
                IntStream.range(0, comps.length)
                    .mapToObj(
                        i ->
                            new DataTypeComponentDetail(
                                Optional.ofNullable(comps[i].getFieldName()).orElse(""),
                                comps[i].getDataType().getName(),
                                comps[i].getOffset(),
                                comps[i].getLength(),
                                comps[i].getComment(),
                                comps[i].getOrdinal()))
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
            DataTypeComponent[] comps = union.getComponents();
            components =
                IntStream.range(0, comps.length)
                    .mapToObj(
                        i ->
                            new DataTypeComponentDetail(
                                Optional.ofNullable(comps[i].getFieldName()).orElse(""),
                                comps[i].getDataType().getName(),
                                null,
                                comps[i].getLength(),
                                comps[i].getComment(),
                                comps[i].getOrdinal()))
                    .collect(Collectors.toList());
            componentCount = union.getNumComponents();
          } else if (dataType instanceof RTTI0DataType) {
            components =
                List.of(
                    new DataTypeComponentDetail("vfTablePointer", "Pointer", 0, 8, null, 0),
                    new DataTypeComponentDetail("dataPointer", "Pointer", 8, 8, null, 1),
                    new DataTypeComponentDetail("name", "NullTerminatedString", 16, -1, null, 2));
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

  private Object buildUpdateResult(
      String dataTypeKind,
      DataType existing,
      DataTypeManager dtm,
      Map<String, Object> args,
      GhidraMcpTool annotation)
      throws GhidraMcpException {
    return switch (dataTypeKind.toLowerCase(Locale.ROOT)) {
      case "struct" ->
          updateStruct(
              dtm,
              requireDataTypeKind(existing, Structure.class, dataTypeKind, annotation),
              args,
              annotation);
      case "enum" ->
          updateEnum(
              dtm,
              requireDataTypeKind(
                  existing, ghidra.program.model.data.Enum.class, dataTypeKind, annotation),
              args,
              annotation);
      case "union" ->
          updateUnion(
              dtm,
              requireDataTypeKind(existing, Union.class, dataTypeKind, annotation),
              args,
              annotation);
      case "typedef" ->
          updateTypedef(
              dtm,
              requireDataTypeKind(existing, TypeDef.class, dataTypeKind, annotation),
              args,
              annotation);
      case "pointer" ->
          updatePointer(
              dtm,
              requireDataTypeKind(existing, TypeDef.class, dataTypeKind, annotation),
              args,
              annotation);
      case "function_definition" ->
          updateFunctionDefinition(
              dtm,
              requireDataTypeKind(existing, FunctionDefinition.class, dataTypeKind, annotation),
              args,
              annotation);
      case "category" -> updateCategory(dtm, args, annotation);
      case "rtti0" ->
          updateRTTI(
              dtm,
              requireDataTypeKind(existing, RTTI0DataType.class, dataTypeKind, annotation),
              args,
              annotation);
      default ->
          throw new GhidraMcpException(
              GhidraMcpError.invalid(
                  "data_type_kind",
                  dataTypeKind,
                  "Update not supported for data type kind: " + dataTypeKind));
    };
  }

  private <T extends DataType> T requireDataTypeKind(
      DataType existing, Class<T> expectedType, String requestedKind, GhidraMcpTool annotation)
      throws GhidraMcpException {
    if (expectedType.isInstance(existing)) {
      return expectedType.cast(existing);
    }

    throw new GhidraMcpException(
        GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
            .message(
                "Data type kind mismatch for '"
                    + requestedKind
                    + "': found "
                    + existing.getClass().getSimpleName()
                    + " at "
                    + existing.getPathName())
            .context(
                new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "update data type kind validation",
                    null,
                    Map.of(
                        "requested_kind", requestedKind, "resolved_path", existing.getPathName()),
                    Map.of("resolved_class", existing.getClass().getName())))
            .build());
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
    warnIfWrongMemberKey(args, members);
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
    warnIfWrongMemberKey(args, members);
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
    Optional.ofNullable(parameters)
        .filter(list -> !list.isEmpty())
        .ifPresent(
            paramList -> {
              // Pre-validate all parameter types first to avoid partial state
              paramList.forEach(
                  param -> {
                    String paramType = getRequiredStringArgument(param, ARG_TYPE);
                    if (resolveDataTypeWithFallback(dtm, paramType) == null) {
                      throw new GhidraMcpException(
                          GhidraMcpError.parse("parameter type", paramType));
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
      throw new GhidraMcpException(
          GhidraMcpError.conflict("Category already exists: " + newCategoryPath.getPath()));
    }

    Category category = dtm.createCategory(newCategoryPath);
    if (category == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("create category", newCategoryPath.getPath()));
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
                  .map(DataTypesTool::normalizeParentPath)
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
        throw new GhidraMcpException(
            GhidraMcpError.failed("create category", categoryPath.getPath()));
      }
    }
  }

  private OperationResult updateStruct(
      DataTypeManager dtm, Structure existing, Map<String, Object> args, GhidraMcpTool annotation)
      throws GhidraMcpException {
    Structure struct = existing;

    getOptionalStringArgument(args, ARG_COMMENT).ifPresent(struct::setDescription);

    List<Map<String, Object>> members = getOptionalListArgument(args, ARG_MEMBERS).orElse(null);
    warnIfWrongMemberKey(args, members);
    if (members != null && !members.isEmpty()) {
      String mode = getOptionalStringArgument(args, ARG_MEMBER_UPDATE_MODE).orElse("replace");

      if ("patch".equals(mode)) {
        patchStructMembers(dtm, struct, members);
      } else {
        replaceStructMembers(dtm, struct, members);
      }
    }

    return OperationResult.success("update_data_type", "struct", "Struct updated successfully");
  }

  private void replaceStructMembers(
      DataTypeManager dtm, Structure struct, List<Map<String, Object>> members)
      throws GhidraMcpException {
    struct.deleteAll();
    for (Map<String, Object> member : members) {
      String memberName =
          getOptionalStringArgument(member, ARG_NAME)
              .orElseThrow(
                  () ->
                      new GhidraMcpException(
                          GhidraMcpError.of(
                              "Member 'name' is required in replace mode",
                              "Each member must have a 'name' when using replace mode (the"
                                  + " default)")));
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

  private void patchStructMembers(
      DataTypeManager dtm, Structure struct, List<Map<String, Object>> members)
      throws GhidraMcpException {
    for (Map<String, Object> member : members) {
      int offset =
          getOptionalIntArgument(member, ARG_OFFSET)
              .orElseThrow(
                  () ->
                      new GhidraMcpException(
                          GhidraMcpError.of(
                              "Member 'offset' is required in patch mode",
                              "Each member must specify 'offset' to identify which existing member"
                                  + " to update")));

      DataTypeComponent component = struct.getComponentAt(offset);
      if (component == null) {
        component = struct.getComponentContaining(offset);
      }
      if (component == null) {
        throw new GhidraMcpException(
            GhidraMcpError.of(
                "No struct member found at offset " + offset,
                "Use 'get' action to inspect the struct and find valid offsets"));
      }

      Optional<Long> dataTypeIdOpt = getOptionalLongArgument(member, ARG_DATA_TYPE_ID);
      Optional<String> dataTypePathOpt = getOptionalStringArgument(member, ARG_DATA_TYPE_PATH);
      boolean hasTypeChange = dataTypeIdOpt.isPresent() || dataTypePathOpt.isPresent();

      if (hasTypeChange) {
        String memberName =
            getOptionalStringArgument(member, ARG_NAME).orElse(component.getFieldName());
        String memberComment =
            getOptionalStringArgument(member, ARG_COMMENT).orElse(component.getComment());

        DataType newType =
            resolveMemberDataType(
                dtm, member, memberName != null ? memberName : "field_at_" + offset);
        if (newType == null) {
          String dataTypePath = dataTypePathOpt.orElse("not provided");
          throw new GhidraMcpException(
              GhidraMcpError.parse("data type for member at offset " + offset, dataTypePath));
        }

        try {
          struct.replaceAtOffset(offset, newType, newType.getLength(), memberName, memberComment);
        } catch (Exception e) {
          throw new GhidraMcpException(
              GhidraMcpError.failed("replace member at offset " + offset, e.getMessage()));
        }
      } else {
        try {
          Optional<String> nameOpt = getOptionalStringArgument(member, ARG_NAME);
          if (nameOpt.isPresent()) {
            component.setFieldName(nameOpt.get());
          }
        } catch (DuplicateNameException e) {
          throw new GhidraMcpException(
              GhidraMcpError.failed("rename member at offset " + offset, e.getMessage()));
        }

        getOptionalStringArgument(member, ARG_COMMENT).ifPresent(component::setComment);
      }
    }
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
                throw new GhidraMcpException(
                    GhidraMcpError.failed("update enum entries", e.getMessage()));
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
    warnIfWrongMemberKey(args, members);
    if (members != null && !members.isEmpty()) {
      String mode = getOptionalStringArgument(args, ARG_MEMBER_UPDATE_MODE).orElse("replace");

      if ("patch".equals(mode)) {
        patchUnionMembers(dtm, union, members);
      } else {
        replaceUnionMembers(dtm, union, members);
      }
    }

    return OperationResult.success("update_data_type", "union", "Union updated successfully");
  }

  private void replaceUnionMembers(
      DataTypeManager dtm, Union union, List<Map<String, Object>> members)
      throws GhidraMcpException {
    UnionDataType updated = new UnionDataType(union.getCategoryPath(), union.getName(), dtm);

    for (Map<String, Object> member : members) {
      String memberName =
          getOptionalStringArgument(member, ARG_NAME)
              .orElseThrow(
                  () ->
                      new GhidraMcpException(
                          GhidraMcpError.of(
                              "Member 'name' is required in replace mode",
                              "Each member must have a 'name' when using replace mode (the"
                                  + " default)")));
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

  private void patchUnionMembers(
      DataTypeManager dtm, Union union, List<Map<String, Object>> members)
      throws GhidraMcpException {
    for (Map<String, Object> member : members) {
      int ordinal =
          getOptionalIntArgument(member, "ordinal")
              .orElseThrow(
                  () ->
                      new GhidraMcpException(
                          GhidraMcpError.of(
                              "Member 'ordinal' is required in patch mode for unions",
                              "Each member must specify 'ordinal' to identify which existing"
                                  + " member to update. Use 'get' action to see ordinals.")));

      if (ordinal < 0 || ordinal >= union.getNumComponents()) {
        throw new GhidraMcpException(
            GhidraMcpError.of(
                "Invalid ordinal "
                    + ordinal
                    + " (union has "
                    + union.getNumComponents()
                    + " members)",
                "Use 'get' action to inspect the union and find valid ordinals (0-based)"));
      }

      DataTypeComponent component = union.getComponent(ordinal);

      Optional<Long> dataTypeIdOpt = getOptionalLongArgument(member, ARG_DATA_TYPE_ID);
      Optional<String> dataTypePathOpt = getOptionalStringArgument(member, ARG_DATA_TYPE_PATH);
      boolean hasTypeChange = dataTypeIdOpt.isPresent() || dataTypePathOpt.isPresent();

      if (hasTypeChange) {
        // For type changes on unions: delete old component and insert new one at same ordinal
        String memberName =
            getOptionalStringArgument(member, ARG_NAME).orElse(component.getFieldName());
        String memberComment =
            getOptionalStringArgument(member, ARG_COMMENT).orElse(component.getComment());

        DataType newType =
            resolveMemberDataType(
                dtm, member, memberName != null ? memberName : "member_" + ordinal);
        if (newType == null) {
          String dataTypePath = dataTypePathOpt.orElse("not provided");
          throw new GhidraMcpException(
              GhidraMcpError.parse("data type for member at ordinal " + ordinal, dataTypePath));
        }

        try {
          union.delete(ordinal);
          union.insert(ordinal, newType, newType.getLength(), memberName, memberComment);
        } catch (Exception e) {
          throw new GhidraMcpException(
              GhidraMcpError.failed("replace member at ordinal " + ordinal, e.getMessage()));
        }
      } else {
        // Name/comment-only update
        try {
          Optional<String> nameOpt = getOptionalStringArgument(member, ARG_NAME);
          if (nameOpt.isPresent()) {
            component.setFieldName(nameOpt.get());
          }
        } catch (DuplicateNameException e) {
          throw new GhidraMcpException(
              GhidraMcpError.failed("rename member at ordinal " + ordinal, e.getMessage()));
        }

        getOptionalStringArgument(member, ARG_COMMENT).ifPresent(component::setComment);
      }
    }
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
                              throw new GhidraMcpException(
                                  GhidraMcpError.parse("parameter type", paramTypeName));
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
          throw new GhidraMcpException(GhidraMcpError.failed("move category", e.getMessage()));
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
        "update_data_type", "rtti0", "RTTI data type updated successfully");
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

  /** Enhanced member data type resolution with priority: dataTypeId > dataTypePath. */
  /**
   * Throws an error if the agent passed "fields" instead of "members", preventing silent failure.
   */
  private void warnIfWrongMemberKey(Map<String, Object> args, List<Map<String, Object>> members)
      throws GhidraMcpException {
    if (members == null && args.containsKey("fields")) {
      throw new GhidraMcpException(
          GhidraMcpError.of(
              "Unknown parameter 'fields' — use 'members' for struct/union fields",
              "Rename 'fields' to 'members'. Each member needs 'name' and 'data_type_path'."
                  + " Example: {\"members\": [{\"name\": \"x\", \"data_type_path\": \"int\"}]}"));
    }
  }

  private DataType resolveMemberDataType(
      DataTypeManager dtm, Map<String, Object> member, String memberName)
      throws GhidraMcpException {
    // Validate that at least one of data_type_id or data_type_path is provided
    Optional<Long> dataTypeIdOpt = getOptionalLongArgument(member, ARG_DATA_TYPE_ID);
    Optional<String> dataTypePathOpt = getOptionalStringArgument(member, ARG_DATA_TYPE_PATH);

    if (dataTypeIdOpt.isEmpty() && dataTypePathOpt.isEmpty()) {
      // Check for common agent mistakes
      String hint =
          "Each member needs 'data_type_path' (e.g., \"int\", \"byte\", \"char *\") or"
              + " 'data_type_id' (numeric). Example: {\"name\": \"field1\","
              + " \"data_type_path\": \"int\"}";
      if (member.containsKey("type") || member.containsKey("data_type")) {
        hint =
            "Found '"
                + (member.containsKey("type") ? "type" : "data_type")
                + "' — use 'data_type_path' instead. Example: {\"name\": \""
                + memberName
                + "\", \"data_type_path\": \""
                + member.getOrDefault("type", member.get("data_type"))
                + "\"}";
      }
      throw new GhidraMcpException(
          GhidraMcpError.of(
              "Member '" + memberName + "' requires either 'data_type_id' or 'data_type_path'",
              hint));
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

    // 2. SECONDARY: Try data type path (string-based resolution)
    if (dataTypePathOpt.isPresent()) {
      DataType result = resolveDataTypeWithFallback(dtm, dataTypePathOpt.get());
      if (result != null) {
        return result;
      }
    }

    return null;
  }
}
