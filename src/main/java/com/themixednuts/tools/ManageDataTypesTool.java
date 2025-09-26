package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DataTypeDeleteResult;
import com.themixednuts.models.CreateDataTypeResult;
import com.themixednuts.models.DataTypeListEntry;
import com.themixednuts.models.DataTypeListResult;
import com.themixednuts.models.DataTypeReadResult;
import com.themixednuts.models.DataTypeReadResult.DataTypeComponentDetail;
import com.themixednuts.models.DataTypeReadResult.DataTypeEnumValue;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.DataTypeUtils;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

@GhidraMcpTool(
    name = "Manage Data Types",
    description = "Comprehensive data type management for Ghidra programs including structs, enums, unions, typedefs, and categories.",
    mcpName = "manage_data_types",
    mcpDescription = """
    <use_case>
    Comprehensive management of all data types in Ghidra programs. Create, read, update, delete, and list
    structures, enums, unions, typedefs, pointers, function definitions, and categories. Essential for
    reverse engineering when you need to define custom data structures and organize type information.
    </use_case>

    <important_notes>
    - Supports complex operations like creating structs with all members in one call
    - Handles category organization and type resolution automatically
    - Validates data types and provides detailed error messages
    - Uses transactions for safe modifications
    </important_notes>

    <examples>
    Create a struct with members:
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
    </examples>
    """
)
public class ManageDataTypesTool implements IGhidraMcpSpecification {

    public static final String ARG_ACTION = "action";
    public static final String ARG_DATA_TYPE_KIND = "data_type_kind";
    public static final String ARG_CATEGORY_PATH = "category_path";
    public static final String ARG_MEMBERS = "members";
    public static final String ARG_ENTRIES = "entries";
    public static final String ARG_BASE_TYPE = "base_type";
    public static final String ARG_RETURN_TYPE = "return_type";
    public static final String ARG_PARAMETERS = "parameters";
    public static final String ARG_DATA_TYPE_PATH = "data_type_path";
    public static final String ARG_OFFSET = "offset";
    public static final String ARG_VALUE = "value";
    public static final String ARG_TYPE = "type";
    public static final String ARG_NEW_CATEGORY_PATH = "new_category_path";
    public static final String ARG_NEW_NAME = "new_name";
    private static final String ARG_PAGE_SIZE = "page_size";
    private static final int DEFAULT_PAGE_SIZE = 100;

    private static final String ACTION_CREATE = "create";
    private static final String ACTION_READ = "read";
    private static final String ACTION_UPDATE = "update";
    private static final String ACTION_DELETE = "delete";
    private static final String ACTION_LIST = "list";

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
                        ACTION_DELETE,
                        ACTION_LIST)
                .description("Action to perform on data types"));

        schemaRoot.property(ARG_DATA_TYPE_KIND, JsonSchemaBuilder.string(mapper)
                .enumValues("struct", "enum", "union", "typedef", "pointer", "function_definition", "category")
                .description("Type of data type to work with"));

        schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
                .description("Name of the data type"));

        schemaRoot.property(ARG_CATEGORY_PATH, JsonSchemaBuilder.string(mapper)
                .description("For non-category data types: full category path. For category operations: parent category path (default '/').")
                .defaultValue("/"));

        schemaRoot.property(ARG_SIZE, JsonSchemaBuilder.integer(mapper)
                .description("Size in bytes (for enums: 1,2,4,8; structs: 0 for growable)"));

        schemaRoot.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
                .description("Comment/description for the data type"));

        // For struct/union members
        schemaRoot.property(ARG_MEMBERS, JsonSchemaBuilder.array(mapper)
                .items(JsonSchemaBuilder.object(mapper)
                    .property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Member name"))
                    .property(ARG_DATA_TYPE_PATH, JsonSchemaBuilder.string(mapper).description("Member data type"))
                    .property(ARG_OFFSET, JsonSchemaBuilder.integer(mapper).description("Offset in bytes (-1 for append)"))
                    .property(ARG_COMMENT, JsonSchemaBuilder.string(mapper).description("Member comment"))
                    .requiredProperty(ARG_NAME)
                    .requiredProperty(ARG_DATA_TYPE_PATH))
                .description("Members for struct/union creation"));

        // For enum entries
        schemaRoot.property(ARG_ENTRIES, JsonSchemaBuilder.array(mapper)
                .items(JsonSchemaBuilder.object(mapper)
                    .property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Entry name"))
                    .property(ARG_VALUE, JsonSchemaBuilder.integer(mapper).description("Entry value"))
                    .requiredProperty(ARG_NAME)
                    .requiredProperty(ARG_VALUE))
                .description("Entries for enum creation"));

        // For typedef/pointer
        schemaRoot.property(ARG_BASE_TYPE, JsonSchemaBuilder.string(mapper)
                .description("Base type for typedef/pointer"));

        // For function definitions
        schemaRoot.property(ARG_RETURN_TYPE, JsonSchemaBuilder.string(mapper)
                .description("Return type for function definitions"));

        schemaRoot.property(ARG_PARAMETERS, JsonSchemaBuilder.array(mapper)
                .items(JsonSchemaBuilder.object(mapper)
                    .property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Parameter name"))
                    .property(ARG_TYPE, JsonSchemaBuilder.string(mapper).description("Parameter type"))
                    .requiredProperty(ARG_TYPE))
                .description("Parameters for function definitions"));

        schemaRoot.property(ARG_NEW_CATEGORY_PATH, JsonSchemaBuilder.string(mapper)
                .description("Destination parent path when moving a category"));

        schemaRoot.property(ARG_PAGE_SIZE, JsonSchemaBuilder.integer(mapper)
                .description("Maximum number of results per page for list action")
                .minimum(1)
                .maximum(500)
                .defaultValue(DEFAULT_PAGE_SIZE));

        schemaRoot.requiredProperty(ARG_FILE_NAME)
                .requiredProperty(ARG_ACTION)
                .requiredProperty(ARG_DATA_TYPE_KIND);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String action = getRequiredStringArgument(args, ARG_ACTION);
            String dataTypeKind = getRequiredStringArgument(args, ARG_DATA_TYPE_KIND);

            return switch (action.toLowerCase()) {
                case ACTION_CREATE -> handleCreate(program, args, annotation, dataTypeKind);
                case ACTION_READ -> handleRead(program, args, annotation, dataTypeKind);
                case ACTION_UPDATE -> handleUpdate(program, args, annotation, dataTypeKind);
                case ACTION_DELETE -> handleDelete(program, args, annotation, dataTypeKind);
                case ACTION_LIST -> handleList(program, args, annotation, dataTypeKind);
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
                                    ACTION_DELETE,
                                    ACTION_LIST))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid action",
                                "Choose from: create, read, update, delete, list",
                                List.of(
                                        ACTION_CREATE,
                                        ACTION_READ,
                                        ACTION_UPDATE,
                                        ACTION_DELETE,
                                        ACTION_LIST),
                                null)))
                        .build();
                    yield Mono.error(new GhidraMcpException(error));
                }
            };
        });
    }

    private Object buildUpdateResult(String dataTypeKind,
                                     DataType existing,
                                     DataTypeManager dtm,
                                     Map<String, Object> args,
                                     GhidraMcpTool annotation) throws GhidraMcpException {
        return switch (dataTypeKind.toLowerCase(Locale.ROOT)) {
            case "struct" -> updateStruct(dtm, (Structure) existing, args, annotation);
            case "enum" -> updateEnum(dtm, (ghidra.program.model.data.Enum) existing, args, annotation);
            case "union" -> updateUnion(dtm, (Union) existing, args, annotation);
            case "typedef" -> updateTypedef(dtm, (TypeDef) existing, args, annotation);
            case "pointer" -> updatePointer(dtm, (TypeDef) existing, args, annotation);
            case "function_definition" -> updateFunctionDefinition(dtm, (FunctionDefinition) existing, args, annotation);
            case "category" -> updateCategory(dtm, args, annotation);
            default -> OperationResult.failure(
                "update_data_type",
                dataTypeKind,
                "Update not supported for data type kind: " + dataTypeKind);
        };
    }

    private Mono<? extends Object> handleCreate(Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
        return Mono.defer(() -> {
            String name = getOptionalStringArgument(args, "name").orElse("NewDataType");
            String transactionName = "Create " + dataTypeKind + ": " + name;

            return executeInTransaction(program, transactionName, () -> {
                CreateDataTypeResult createResult = switch (dataTypeKind) {
                    case "struct" -> createStruct(args, program, name);
                    case "enum" -> createEnum(args, program, name);
                    case "union" -> createUnion(args, program, name);
                    case "typedef" -> createTypedef(args, program, name);
                    case "pointer" -> createPointer(args, program, name);
                    case "function_definition" -> createFunctionDefinition(args, program, name);
                    case "category" -> createCategory(args, program, name);
                    default -> throw new IllegalArgumentException("Unsupported data type kind for creation: " + dataTypeKind);
                };
                return createResult;
            }).map(result -> {
                CreateDataTypeResult createResult = (CreateDataTypeResult) result;
                return OperationResult.success(
                    "create_data_type",
                    dataTypeKind,
                    createResult.getMessage())
                    .setResult(createResult);
            });
        });
    }

    private CreateDataTypeResult createStruct(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);

        // Check if already exists
        if (dtm.getDataType(categoryPath, name) != null) {
            throw new RuntimeException("Data type already exists: " + categoryPath.getPath() + "/" + name);
        }

        int size = getOptionalIntArgument(args, "size").orElse(0);
        StructureDataType newStruct = new StructureDataType(categoryPath, name, size, dtm);

        // Handle packing
        getOptionalIntArgument(args, "packing_value").ifPresent(packingValue -> {
            if (packingValue == -1) {
                newStruct.setToDefaultPacking();
                newStruct.setPackingEnabled(true);
            } else if (packingValue == 0) {
                newStruct.setPackingEnabled(false);
            } else {
                newStruct.setExplicitPackingValue(packingValue);
                newStruct.setPackingEnabled(true);
            }
        });

        // Handle alignment
        getOptionalIntArgument(args, "alignment_value").ifPresent(alignmentValue -> {
            if (alignmentValue == -1) {
                newStruct.setToDefaultAligned();
            } else if (alignmentValue == 0) {
                newStruct.setToMachineAligned();
            } else {
                newStruct.setExplicitMinimumAlignment(alignmentValue);
            }
        });

        DataType addedStruct = dtm.addDataType(newStruct, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedStruct == null) {
            throw new RuntimeException("Failed to add struct to data type manager");
        }

        // Set comment if provided
        getOptionalStringArgument(args, "comment").ifPresent(addedStruct::setDescription);

        // Add members if provided
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) args.get("members");
        if (members != null && !members.isEmpty()) {
            Structure struct = (Structure) addedStruct;
            for (Map<String, Object> member : members) {
                String memberName = (String) member.get("name");
                String dataTypePath = (String) member.get("data_type_path");
                Integer offset = (Integer) member.get("offset");
                String memberComment = (String) member.get("comment");

                try {
                    DataType memberDataType = DataTypeUtils.resolveDataType(dtm, dataTypePath);
                    if (memberDataType == null) {
                        throw new RuntimeException("Could not resolve data type: " + dataTypePath);
                    }

                    if (offset == null || offset == -1) {
                        // Append to end
                        struct.add(memberDataType, memberName, memberComment);
                    } else if (offset == 0) {
                        // Insert at beginning
                        struct.insertAtOffset(0, memberDataType, memberDataType.getLength(), memberName, memberComment);
                    } else {
                        // Insert at specific offset
                        struct.insertAtOffset(offset, memberDataType, memberDataType.getLength(), memberName, memberComment);
                    }
                } catch (Exception e) {
                    throw new RuntimeException("Failed to add member '" + memberName + "': " + e.getMessage());
                }
            }
        }

        return new CreateDataTypeResult(
            "struct",
            addedStruct.getName(),
            addedStruct.getPathName(),
            "Successfully created struct",
            Map.of(
                "member_count", members != null ? members.size() : 0,
                "size", addedStruct.getLength()));
    }

    private CreateDataTypeResult createEnum(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);

        if (dtm.getDataType(categoryPath, name) != null) {
            throw new RuntimeException("Data type already exists: " + categoryPath.getPath() + "/" + name);
        }

        int size = getOptionalIntArgument(args, "size").orElse(1);
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            throw new RuntimeException("Invalid enum size: " + size + ". Must be 1, 2, 4, or 8 bytes.");
        }

        EnumDataType newEnum = new EnumDataType(categoryPath, name, size, dtm);

        // Add entries if provided
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> entries = (List<Map<String, Object>>) args.get("entries");
        if (entries != null) {
            for (Map<String, Object> entry : entries) {
                String entryName = (String) entry.get("name");
                Integer entryValue = (Integer) entry.get("value");
                if (entryName != null && entryValue != null) {
                    newEnum.add(entryName, entryValue.longValue());
                }
            }
        }

        DataType addedEnum = dtm.addDataType(newEnum, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedEnum == null) {
            throw new RuntimeException("Failed to add enum to data type manager");
        }

        getOptionalStringArgument(args, "comment").ifPresent(addedEnum::setDescription);

        return new CreateDataTypeResult(
            "enum",
            addedEnum.getName(),
            addedEnum.getPathName(),
            "Successfully created enum",
            Map.of(
                "entry_count", entries != null ? entries.size() : 0,
                "size", addedEnum.getLength()));
    }

    private CreateDataTypeResult createUnion(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);

        if (dtm.getDataType(categoryPath, name) != null) {
            throw new RuntimeException("Data type already exists: " + categoryPath.getPath() + "/" + name);
        }

        UnionDataType newUnion = new UnionDataType(categoryPath, name, dtm);

        // Add members if provided
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) args.get("members");
        if (members != null) {
            for (Map<String, Object> member : members) {
                String memberName = (String) member.get("name");
                String dataTypePath = (String) member.get("data_type_path");
                String memberComment = (String) member.get("comment");

                try {
                    DataType memberDataType = DataTypeUtils.resolveDataType(dtm, dataTypePath);
                    if (memberDataType == null) {
                        throw new RuntimeException("Could not resolve data type: " + dataTypePath);
                    }

                    newUnion.add(memberDataType, memberName, memberComment);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to add member '" + memberName + "': " + e.getMessage());
                }
            }
        }

        DataType addedUnion = dtm.addDataType(newUnion, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedUnion == null) {
            throw new RuntimeException("Failed to add union to data type manager");
        }

        getOptionalStringArgument(args, "comment").ifPresent(addedUnion::setDescription);

        return new CreateDataTypeResult(
            "union",
            addedUnion.getName(),
            addedUnion.getPathName(),
            "Successfully created union",
            Map.of(
                "member_count", members != null ? members.size() : 0,
                "size", addedUnion.getLength()));
    }

    private CreateDataTypeResult createTypedef(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);

        String baseType = getRequiredStringArgument(args, "base_type");
        DataType baseDataType = DataTypeUtils.resolveDataType(dtm, baseType);
        if (baseDataType == null) {
            throw new RuntimeException("Could not resolve base type: " + baseType);
        }

        TypedefDataType newTypedef = new TypedefDataType(categoryPath, name, baseDataType, dtm);
        DataType addedTypedef = dtm.addDataType(newTypedef, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedTypedef == null) {
            throw new RuntimeException("Failed to add typedef to data type manager");
        }

        getOptionalStringArgument(args, "comment").ifPresent(addedTypedef::setDescription);

        return new CreateDataTypeResult(
            "typedef",
            addedTypedef.getName(),
            addedTypedef.getPathName(),
            "Successfully created typedef",
            Map.of("base_type", baseType));
    }

    private CreateDataTypeResult createPointer(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);

        String baseType = getRequiredStringArgument(args, "base_type");
        DataType baseDataType = DataTypeUtils.resolveDataType(dtm, baseType);
        if (baseDataType == null) {
            throw new RuntimeException("Could not resolve base type: " + baseType);
        }

        Pointer pointer = PointerDataType.getPointer(baseDataType, dtm);
        TypedefDataType pointerTypedef = new TypedefDataType(categoryPath, name, pointer, dtm);

        DataType addedPointer = dtm.addDataType(pointerTypedef, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedPointer == null) {
            throw new RuntimeException("Failed to add pointer type to data type manager");
        }

        getOptionalStringArgument(args, "comment").ifPresent(addedPointer::setDescription);

        return new CreateDataTypeResult(
            "pointer",
            addedPointer.getName(),
            addedPointer.getPathName(),
            "Successfully created pointer",
            Map.of("base_type", baseType + "*"));
    }

    private CreateDataTypeResult createFunctionDefinition(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);

        String returnType = getOptionalStringArgument(args, "return_type").orElse("void");
        DataType returnDataType = DataTypeUtils.resolveDataType(dtm, returnType);
        if (returnDataType == null) {
            throw new RuntimeException("Could not resolve return type: " + returnType);
        }

        FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(categoryPath, name, dtm);
        funcDef.setReturnType(returnDataType);

        // Add parameters if provided
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> parameters = (List<Map<String, Object>>) args.get("parameters");
        if (parameters != null && !parameters.isEmpty()) {
            List<ParameterDefinition> paramList = new ArrayList<>();
            for (int i = 0; i < parameters.size(); i++) {
                Map<String, Object> param = parameters.get(i);
                String paramName = (String) param.get("name");
                String paramType = (String) param.get("type");

                if (paramName == null) {
                    paramName = "param" + (i + 1);
                }

                DataType paramDataType = DataTypeUtils.resolveDataType(dtm, paramType);
                if (paramDataType == null) {
                    throw new RuntimeException("Could not resolve parameter type: " + paramType);
                }

                paramList.add(new ParameterDefinitionImpl(paramName, paramDataType, null));
            }

            funcDef.setArguments(paramList.toArray(new ParameterDefinition[0]));
        }

        DataType addedFuncDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedFuncDef == null) {
            throw new RuntimeException("Failed to add function definition to data type manager");
        }

        getOptionalStringArgument(args, "comment").ifPresent(addedFuncDef::setDescription);

        return new CreateDataTypeResult(
            "function_definition",
            addedFuncDef.getName(),
            addedFuncDef.getPathName(),
            "Successfully created function definition",
            Map.of(
                "parameter_count", parameters != null ? parameters.size() : 0,
                "return_type", returnType));
    }

    private CreateDataTypeResult createCategory(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath parentPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        CategoryPath newCategoryPath = new CategoryPath(parentPath, name);

        if (dtm.getCategory(newCategoryPath) != null) {
            throw new RuntimeException("Category already exists: " + newCategoryPath.getPath());
        }

        Category category = dtm.createCategory(newCategoryPath);
        if (category == null) {
            throw new RuntimeException("Failed to create category: " + newCategoryPath.getPath());
        }

        return new CreateDataTypeResult(
            "category",
            name,
            newCategoryPath.getPath(),
            "Successfully created category",
            Map.of());
    }

    private Mono<? extends Object> handleRead(Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
        return Mono.fromCallable(() -> {
            String name = getRequiredStringArgument(args, ARG_NAME);
            CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
                .map(CategoryPath::new).orElse(CategoryPath.ROOT);

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = dtm.getDataType(categoryPath, name);

            if (dataType == null) {
                GhidraMcpError error = GhidraMcpError.resourceNotFound()
                    .errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
                    .message("Data type not found: " + name)
                    .build();
                throw new GhidraMcpException(error);
            }

            List<DataTypeComponentDetail> components = null;
            List<DataTypeEnumValue> enumValues = null;
            int componentCount = 0;
            int valueCount = 0;

            if (dataType instanceof Structure struct) {
                components = new ArrayList<>();
                for (DataTypeComponent comp : struct.getComponents()) {
                    components.add(new DataTypeComponentDetail(
                        comp.getFieldName() != null ? comp.getFieldName() : "",
                        comp.getDataType().getName(),
                        comp.getOffset(),
                        comp.getLength()));
                }
                componentCount = struct.getNumComponents();
            } else if (dataType instanceof ghidra.program.model.data.Enum enumType) {
                enumValues = new ArrayList<>();
                for (String valueName : enumType.getNames()) {
                    enumValues.add(new DataTypeEnumValue(valueName, enumType.getValue(valueName)));
                }
                valueCount = enumType.getCount();
            } else if (dataType instanceof Union union) {
                components = new ArrayList<>();
                for (DataTypeComponent comp : union.getComponents()) {
                    components.add(new DataTypeComponentDetail(
                        comp.getFieldName() != null ? comp.getFieldName() : "",
                        comp.getDataType().getName(),
                        null,
                        comp.getLength()));
                }
                componentCount = union.getNumComponents();
            }

            return new DataTypeReadResult(
                dataType.getName(),
                dataType.getPathName(),
                DataTypeUtils.getDataTypeKind(dataType),
                dataType.getLength(),
                dataType.getDescription(),
                components,
                enumValues,
                componentCount,
                valueCount);
        });
    }

    private Mono<? extends Object> handleUpdate(Program program,
                                               Map<String, Object> args,
                                               GhidraMcpTool annotation,
                                               String dataTypeKind) {
        return executeInTransaction(program, "MCP - Update " + dataTypeKind, () -> {
            String name = getRequiredStringArgument(args, ARG_NAME);
            CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
                .map(ManageDataTypesTool::normalizeParentPath)
                .orElse(CategoryPath.ROOT);

            DataTypeManager dtm = program.getDataTypeManager();

            if ("category".equalsIgnoreCase(dataTypeKind)) {
                CategoryPath targetPath = buildCategoryPath(categoryPath, name);
                Category category = dtm.getCategory(targetPath);
                if (category == null) {
                    Optional<String> swapCandidate = getOptionalStringArgument(args, ARG_NEW_CATEGORY_PATH);
                    if (swapCandidate.isPresent()) {
                        CategoryPath swapParent = normalizeParentPath(swapCandidate.get());
                        CategoryPath swappedPath = buildCategoryPath(swapParent, name);
                        if (dtm.getCategory(swappedPath) != null) {
                            throw new GhidraMcpException(GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                .message("Category not found at provided category_path. It appears category_path and new_category_path might be swapped.")
                                .context(new GhidraMcpError.ErrorContext(
                                    annotation.mcpName(),
                                    "category update lookup",
                                    args,
                                    Map.of(
                                        ARG_CATEGORY_PATH, categoryPath.getPath(),
                                        ARG_NEW_CATEGORY_PATH, swapParent.getPath(),
                                        ARG_NAME, name),
                                    Map.of("swapDetected", true)))
                                .suggestions(List.of(new GhidraMcpError.ErrorSuggestion(
                                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                    "Swap category_path and new_category_path",
                                    "Provide the current parent in category_path and the destination parent in new_category_path",
                                    List.of(
                                        String.format("\"%s\": \"%s\"", ARG_CATEGORY_PATH, swapParent.getPath()),
                                        String.format("\"%s\": \"%s\"", ARG_NEW_CATEGORY_PATH, categoryPath.getPath())),
                                    null)))
                                .build());
                        }
                    }
                    GhidraMcpError error = GhidraMcpError.resourceNotFound()
                        .errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
                        .message("Category not found at path: " + targetPath.getPath())
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "category update lookup",
                            args,
                            Map.of(ARG_CATEGORY_PATH, targetPath.getPath(), ARG_NAME, name),
                            Map.of("dataTypeKind", dataTypeKind)))
                        .build();
                    throw new GhidraMcpException(error);
                }
                args.put(ARG_CATEGORY_PATH, targetPath.getPath());
                return updateCategory(dtm, args, annotation);
            }

            DataType existing = dtm.getDataType(categoryPath, name);

            if (existing == null) {
                GhidraMcpError error = GhidraMcpError.resourceNotFound()
                    .errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
                    .message("Data type not found: " + name)
                    .context(new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        "update lookup",
                        args,
                        Map.of("category_path", categoryPath.getPath(), "name", name),
                        Map.of("dataTypeKind", dataTypeKind)))
                    .build();
                throw new GhidraMcpException(error);
            }

            return buildUpdateResult(dataTypeKind, existing, dtm, args, annotation);
        });
    }

    private Mono<? extends Object> handleDelete(Program program,
                                               Map<String, Object> args,
                                               GhidraMcpTool annotation,
                                               String dataTypeKind) {
        return executeInTransaction(program, "MCP - Delete " + dataTypeKind, () -> {
            String name = getRequiredStringArgument(args, ARG_NAME);
            CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
                .map(CategoryPath::new).orElse(CategoryPath.ROOT);

            DataTypeManager dtm = program.getDataTypeManager();
            if ("category".equalsIgnoreCase(dataTypeKind)) {
                try {
                    return deleteCategory(dtm, categoryPath, name, annotation, args);
                } catch (GhidraMcpException e) {
                    throw new RuntimeException(e);
                }
            }
            DataType dataType = dtm.getDataType(categoryPath, name);

            if (dataType == null) {
                GhidraMcpError error = GhidraMcpError.resourceNotFound()
                    .errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
                    .message("Data type not found: " + name)
                    .build();
                throw new GhidraMcpException(error);
            }

            boolean removed = dtm.remove(dataType, null);
            if (!removed) {
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to remove data type: " + name)
                    .build();
                throw new GhidraMcpException(error);
            }

            return new DataTypeDeleteResult(
                true,
                "Successfully deleted " + dataTypeKind + " '" + name + "'",
                name,
                categoryPath.toString());
        }).onErrorMap(throwable -> {
            if (throwable instanceof RuntimeException runtime && runtime.getCause() instanceof GhidraMcpException ghidra) {
                return ghidra;
            }
            return throwable;
        });
    }

    private DataTypeDeleteResult deleteCategory(DataTypeManager dtm,
                                               CategoryPath categoryPath,
                                               String name,
                                               GhidraMcpTool annotation,
                                               Map<String, Object> args) throws GhidraMcpException {

        CategoryPath targetPath = buildCategoryPath(categoryPath, name);

        if (targetPath.isRoot()) {
            GhidraMcpError error = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Cannot delete the root category '/' using this tool.")
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "category validation",
                    args,
                    Map.of(ARG_CATEGORY_PATH, targetPath.getPath()),
                    Map.of("isRoot", true)))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                        "Provide a non-root category",
                        "Specify a specific category path to delete",
                        List.of("/UserDefined", "/MyTypes/MyEmptyCategory"),
                        null)))
                .build();
            throw new GhidraMcpException(error);
        }

        Category targetCategory = dtm.getCategory(targetPath);
        if (targetCategory == null) {
            GhidraMcpError error = GhidraMcpError.resourceNotFound()
                .errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
                .message("Category not found at path: " + targetPath.getPath())
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "category lookup",
                    args,
                    Map.of(ARG_CATEGORY_PATH, targetPath.getPath()),
                    Map.of("categoryExists", false)))
                .build();
            throw new GhidraMcpException(error);
        }

        CategoryPath parentPath = targetCategory.getParent() != null
            ? targetCategory.getParent().getCategoryPath()
            : CategoryPath.ROOT;

        Category parentCategory = dtm.getCategory(parentPath);
        if (parentCategory == null) {
            throw new IllegalStateException(
                "Parent category '" + parentPath.getPath() + "' not found for '" + targetPath.getPath() + "'");
        }

        boolean removed = parentCategory.removeCategory(targetPath.getName(), TaskMonitor.DUMMY);
        if (!removed) {
            GhidraMcpError error = GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to delete category '" + targetPath.getPath() + "'. Ensure it is empty.")
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "category deletion",
                    args,
                    Map.of("attemptedCategory", targetPath.getPath()),
                    Map.of("categoryEmpty", false)))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                        "Ensure the category is empty",
                        "Remove any contained data types or subcategories before deletion",
                        null,
                        null)))
                .build();
            throw new GhidraMcpException(error);
        }

        return new DataTypeDeleteResult(
            true,
            "Successfully deleted category '" + targetPath.getPath() + "'",
            targetPath.getName(),
            parentPath.getPath());
    }

    private Mono<? extends Object> handleList(Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
        return Mono.fromCallable(() -> {
            CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
                .map(ManageDataTypesTool::normalizeParentPath).orElse(CategoryPath.ROOT);
            Optional<String> filter = getOptionalStringArgument(args, "filter");
            boolean includeBuiltin = getOptionalBooleanArgument(args, "include_builtin").orElse(false);
            Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
            int pageSize = getOptionalIntArgument(args, ARG_PAGE_SIZE).orElse(DEFAULT_PAGE_SIZE);

            DataTypeManager dtm = program.getDataTypeManager();
            List<DataTypeListEntry> dataTypeList = new ArrayList<>();

            Category category = dtm.getCategory(categoryPath);
            if (category != null) {
                collectDataTypesAsEntries(category, dataTypeList, dataTypeKind, filter, includeBuiltin);
            }

            dataTypeList.sort(Comparator.comparing(
                DataTypeListEntry::getPath,
                Comparator.nullsLast(String::compareTo)));

            int startIndex = 0;
            if (cursorOpt.isPresent()) {
                String cursor = cursorOpt.get();
                startIndex = dataTypeList.size();
                for (int i = 0; i < dataTypeList.size(); i++) {
                    String path = dataTypeList.get(i).getPath();
                    if (path != null && path.compareTo(cursor) > 0) {
                        startIndex = i;
                        break;
                    }
                }
            }

            List<DataTypeListEntry> pageBuffer = new ArrayList<>();
            for (int i = startIndex; i < dataTypeList.size() && pageBuffer.size() < pageSize + 1; i++) {
                pageBuffer.add(dataTypeList.get(i));
            }

            String nextCursor = null;
            if (pageBuffer.size() > pageSize) {
                nextCursor = pageBuffer.get(pageSize).getPath();
            }

            List<DataTypeListEntry> pageResults = pageBuffer.size() > pageSize
                ? new ArrayList<>(pageBuffer.subList(0, pageSize))
                : pageBuffer;

            PaginatedResult<DataTypeListEntry> paginated = new PaginatedResult<>(pageResults, nextCursor);

            return new DataTypeListResult(
                paginated,
                dataTypeList.size(),
                pageResults.size(),
                pageSize,
                categoryPath.toString(),
                filter.orElse("none"),
                includeBuiltin,
                dataTypeKind
            );
        });
    }


    private void collectDataTypesAsEntries(Category category, List<DataTypeListEntry> dataTypes, String kindFilter,
                                      Optional<String> nameFilter, boolean includeBuiltin) {
        // Collect from current category
        for (DataType dt : category.getDataTypes()) {
            if (!includeBuiltin && dt.getDataTypeManager() != category.getDataTypeManager()) {
                continue; // Skip built-in types
            }

            String dtKind = getDataTypeKind(dt);
            if (!kindFilter.equals("all") && !kindFilter.equals(dtKind)) {
                continue;
            }

            if (nameFilter.isPresent() && !dt.getName().toLowerCase(Locale.ROOT).contains(nameFilter.get().toLowerCase(Locale.ROOT))) {
                continue;
            }

            dataTypes.add(new DataTypeListEntry(
                dt.getName(),
                dt.getPathName(),
                dtKind,
                dt.getLength(),
                dt.getDescription() != null ? dt.getDescription() : "",
                dt.getCategoryPath().toString()
            ));
        }

        // Recursively collect from subcategories
        for (Category subCategory : category.getCategories()) {
            collectDataTypesAsEntries(subCategory, dataTypes, kindFilter, nameFilter, includeBuiltin);
        }
    }

    private String getDataTypeKind(DataType dt) {
        if (dt instanceof Structure) return "struct";
        if (dt instanceof ghidra.program.model.data.Enum) return "enum";
        if (dt instanceof Union) return "union";
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof Pointer) return "pointer";
        if (dt instanceof FunctionDefinition) return "function_definition";
        return "other";
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

    private OperationResult updateStruct(DataTypeManager dtm,
                                         Structure existing,
                                         Map<String, Object> args,
                                         GhidraMcpTool annotation) throws GhidraMcpException {
        Structure struct = existing;

        getOptionalStringArgument(args, ARG_COMMENT).ifPresent(struct::setDescription);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) args.get(ARG_MEMBERS);
        if (members != null) {
            struct.deleteAll();
            for (Map<String, Object> member : members) {
                String memberName = (String) member.get(ARG_NAME);
                String dataTypePath = (String) member.get(ARG_DATA_TYPE_PATH);
                Integer offset = (Integer) member.get(ARG_OFFSET);
                String memberComment = (String) member.get(ARG_COMMENT);

                DataType memberDataType = DataTypeUtils.resolveDataType(dtm, dataTypePath);
                if (memberDataType == null) {
                    throw new GhidraMcpException(GhidraMcpError.execution()
                        .message("Could not resolve data type: " + dataTypePath)
                        .build());
                }

                if (offset == null || offset == -1) {
                    struct.add(memberDataType, memberName, memberComment);
                } else {
                    struct.insertAtOffset(offset, memberDataType, memberDataType.getLength(), memberName, memberComment);
                }
            }
        }

        return OperationResult.success(
            "update_data_type",
            "struct",
            "Struct updated successfully");
    }

    private OperationResult updateEnum(DataTypeManager dtm,
                                       ghidra.program.model.data.Enum existing,
                                       Map<String, Object> args,
                                       GhidraMcpTool annotation) throws GhidraMcpException {
        ghidra.program.model.data.Enum enumType = existing;

        getOptionalStringArgument(args, ARG_COMMENT).ifPresent(enumType::setDescription);

        Integer size = getOptionalIntArgument(args, ARG_SIZE).orElse(null);
        if (size != null && size != enumType.getLength()) {
            ghidra.program.model.data.EnumDataType resized = new ghidra.program.model.data.EnumDataType(
                enumType.getCategoryPath(), enumType.getName(), size, dtm);
            for (String name : enumType.getNames()) {
                resized.add(name, enumType.getValue(name), enumType.getComment(name));
            }
            try {
                dtm.replaceDataType(enumType, resized, true);
            } catch (DataTypeDependencyException e) {
                throw new GhidraMcpException(GhidraMcpError.execution()
                    .message("Failed to resize enum: " + e.getMessage())
                    .build());
            }
            enumType = resized;
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> entries = (List<Map<String, Object>>) args.get(ARG_ENTRIES);
        if (entries != null) {
            ghidra.program.model.data.EnumDataType updated = new ghidra.program.model.data.EnumDataType(
                enumType.getCategoryPath(), enumType.getName(), enumType.getLength(), dtm);
            for (Map<String, Object> entry : entries) {
                String entryName = (String) entry.get(ARG_NAME);
                Number value = (Number) entry.get(ARG_VALUE);
                String comment = (String) entry.get(ARG_COMMENT);
                if (entryName != null && value != null) {
                    if (comment != null) {
                        updated.add(entryName, value.longValue(), comment);
                    } else {
                        updated.add(entryName, value.longValue());
                    }
                }
            }
            try {
                dtm.replaceDataType(enumType, updated, true);
            } catch (DataTypeDependencyException e) {
                throw new GhidraMcpException(GhidraMcpError.execution()
                    .message("Failed to update enum entries: " + e.getMessage())
                    .build());
            }
        }

        return OperationResult.success(
            "update_data_type",
            "enum",
            "Enum updated successfully");
    }

    private OperationResult updateUnion(DataTypeManager dtm,
                                        Union existing,
                                        Map<String, Object> args,
                                        GhidraMcpTool annotation) throws GhidraMcpException {
        Union union = existing;

        getOptionalStringArgument(args, ARG_COMMENT).ifPresent(union::setDescription);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) args.get(ARG_MEMBERS);
        if (members != null) {
            UnionDataType updated = new UnionDataType(union.getCategoryPath(), union.getName(), dtm);
            for (Map<String, Object> member : members) {
                String memberName = (String) member.get(ARG_NAME);
                String dataTypePath = (String) member.get(ARG_DATA_TYPE_PATH);
                String memberComment = (String) member.get(ARG_COMMENT);

                DataType memberDataType = DataTypeUtils.resolveDataType(dtm, dataTypePath);
                if (memberDataType == null) {
                    throw new GhidraMcpException(GhidraMcpError.execution()
                        .message("Could not resolve data type: " + dataTypePath)
                        .build());
                }

                updated.add(memberDataType, memberName, memberComment);
            }
            try {
                dtm.replaceDataType(union, updated, true);
            } catch (DataTypeDependencyException e) {
                throw new GhidraMcpException(GhidraMcpError.execution()
                    .message("Failed to update union members: " + e.getMessage())
                    .build());
            }
        }

        return OperationResult.success(
            "update_data_type",
            "union",
            "Union updated successfully");
    }

    private OperationResult updateTypedef(DataTypeManager dtm,
                                          TypeDef existing,
                                          Map<String, Object> args,
                                          GhidraMcpTool annotation) throws GhidraMcpException {
        String baseTypeName = getOptionalStringArgument(args, ARG_BASE_TYPE).orElse(null);
        TypeDef typedef = existing;

        if (baseTypeName != null) {
            DataType baseType = DataTypeUtils.resolveDataType(dtm, baseTypeName);
            if (baseType == null) {
                throw new GhidraMcpException(GhidraMcpError.execution()
                    .message("Could not resolve base type: " + baseTypeName)
                    .build());
            }
            typedef = new TypedefDataType(typedef.getCategoryPath(), typedef.getName(), baseType, dtm);
            try {
                dtm.replaceDataType(existing, typedef, true);
            } catch (DataTypeDependencyException e) {
                throw new GhidraMcpException(GhidraMcpError.execution()
                    .message("Failed to update typedef base type: " + e.getMessage())
                    .build());
            }
        }

        TypeDef finalTypedef = typedef;
        getOptionalStringArgument(args, ARG_COMMENT).ifPresent(finalTypedef::setDescription);

        return OperationResult.success(
            "update_data_type",
            "typedef",
            "Typedef updated successfully");
    }

    private OperationResult updatePointer(DataTypeManager dtm,
                                          TypeDef existing,
                                          Map<String, Object> args,
                                          GhidraMcpTool annotation) throws GhidraMcpException {
        String baseTypeName = getOptionalStringArgument(args, ARG_BASE_TYPE).orElse(null);
        TypeDef pointerTypedef = existing;

        if (baseTypeName != null) {
            DataType baseType = DataTypeUtils.resolveDataType(dtm, baseTypeName);
            if (baseType == null) {
                throw new GhidraMcpException(GhidraMcpError.execution()
                    .message("Could not resolve base type: " + baseTypeName)
                    .build());
            }
            DataType pointerType = PointerDataType.getPointer(baseType, dtm);
            pointerTypedef = new TypedefDataType(pointerTypedef.getCategoryPath(), pointerTypedef.getName(), pointerType, dtm);
            try {
                dtm.replaceDataType(existing, pointerTypedef, true);
            } catch (DataTypeDependencyException e) {
                throw new GhidraMcpException(GhidraMcpError.execution()
                    .message("Failed to update pointer typedef: " + e.getMessage())
                    .build());
            }
        }

        TypeDef finalPointer = pointerTypedef;
        getOptionalStringArgument(args, ARG_COMMENT).ifPresent(finalPointer::setDescription);

        return OperationResult.success(
            "update_data_type",
            "pointer",
            "Pointer updated successfully");
    }

    private OperationResult updateFunctionDefinition(DataTypeManager dtm,
                                                     FunctionDefinition existing,
                                                     Map<String, Object> args,
                                                     GhidraMcpTool annotation) throws GhidraMcpException {
        String returnTypeName = getOptionalStringArgument(args, ARG_RETURN_TYPE).orElse(null);
        if (returnTypeName != null) {
            DataType returnType = DataTypeUtils.resolveDataType(dtm, returnTypeName);
            if (returnType == null) {
                throw new GhidraMcpException(GhidraMcpError.execution()
                    .message("Could not resolve return type: " + returnTypeName)
                    .build());
            }
            existing.setReturnType(returnType);
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> parameters = (List<Map<String, Object>>) args.get(ARG_PARAMETERS);
        if (parameters != null) {
            List<ParameterDefinition> defs = new ArrayList<>();
            for (int i = 0; i < parameters.size(); i++) {
                Map<String, Object> param = parameters.get(i);
                String paramName = (String) param.get(ARG_NAME);
                String paramTypeName = (String) param.get(ARG_TYPE);
                if (paramTypeName == null) {
                    continue;
                }
                DataType paramType = DataTypeUtils.resolveDataType(dtm, paramTypeName);
                if (paramType == null) {
                    throw new GhidraMcpException(GhidraMcpError.execution()
                        .message("Could not resolve parameter type: " + paramTypeName)
                        .build());
                }
                if (paramName == null || paramName.isBlank()) {
                    paramName = "param" + (i + 1);
                }
                defs.add(new ParameterDefinitionImpl(paramName, paramType, null));
            }
            existing.setArguments(defs.toArray(new ParameterDefinition[0]));
        }

        getOptionalStringArgument(args, ARG_COMMENT).ifPresent(existing::setDescription);

        return OperationResult.success(
            "update_data_type",
            "function_definition",
            "Function definition updated successfully");
    }

    private OperationResult updateCategory(DataTypeManager dtm,
                                           Map<String, Object> args,
                                           GhidraMcpTool annotation) throws GhidraMcpException {
        String categoryPathStr = getRequiredStringArgument(args, ARG_CATEGORY_PATH);
        CategoryPath currentPath = new CategoryPath(categoryPathStr);

        if (currentPath.isRoot()) {
            throw new GhidraMcpException(GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Cannot update the root category")
                .build());
        }

        Category category = dtm.getCategory(currentPath);
        if (category == null) {
            throw new GhidraMcpException(GhidraMcpError.resourceNotFound()
                .errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
                .message("Category not found at path: " + categoryPathStr)
                .build());
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
                    throw new GhidraMcpException(GhidraMcpError.execution()
                        .message("Failed to rename category: " + e.getMessage())
                        .build());
                }
            }
        }

        if (moveOpt.isPresent()) {
            CategoryPath targetParentPath = normalizeParentPath(moveOpt.get());

            Category currentParent = category.getParent();
            CategoryPath currentParentPath = currentParent != null ? currentParent.getCategoryPath() : CategoryPath.ROOT;

            if (!targetParentPath.equals(currentParentPath)) {
                Category destinationParent = dtm.getCategory(targetParentPath);
                if (destinationParent == null) {
                    destinationParent = dtm.createCategory(targetParentPath);
                }

                try {
                    destinationParent.moveCategory(category, TaskMonitor.DUMMY);
                } catch (DuplicateNameException e) {
                    throw new RuntimeException(new GhidraMcpException(GhidraMcpError.execution()
                        .message("Failed to move category: " + e.getMessage())
                        .build()));
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
            return OperationResult.success(
                "update_data_type",
                "category",
                "Category already up to date");
        }

        return OperationResult.success(
            "update_data_type",
            "category",
            "Category updated successfully");
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
}