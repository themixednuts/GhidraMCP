package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.DataTypeUtils;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;

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

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ACTION, JsonSchemaBuilder.string(mapper)
                .enumValues("create", "read", "update", "delete", "list")
                .description("Action to perform on data types"));

        schemaRoot.property(ARG_DATA_TYPE_KIND, JsonSchemaBuilder.string(mapper)
                .enumValues("struct", "enum", "union", "typedef", "pointer", "function_definition", "category")
                .description("Type of data type to work with"));

        schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
                .description("Name of the data type"));

        schemaRoot.property(ARG_CATEGORY_PATH, JsonSchemaBuilder.string(mapper)
                .description("Category path (e.g., '/MyCategory/SubCategory')")
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
                case "create" -> handleCreate(program, args, annotation, dataTypeKind);
                case "read" -> handleRead(program, args, annotation, dataTypeKind);
                case "update" -> handleUpdate(program, args, annotation, dataTypeKind);
                case "delete" -> handleDelete(program, args, annotation, dataTypeKind);
                case "list" -> handleList(program, args, annotation, dataTypeKind);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid action: " + action)
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "action validation",
                            args,
                            Map.of(ARG_ACTION, action),
                            Map.of("validActions", List.of("create", "read", "update", "delete", "list"))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid action",
                                "Choose from: create, read, update, delete, list",
                                List.of("create", "read", "update", "delete", "list"),
                                null)))
                        .build();
                    yield Mono.error(new GhidraMcpException(error));
                }
            };
        });
    }

    private Mono<? extends Object> handleCreate(Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
        return Mono.fromCallable(() -> {
            String name = getOptionalStringArgument(args, "name").orElse("NewDataType");
            String transactionName = "Create " + dataTypeKind + ": " + name;

            return executeInTransaction(program, transactionName, () -> {
                return switch (dataTypeKind) {
                    case "struct" -> createStruct(args, program, name);
                    case "enum" -> createEnum(args, program, name);
                    case "union" -> createUnion(args, program, name);
                    case "typedef" -> createTypedef(args, program, name);
                    case "pointer" -> createPointer(args, program, name);
                    case "function_definition" -> createFunctionDefinition(args, program, name);
                    case "category" -> createCategory(args, program, name);
                    default -> "Unsupported data type kind for creation: " + dataTypeKind;
                };
            });
        }).map(result -> Map.of(
            "success", true,
            "message", result,
            "data_type_kind", dataTypeKind
        ));
    }

    private String createStruct(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, "category_path")
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

        return "Successfully created struct '" + addedStruct.getPathName() + "'" +
               (members != null ? " with " + members.size() + " members" : "");
    }

    private String createEnum(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, "category_path")
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

        return "Successfully created enum '" + addedEnum.getPathName() + "'" +
               (entries != null ? " with " + entries.size() + " entries" : "");
    }

    private String createUnion(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, "category_path")
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

        return "Successfully created union '" + addedUnion.getPathName() + "'" +
               (members != null ? " with " + members.size() + " members" : "");
    }

    private String createTypedef(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, "category_path")
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

        return "Successfully created typedef '" + addedTypedef.getPathName() + "' -> " + baseType;
    }

    private String createPointer(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, "category_path")
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

        return "Successfully created pointer type '" + addedPointer.getPathName() + "' -> " + baseType + "*";
    }

    private String createFunctionDefinition(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, "category_path")
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

        return "Successfully created function definition '" + addedFuncDef.getPathName() + "'" +
               (parameters != null ? " with " + parameters.size() + " parameters" : "");
    }

    private String createCategory(Map<String, Object> args, Program program, String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath parentPath = getOptionalStringArgument(args, "category_path")
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        CategoryPath newCategoryPath = new CategoryPath(parentPath, name);

        if (dtm.getCategory(newCategoryPath) != null) {
            throw new RuntimeException("Category already exists: " + newCategoryPath.getPath());
        }

        Category category = dtm.createCategory(newCategoryPath);
        if (category == null) {
            throw new RuntimeException("Failed to create category: " + newCategoryPath.getPath());
        }

        return "Successfully created category '" + newCategoryPath.getPath() + "'";
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

            Map<String, Object> result = new HashMap<>();
            result.put("name", dataType.getName());
            result.put("path_name", dataType.getPathName());
            result.put("kind", DataTypeUtils.getDataTypeKind(dataType));
            result.put("size", dataType.getLength());
            result.put("description", dataType.getDescription());

            // Add specific details based on type
            if (dataType instanceof Structure struct) {
                List<Map<String, Object>> components = new ArrayList<>();
                for (DataTypeComponent comp : struct.getComponents()) {
                    components.add(Map.of(
                        "name", comp.getFieldName() != null ? comp.getFieldName() : "",
                        "type", comp.getDataType().getName(),
                        "offset", comp.getOffset(),
                        "length", comp.getLength()
                    ));
                }
                result.put("components", components);
                result.put("component_count", struct.getNumComponents());
            } else if (dataType instanceof ghidra.program.model.data.Enum enumType) {
                List<Map<String, Object>> values = new ArrayList<>();
                for (String valueName : enumType.getNames()) {
                    values.add(Map.of(
                        "name", valueName,
                        "value", enumType.getValue(valueName)
                    ));
                }
                result.put("values", values);
                result.put("value_count", enumType.getCount());
            } else if (dataType instanceof Union union) {
                List<Map<String, Object>> components = new ArrayList<>();
                for (DataTypeComponent comp : union.getComponents()) {
                    components.add(Map.of(
                        "name", comp.getFieldName() != null ? comp.getFieldName() : "",
                        "type", comp.getDataType().getName(),
                        "length", comp.getLength()
                    ));
                }
                result.put("components", components);
                result.put("component_count", union.getNumComponents());
            }

            return result;
        });
    }

    private Mono<? extends Object> handleUpdate(Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
        return executeInTransaction(program, "MCP - Update " + dataTypeKind, () -> {
            // Implementation would go here for updating data types
            return Map.of("message", "Update operation not yet fully implemented", "success", false);
        });
    }

    private Mono<? extends Object> handleDelete(Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
        return executeInTransaction(program, "MCP - Delete " + dataTypeKind, () -> {
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

            boolean removed = dtm.remove(dataType, null);
            if (!removed) {
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to remove data type: " + name)
                    .build();
                throw new GhidraMcpException(error);
            }

            return Map.of(
                "success", true,
                "message", "Successfully deleted " + dataTypeKind + " '" + name + "'",
                "deleted_type", name,
                "category", categoryPath.toString()
            );
        });
    }

    private Mono<? extends Object> handleList(Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
        return Mono.fromCallable(() -> {
            CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
                .map(CategoryPath::new).orElse(CategoryPath.ROOT);
            Optional<String> filter = getOptionalStringArgument(args, "filter");
            boolean includeBuiltin = getOptionalBooleanArgument(args, "include_builtin").orElse(false);

            DataTypeManager dtm = program.getDataTypeManager();
            List<Map<String, Object>> dataTypeList = new ArrayList<>();

            // Get all data types in the category
            Category category = dtm.getCategory(categoryPath);
            if (category != null) {
                collectDataTypesAsMaps(category, dataTypeList, dataTypeKind, filter, includeBuiltin);
            }

            return Map.of(
                "data_types", dataTypeList,
                "total_count", dataTypeList.size(),
                "category", categoryPath.toString(),
                "filter_applied", filter.orElse("none"),
                "include_builtin", includeBuiltin,
                "data_type_kind", dataTypeKind
            );
        });
    }


    private void collectDataTypesAsMaps(Category category, List<Map<String, Object>> dataTypes, String kindFilter,
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

            if (nameFilter.isPresent() && !dt.getName().toLowerCase().contains(nameFilter.get().toLowerCase())) {
                continue;
            }

            Map<String, Object> dataTypeMap = new HashMap<>();
            dataTypeMap.put("name", dt.getName());
            dataTypeMap.put("path", dt.getPathName());
            dataTypeMap.put("kind", dtKind);
            dataTypeMap.put("size", dt.getLength());
            dataTypeMap.put("description", dt.getDescription() != null ? dt.getDescription() : "");
            dataTypeMap.put("category", dt.getCategoryPath().toString());

            dataTypes.add(dataTypeMap);
        }

        // Recursively collect from subcategories
        for (Category subCategory : category.getCategories()) {
            collectDataTypesAsMaps(subCategory, dataTypes, kindFilter, nameFilter, includeBuiltin);
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
}