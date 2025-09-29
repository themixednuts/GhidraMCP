package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DataTypeDeleteResult;
import com.themixednuts.models.CreateDataTypeResult;
import com.themixednuts.models.DataTypeReadResult;
import com.themixednuts.models.DataTypeReadResult.DataTypeComponentDetail;
import com.themixednuts.models.DataTypeReadResult.DataTypeEnumValue;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.RTTIAnalysisResult;
import com.themixednuts.utils.DataTypeUtils;
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
import ghidra.app.util.datatype.microsoft.RTTI0DataType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.address.Address;
import ghidra.app.util.demangler.DemanglerUtil;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@GhidraMcpTool(
    name = "Manage Data Types",
    description = "Data type CRUD operations: create, read, update, and delete structs, enums, unions, typedefs, and categories.",
    mcpName = "manage_data_types",
    mcpDescription = """
    <use_case>
    Data type CRUD operations for Ghidra programs. Create, read, update, and delete
    structures, enums, unions, typedefs, pointers, function definitions, and categories. Essential for
    reverse engineering when you need to define custom data structures and organize type information.
    </use_case>

    <important_notes>
    - Supports complex operations like creating structs with all members in one call
    - Handles category organization and type resolution automatically
    - Validates data types and provides detailed error messages
    - Uses transactions for safe modifications
    - Use ListDataTypesTool for browsing data types with filtering
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

    private static final String ACTION_CREATE = "create";
    private static final String ACTION_READ = "read";
    private static final String ACTION_UPDATE = "update";
    private static final String ACTION_DELETE = "delete";

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
                        ACTION_DELETE)
                .description("Action to perform on data types"));

        schemaRoot.property(ARG_DATA_TYPE_KIND, JsonSchemaBuilder.string(mapper)
                .enumValues("struct", "enum", "union", "typedef", "pointer", "function_definition", "category", "rtti0")
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

        schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
                .description("Optional: Address to analyze for RTTI structure information"));


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
                                    ACTION_DELETE))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid action",
                                "Choose from: create, read, update, delete",
                                List.of(
                                        ACTION_CREATE,
                                        ACTION_READ,
                                        ACTION_UPDATE,
                                        ACTION_DELETE),
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
            case "rtti" -> updateRTTI(dtm, (RTTI0DataType) existing, args, annotation);
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
                    case "rtti0" -> createRTTI0(args, program, name);
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

    private CreateDataTypeResult createStruct(Map<String, Object> args, Program program, String name) throws GhidraMcpException {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);
        checkDataTypeExists(dtm, categoryPath, name);

        int size = getOptionalIntArgument(args, "size").orElse(0);
        StructureDataType newStruct = new StructureDataType(categoryPath, name, size, dtm);

        // Handle packing
        getOptionalIntArgument(args, "packing_value").ifPresent(packingValue -> {
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
        getOptionalIntArgument(args, "alignment_value").ifPresent(alignmentValue -> {
            switch (alignmentValue) {
                case -1 -> newStruct.setToDefaultAligned();
                case 0 -> newStruct.setToMachineAligned();
                default -> newStruct.setExplicitMinimumAlignment(alignmentValue);
            }
        });

        DataType addedStruct = dtm.addDataType(newStruct, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedStruct == null) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to add struct to data type manager")
                .build());
        }

        // Set comment if provided
        getOptionalStringArgument(args, "comment").ifPresent(addedStruct::setDescription);

        // Add members if provided
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) args.get("members");
        processStructMembers(members, dtm, (Structure) addedStruct);

        return new CreateDataTypeResult(
            "struct",
            addedStruct.getName(),
            addedStruct.getPathName(),
            "Successfully created struct",
            Map.of(
                "member_count", members != null ? members.size() : 0,
                "size", addedStruct.getLength()));
    }

    private CreateDataTypeResult createEnum(Map<String, Object> args, Program program, String name) throws GhidraMcpException {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);
        checkDataTypeExists(dtm, categoryPath, name);

        int size = getOptionalIntArgument(args, "size").orElse(1);
        validateEnumSize(size);

        EnumDataType newEnum = new EnumDataType(categoryPath, name, size, dtm);

        // Add entries if provided
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> entries = (List<Map<String, Object>>) args.get("entries");
        Optional.ofNullable(entries)
            .ifPresent(entryList -> 
                entryList.stream()
                    .filter(entry -> entry.get("name") != null && entry.get("value") != null)
                    .forEach(entry -> {
                        String entryName = (String) entry.get("name");
                        Integer entryValue = (Integer) entry.get("value");
                        newEnum.add(entryName, entryValue.longValue());
                    })
            );

        DataType addedEnum = dtm.addDataType(newEnum, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedEnum == null) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to add enum to data type manager")
                .build());
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

    private CreateDataTypeResult createUnion(Map<String, Object> args, Program program, String name) throws GhidraMcpException {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);
        checkDataTypeExists(dtm, categoryPath, name);

        UnionDataType newUnion = new UnionDataType(categoryPath, name, dtm);

        // Add members if provided
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) args.get("members");
        processUnionMembers(members, dtm, newUnion);

        DataType addedUnion = dtm.addDataType(newUnion, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedUnion == null) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to add union to data type manager")
                .build());
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

    private CreateDataTypeResult createTypedef(Map<String, Object> args, Program program, String name) throws GhidraMcpException {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);

        String baseType = getRequiredStringArgument(args, "base_type");
        DataType baseDataType = DataTypeUtils.resolveDataType(dtm, baseType);
        if (baseDataType == null) {
            throw new GhidraMcpException(GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
                .message("Could not resolve base type: " + baseType)
                .build());
        }

        TypedefDataType newTypedef = new TypedefDataType(categoryPath, name, baseDataType, dtm);
        DataType addedTypedef = dtm.addDataType(newTypedef, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedTypedef == null) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to add typedef to data type manager")
                .build());
        }

        getOptionalStringArgument(args, "comment").ifPresent(addedTypedef::setDescription);

        return new CreateDataTypeResult(
            "typedef",
            addedTypedef.getName(),
            addedTypedef.getPathName(),
            "Successfully created typedef",
            Map.of("base_type", baseType));
    }

    private CreateDataTypeResult createPointer(Map<String, Object> args, Program program, String name) throws GhidraMcpException {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);

        String baseType = getRequiredStringArgument(args, "base_type");
        DataType baseDataType = DataTypeUtils.resolveDataType(dtm, baseType);
        if (baseDataType == null) {
            throw new GhidraMcpException(GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
                .message("Could not resolve base type: " + baseType)
                .build());
        }

        Pointer pointer = PointerDataType.getPointer(baseDataType, dtm);
        TypedefDataType pointerTypedef = new TypedefDataType(categoryPath, name, pointer, dtm);

        DataType addedPointer = dtm.addDataType(pointerTypedef, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedPointer == null) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to add pointer type to data type manager")
                .build());
        }

        getOptionalStringArgument(args, "comment").ifPresent(addedPointer::setDescription);

        return new CreateDataTypeResult(
            "pointer",
            addedPointer.getName(),
            addedPointer.getPathName(),
            "Successfully created pointer",
            Map.of("base_type", baseType + "*"));
    }

    private CreateDataTypeResult createFunctionDefinition(Map<String, Object> args, Program program, String name) throws GhidraMcpException {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);

        String returnType = getOptionalStringArgument(args, "return_type").orElse("void");
        DataType returnDataType = DataTypeUtils.resolveDataType(dtm, returnType);
        if (returnDataType == null) {
            throw new GhidraMcpException(GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
                .message("Could not resolve return type: " + returnType)
                .build());
        }

        FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(categoryPath, name, dtm);
        funcDef.setReturnType(returnDataType);

        // Add parameters if provided
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> parameters = (List<Map<String, Object>>) args.get("parameters");
        try {
            Optional.ofNullable(parameters)
                .filter(list -> !list.isEmpty())
                .ifPresent(paramList -> {
                    // Pre-validate all parameter types first to avoid partial state
                    paramList.forEach(param -> {
                        String paramType = (String) param.get("type");
                        if (DataTypeUtils.resolveDataType(dtm, paramType) == null) {
                            throw new RuntimeException(new GhidraMcpException(GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
                                .message("Could not resolve parameter type: " + paramType)
                                .build()));
                        }
                    });

                    // Now build the parameter definitions
                    List<ParameterDefinition> defs = IntStream.range(0, paramList.size())
                        .mapToObj(i -> {
                            Map<String, Object> param = paramList.get(i);
                            String paramName = Optional.ofNullable((String) param.get("name"))
                                .orElse("param" + (i + 1));
                            String paramType = (String) param.get("type");

                            // This should not fail since we pre-validated
                            DataType paramDataType = DataTypeUtils.resolveDataType(dtm, paramType);
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
            throw new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to add function definition to data type manager")
                .build());
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

    private CreateDataTypeResult createCategory(Map<String, Object> args, Program program, String name) throws GhidraMcpException {
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

    private CreateDataTypeResult createRTTI0(Map<String, Object> args, Program program, String name) throws GhidraMcpException {
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
            .map(CategoryPath::new).orElse(CategoryPath.ROOT);

        ensureCategoryExists(dtm, categoryPath);
        checkDataTypeExists(dtm, categoryPath, name);

        // Create RTTI0DataType
        RTTI0DataType rttiType = new RTTI0DataType(dtm);
        
        // Add to data type manager
        DataType addedRTTI = dtm.addDataType(rttiType, DataTypeConflictHandler.REPLACE_HANDLER);
        if (addedRTTI == null) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                .message("Failed to add RTTI0 data type to data type manager")
                .build());
        }

        // Set comment if provided
        getOptionalStringArgument(args, "comment").ifPresent(addedRTTI::setDescription);

        return new CreateDataTypeResult(
            "rtti0",
            addedRTTI.getName(),
            addedRTTI.getPathName(),
            "Successfully created RTTI0 data type",
            Map.of(
                "component_count", 3, // RTTI0DataType has 3 components: vfTablePointer, dataPointer, name
                "size", addedRTTI.getLength()));
    }

    private Mono<? extends Object> handleRead(Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
        return Mono.fromCallable(() -> {
            // Check if this is an RTTI analysis request
            Optional<String> analyzeAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
            if (analyzeAddressOpt.isPresent()) {
                return analyzeRTTIAtAddress(program, analyzeAddressOpt.get(), dataTypeKind);
            }

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
                // For RTTI types, we'll provide special handling
                // RTTI0DataType has 3 components: vfTablePointer, dataPointer, name
                components = List.of(
                    new DataTypeComponentDetail("vfTablePointer", "Pointer", 0, 8),
                    new DataTypeComponentDetail("dataPointer", "Pointer", 8, 8),
                    new DataTypeComponentDetail("name", "NullTerminatedString", 16, -1)
                );
                componentCount = 3;
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
                                         GhidraMcpTool annotation) {
        Structure struct = existing;

        getOptionalStringArgument(args, ARG_COMMENT).ifPresent(struct::setDescription);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) args.get(ARG_MEMBERS);
        Optional.ofNullable(members)
            .ifPresent(memberList -> {
                struct.deleteAll();
                memberList.forEach(member -> {
                    String memberName = (String) member.get(ARG_NAME);
                    String dataTypePath = (String) member.get(ARG_DATA_TYPE_PATH);
                    Integer offset = (Integer) member.get(ARG_OFFSET);
                    String memberComment = (String) member.get(ARG_COMMENT);

                    try {
                        DataType memberDataType = DataTypeUtils.resolveDataType(dtm, dataTypePath);
                        if (memberDataType == null) {
                            throw new RuntimeException("Could not resolve data type: " + dataTypePath);
                        }

                        if (offset == null || offset == -1) {
                            struct.add(memberDataType, memberName, memberComment);
                        } else {
                            struct.insertAtOffset(offset, memberDataType, memberDataType.getLength(), memberName, memberComment);
                        }
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to add member '" + memberName + "': " + e.getMessage());
                    }
                });
            });

        return OperationResult.success(
            "update_data_type",
            "struct",
            "Struct updated successfully");
    }

    private OperationResult updateEnum(DataTypeManager dtm,
                                       ghidra.program.model.data.Enum existing,
                                       Map<String, Object> args,
                                       GhidraMcpTool annotation) throws GhidraMcpException {
        // Set description if provided
        getOptionalStringArgument(args, ARG_COMMENT).ifPresent(comment -> existing.setDescription(comment));

        // Handle resizing and get the final enum type to use
        final ghidra.program.model.data.Enum finalEnumType;
        Integer size = getOptionalIntArgument(args, ARG_SIZE).orElse(null);
        if (size != null && size != existing.getLength()) {
            ghidra.program.model.data.EnumDataType resized = new ghidra.program.model.data.EnumDataType(
                existing.getCategoryPath(), existing.getName(), size, dtm);
            Arrays.stream(existing.getNames())
                .forEach(name -> resized.add(name, existing.getValue(name), existing.getComment(name)));
            try {
                dtm.replaceDataType(existing, resized, true);
                finalEnumType = resized;
            } catch (DataTypeDependencyException e) {
                throw new GhidraMcpException(GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to resize enum: " + e.getMessage())
                    .build());
            }
        } else {
            finalEnumType = existing;
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> entries = (List<Map<String, Object>>) args.get(ARG_ENTRIES);
        Optional.ofNullable(entries)
            .ifPresent(entryList -> {
                ghidra.program.model.data.EnumDataType updated = new ghidra.program.model.data.EnumDataType(
                    finalEnumType.getCategoryPath(), finalEnumType.getName(), finalEnumType.getLength(), dtm);
                
                entryList.stream()
                    .filter(entry -> entry.get(ARG_NAME) != null && entry.get(ARG_VALUE) != null)
                    .forEach(entry -> {
                        String entryName = (String) entry.get(ARG_NAME);
                        Number value = (Number) entry.get(ARG_VALUE);
                        String comment = (String) entry.get(ARG_COMMENT);
                        
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

        return OperationResult.success(
            "update_data_type",
            "enum",
            "Enum updated successfully");
    }

    private OperationResult updateUnion(DataTypeManager dtm,
                                        Union existing,
                                        Map<String, Object> args,
                                        GhidraMcpTool annotation) {
        Union union = existing;

        getOptionalStringArgument(args, ARG_COMMENT).ifPresent(union::setDescription);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) args.get(ARG_MEMBERS);
        Optional.ofNullable(members)
            .ifPresent(memberList -> {
                UnionDataType updated = new UnionDataType(union.getCategoryPath(), union.getName(), dtm);
                
                memberList.forEach(member -> {
                    String memberName = (String) member.get(ARG_NAME);
                    String dataTypePath = (String) member.get(ARG_DATA_TYPE_PATH);
                    String memberComment = (String) member.get(ARG_COMMENT);

                    DataType memberDataType = DataTypeUtils.resolveDataType(dtm, dataTypePath);
                    if (memberDataType == null) {
                        throw new RuntimeException("Could not resolve data type: " + dataTypePath);
                    }

                    updated.add(memberDataType, memberName, memberComment);
                });
                
                try {
                    dtm.replaceDataType(union, updated, true);
                } catch (DataTypeDependencyException e) {
                    throw new RuntimeException("Failed to update union members: " + e.getMessage());
                }
            });

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
        Optional.ofNullable(parameters)
            .ifPresent(paramList -> {
                List<ParameterDefinition> defs = IntStream.range(0, paramList.size())
                    .mapToObj(i -> {
                        Map<String, Object> param = paramList.get(i);
                        String paramTypeName = (String) param.get(ARG_TYPE);
                        if (paramTypeName == null) {
                            return null;
                        }
                        
                        DataType paramType = DataTypeUtils.resolveDataType(dtm, paramTypeName);
                        if (paramType == null) {
                            throw new RuntimeException("Could not resolve parameter type: " + paramTypeName);
                        }
                        
                        String paramName = Optional.ofNullable((String) param.get(ARG_NAME))
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

    private OperationResult updateRTTI(DataTypeManager dtm,
                                      RTTI0DataType existing,
                                      Map<String, Object> args,
                                      GhidraMcpTool annotation) throws GhidraMcpException {
        // RTTI data types are typically read-only in terms of structure
        // We can only update the description/comment
        getOptionalStringArgument(args, ARG_COMMENT).ifPresent(existing::setDescription);

        return OperationResult.success(
            "update_data_type",
            "rtti",
            "RTTI data type updated successfully");
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

    /**
     * Helper method to validate enum size
     */
    private static void validateEnumSize(int size) throws GhidraMcpException {
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            throw new GhidraMcpException(GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Invalid enum size: " + size + ". Must be 1, 2, 4, or 8 bytes.")
                .build());
        }
    }

    /**
     * Helper method to check if data type already exists
     */
    private static void checkDataTypeExists(DataTypeManager dtm, CategoryPath categoryPath, String name) throws GhidraMcpException {
        if (dtm.getDataType(categoryPath, name) != null) {
            throw new GhidraMcpException(GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
                .message("Data type already exists: " + categoryPath.getPath() + "/" + name)
                .build());
        }
    }

    /**
     * Helper method to process struct/union members with consistent error handling
     */
    private void processStructMembers(List<Map<String, Object>> members, DataTypeManager dtm, Structure struct) {
        Optional.ofNullable(members)
            .filter(list -> !list.isEmpty())
            .ifPresent(memberList -> 
                memberList.forEach(member -> {
                    String memberName = (String) member.get("name");
                    String dataTypePath = (String) member.get("data_type_path");
                    String memberComment = (String) member.get("comment");
                    Integer offset = (Integer) member.get("offset");

                    try {
                        DataType memberDataType = DataTypeUtils.resolveDataType(dtm, dataTypePath);
                        if (memberDataType == null) {
                            throw new RuntimeException("Could not resolve data type: " + dataTypePath);
                        }

                        if (offset == null || offset == -1) {
                            struct.add(memberDataType, memberName, memberComment);
                        } else {
                            struct.insertAtOffset(offset, memberDataType, memberDataType.getLength(), memberName, memberComment);
                        }
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to add member '" + memberName + "': " + e.getMessage());
                    }
                })
            );
    }

    /**
     * Helper method to process union members
     */
    private void processUnionMembers(List<Map<String, Object>> members, DataTypeManager dtm, UnionDataType union) {
        Optional.ofNullable(members)
            .ifPresent(memberList -> 
                memberList.forEach(member -> {
                    String memberName = (String) member.get("name");
                    String dataTypePath = (String) member.get("data_type_path");
                    String memberComment = (String) member.get("comment");

                    try {
                        DataType memberDataType = DataTypeUtils.resolveDataType(dtm, dataTypePath);
                        if (memberDataType == null) {
                            throw new RuntimeException("Could not resolve data type: " + dataTypePath);
                        }
                        union.add(memberDataType, memberName, memberComment);
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to add member '" + memberName + "': " + e.getMessage());
                    }
                })
            );
    }


    private RTTIAnalysisResult analyzeRTTIAtAddress(Program program, String addressStr, String dataTypeKind) throws GhidraMcpException {
        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                throw new GhidraMcpException(GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid address: " + addressStr)
                        .build());
            }

            Memory memory = program.getMemory();
            DataTypeManager dtm = program.getDataTypeManager();
            
            // Test RTTI0DataType
            RTTI0DataType rtti0 = new RTTI0DataType(dtm);
            boolean isValid = rtti0.isValid(program, address, null);

            if (!isValid) {
                return new RTTIAnalysisResult(
                    "RTTI0DataType",
                    addressStr,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    false,
                    Optional.of("No valid RTTI0 structure found at address"),
                    false,
                    Optional.of("Address does not contain valid RTTI0 structure"),
                    0,
                    rtti0.getDescription(),
                    rtti0.getMnemonic(null),
                    rtti0.getDefaultLabelPrefix(),
                    Map.of("attemptedType", "RTTI0DataType")
                );
            }

            // Extract RTTI information
            Optional<String> vtableAddress = Optional.empty();
            Optional<String> spareDataAddress = Optional.empty();
            Optional<String> mangledName = Optional.empty();
            Optional<String> demangledName = Optional.empty();
            boolean demanglingSuccessful = false;
            Optional<String> demanglingError = Optional.empty();
            int length = 0;

            try {
                // Get length using the proper method signature
                length = rtti0.getLength(memory, address);
                
                // Get vtable address using the public method
                vtableAddress = Optional.ofNullable(rtti0.getVFTableAddress(memory, address))
                    .map(Address::toString);
                
                // Get spare data address using the public method
                spareDataAddress = Optional.ofNullable(rtti0.getSpareDataAddress(memory, address))
                    .map(Address::toString);
                
                // Get mangled name using the proper method from RTTI0DataType
                try {
                    // Create MemBuffer using MemoryBufferImpl
                    MemBuffer memBuffer = new MemoryBufferImpl(memory, address);
                    String name = rtti0.getVFTableName(memBuffer);
                    mangledName = Optional.ofNullable(name);
                } catch (Exception e) {
                    mangledName = Optional.empty();
                }

                // Attempt to demangle if we have a mangled name
                if (mangledName.isPresent()) {
                    try {
                        var demangledList = DemanglerUtil.demangle(program, mangledName.get(), null);
                        demangledName = Optional.ofNullable(demangledList)
                            .filter(list -> !list.isEmpty())
                            .map(list -> list.get(0).toString());
                        demanglingSuccessful = demangledName.isPresent();
                        if (!demanglingSuccessful) {
                            demanglingError = Optional.of("No demangler could process this symbol");
                        }
                    } catch (Exception e) {
                        demanglingError = Optional.of("Demangling failed: " + e.getMessage());
                    }
                } else {
                    demanglingError = Optional.of("No mangled name found in RTTI structure");
                }

            } catch (Exception e) {
                demanglingError = Optional.of("Failed to extract RTTI information: " + e.getMessage());
            }

            Map<String, Object> additionalInfo = Map.of(
                "rttiTypeName", "RTTI0DataType",
                "length", length,
                "hasVtable", vtableAddress.isPresent(),
                "hasSpareData", spareDataAddress.isPresent()
            );

            return new RTTIAnalysisResult(
                "RTTI0DataType",
                addressStr,
                vtableAddress,
                spareDataAddress,
                mangledName,
                demangledName,
                demanglingSuccessful,
                demanglingError,
                isValid,
                Optional.empty(),
                length,
                rtti0.getDescription(),
                rtti0.getMnemonic(null),
                rtti0.getDefaultLabelPrefix(),
                additionalInfo
            );

        } catch (Exception e) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to analyze RTTI at address: " + e.getMessage())
                    .build());
        }
    }
}