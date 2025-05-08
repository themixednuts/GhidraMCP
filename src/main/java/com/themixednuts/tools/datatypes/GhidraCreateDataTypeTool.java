package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Data Type", mcpName = "create_data_type", category = ToolCategory.DATATYPES, description = "Creates a new data type (e.g., struct, union, enum, typedef, function definition, category).", mcpDescription = "Creates a new data type (e.g., struct, union, enum, typedef, function definition, category).")
public class GhidraCreateDataTypeTool implements IGhidraMcpSpecification {

	protected static final String ARG_BASE_TYPE_PATH = "baseTypePath";
	protected static final String ARG_FD_RETURN_TYPE_PATH = "returnTypePath";
	protected static final String ARG_FD_PARAMETERS = "parameters";
	protected static final String ARG_FD_CALLING_CONVENTION_NAME = "callingConventionName";
	protected static final String ARG_FD_HAS_VAR_ARGS = "hasVarArgs";
	protected static final String ARG_FD_NO_RETURN = "noReturn";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		// List<String> dataTypes =
		// Arrays.stream(DataTypeKind.values()).map(Enum::name).collect(Collectors.toList());

		// schemaRoot.property(ARG_DATA_TYPE,
		// JsonSchemaBuilder.string(mapper).enumValues(dataTypes)
		// .description("The kind of item to create. Valid values: " + String.join(", ",
		// dataTypes)))
		// .requiredProperty(ARG_DATA_TYPE);

		// --- Category Schema ---
		IObjectSchemaBuilder categorySchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
						.description("Name for the new category (e.g., MyCategoryName)."))
				.property(ARG_DATA_TYPE,
						JsonSchemaBuilder.string(mapper).enumValues(DataTypeKind.CATEGORY.name())
								.description("The data type kind."),
						true)
				.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
						.description(
								"Optional parent category path for the new category (e.g., /MyParentCategory). If omitted, creates a root category if name is simple, or nested if name contains path separators."))
				.requiredProperty(ARG_NAME);

		// --- Struct Schema ---
		IObjectSchemaBuilder structSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
						.description("Name for the new struct (e.g., MyStruct)."), true)
				.property(ARG_DATA_TYPE,
						JsonSchemaBuilder.string(mapper).enumValues(DataTypeKind.STRUCT.name())
								.description("The data type kind."),
						true)
				.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
						.description(
								"Optional category path for the new struct (e.g., /MyCategory). If omitted, uses default/root path."))
				.property(ARG_SIZE, JsonSchemaBuilder.integer(mapper)
						.description("Optional initial size for the struct (0 for default/growable)."))
				.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new struct."))
				.requiredProperty(ARG_NAME);

		// --- Union Schema ---
		IObjectSchemaBuilder unionSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
						.description("Name for the new union (e.g., MyUnion)."), true)
				.property(ARG_DATA_TYPE,
						JsonSchemaBuilder.string(mapper).enumValues(DataTypeKind.UNION.name())
								.description("The data type kind."),
						true)
				.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
						.description(
								"Optional category path for the new union (e.g., /MyCategory). If omitted, uses default/root path."))
				// ARG_SIZE for Union is informational, as Ghidra's UnionDataType is growable.
				.property(ARG_SIZE, JsonSchemaBuilder.integer(mapper)
						.description(
								"Informational: Ghidra UnionDataType is growable; explicit initial sizing is not directly supported. Size will be determined by members."))
				.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new union."))
				.requiredProperty(ARG_NAME);

		// --- Enum Schema ---
		IObjectSchemaBuilder enumSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
						.description("Name for the new enum (e.g., MyEnum)."), true)
				.property(ARG_DATA_TYPE,
						JsonSchemaBuilder.string(mapper).enumValues(DataTypeKind.ENUM.name())
								.description("The data type kind."),
						true)
				.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
						.description(
								"Optional category path for the new enum (e.g., /MyCategory). If omitted, uses default/root path."))
				.property(ARG_SIZE, JsonSchemaBuilder.integer(mapper)
						.description("Optional storage size in bytes (1, 2, 4, or 8; defaults to 1)."))
				.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new enum."))
				.requiredProperty(ARG_NAME);

		// --- Typedef Schema ---
		IObjectSchemaBuilder typedefSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
						.description("Name for the new typedef (e.g., MyTypedef)."), true)
				.property(ARG_DATA_TYPE,
						JsonSchemaBuilder.string(mapper).enumValues(DataTypeKind.TYPEDEF.name())
								.description("The data type kind."),
						true)
				.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
						.description(
								"Optional category path for the new typedef (e.g., /MyCategory). If omitted, uses default/root path."))
				.property(ARG_BASE_TYPE_PATH, JsonSchemaBuilder.string(mapper)
						.description("Path to a base data type (e.g., 'dword', '/MyCategory/MyStruct')."), true)
				.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new typedef."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_BASE_TYPE_PATH);

		// --- Function Definition Schema ---
		IObjectSchemaBuilder fdParamSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition for a single function parameter.")
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Parameter name."))
				.property(ARG_DATA_TYPE,
						JsonSchemaBuilder.string(mapper).enumValues(DataTypeKind.FUNCTION_DEFINITION.name())
								.description("The data type kind."),
						true)
				.property(ARG_DATA_TYPE_PATH, JsonSchemaBuilder.string(mapper)
						.description("Data type path for the parameter (e.g., 'float *', '/MyEnums/Status')."))
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper).description("Optional comment for the parameter."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		IObjectSchemaBuilder functionDefinitionSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
						.description("Name for the new function definition (e.g., MyFunctionDef)."), true)
				.property(ARG_DATA_TYPE,
						JsonSchemaBuilder.string(mapper).enumValues(DataTypeKind.FUNCTION_DEFINITION.name())
								.description("The data type kind."),
						true)
				.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
						.description(
								"Optional category path for the new function definition (e.g., /MyCategory). If omitted, uses default/root path."))
				.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new function definition."))
				.property(ARG_FD_RETURN_TYPE_PATH, JsonSchemaBuilder.string(mapper)
						.description(
								"Data type path for the return type (e.g., 'void', 'int', '/MyStructs/Result'). Defaults to 'void' if not specified."))
				.property(ARG_FD_PARAMETERS, JsonSchemaBuilder.array(mapper)
						.description("Optional ordered list of parameters.")
						.items(fdParamSchema))
				.property(ARG_FD_CALLING_CONVENTION_NAME, JsonSchemaBuilder.string(mapper)
						.description(
								"Optional calling convention name (e.g., '__stdcall', 'default'). Defaults to program's default calling convention."))
				.property(ARG_FD_HAS_VAR_ARGS, JsonSchemaBuilder.bool(mapper)
						.description("Whether the function accepts variable arguments. Defaults to false.")
						.defaultValue(false))
				.property(ARG_FD_NO_RETURN, JsonSchemaBuilder.bool(mapper)
						.description("Whether the function has no return (annotated as noreturn). Defaults to false.")
						.defaultValue(false))
				.requiredProperty(ARG_NAME);

		schemaRoot.anyOf(List.of(
				categorySchema,
				structSchema,
				unionSchema,
				enumSchema,
				typedefSchema,
				functionDefinitionSchema).stream()
				.map(schema -> schema.property(ARG_FILE_NAME,
						JsonSchemaBuilder.string(mapper).description("The file name of the Ghidra tool window to target."), true))
				.collect(Collectors.toList()));

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					// Common arguments needed before switching
					String dataTypeNameOrCategoryName = getRequiredStringArgument(args, ARG_NAME);
					DataTypeKind kind = DataTypeKind.valueOf(getRequiredStringArgument(args, ARG_DATA_TYPE));
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					CategoryPath parentCategoryPath = pathOpt.map(CategoryPath::new).orElse(CategoryPath.ROOT);
					String transactionName = "Create " + kind.toString() + ": " + dataTypeNameOrCategoryName;

					// Execute the specific creation logic within a transaction
					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();

						// Ensure parent category exists if specified (except for CATEGORY kind itself)
						if (kind != DataTypeKind.CATEGORY && pathOpt.isPresent()
								&& !parentCategoryPath.equals(CategoryPath.ROOT)) {
							DataTypeManagerUtils.ensureCategoryExists(dtm, parentCategoryPath);
						}

						// Delegate to specific creation methods
						switch (kind) {
							case CATEGORY:
								return createCategory(dtm, dataTypeNameOrCategoryName, parentCategoryPath);
							case STRUCT:
								Optional<Integer> structSizeOpt = getOptionalIntArgument(args, ARG_SIZE);
								Optional<String> structCommentOpt = getOptionalStringArgument(args, ARG_COMMENT);
								return createStruct(dtm, dataTypeNameOrCategoryName, parentCategoryPath, structCommentOpt,
										structSizeOpt);
							case UNION:
								// Size argument is ignored for union creation as per comment in schema/old code
								Optional<String> unionCommentOpt = getOptionalStringArgument(args, ARG_COMMENT);
								return createUnion(dtm, dataTypeNameOrCategoryName, parentCategoryPath, unionCommentOpt);
							case ENUM:
								Optional<Integer> enumSizeOpt = getOptionalIntArgument(args, ARG_SIZE);
								Optional<String> enumCommentOpt = getOptionalStringArgument(args, ARG_COMMENT);
								return createEnum(dtm, dataTypeNameOrCategoryName, parentCategoryPath, enumCommentOpt,
										enumSizeOpt);
							case TYPEDEF:
								String baseTypePath = getRequiredStringArgument(args, ARG_BASE_TYPE_PATH);
								Optional<String> typedefCommentOpt = getOptionalStringArgument(args, ARG_COMMENT);
								return createTypedef(dtm, dataTypeNameOrCategoryName, parentCategoryPath,
										typedefCommentOpt, baseTypePath);
							case FUNCTION_DEFINITION:
								return createFunctionDefinition(program, args, dtm, dataTypeNameOrCategoryName, parentCategoryPath);
							default:
								throw new UnsupportedOperationException(
										"Creation of data type kind '" + kind + "' is not yet implemented.");
						}
					}); // End of executeInTransaction lambda
				});
	}

	// --- Private Helper Methods for Creation Logic ---

	private String createCategory(DataTypeManager dtm, String categoryName, CategoryPath parentPath) {
		CategoryPath newCategoryPath = parentPath.extend(categoryName);
		if (dtm.getCategory(newCategoryPath) != null) {
			throw new IllegalArgumentException("Category already exists: " + newCategoryPath.getPath());
		}
		ghidra.program.model.data.Category createdCategory = dtm.createCategory(newCategoryPath);
		if (createdCategory == null) {
			// Attempt to re-fetch in case of race condition, though unlikely in transaction
			if (dtm.getCategory(newCategoryPath) == null) {
				throw new RuntimeException("Failed to create category: " + newCategoryPath.getPath());
			}
		}
		return "Category '" + newCategoryPath.getPath() + "' created.";
	}

	private String createStruct(DataTypeManager dtm, String structName, CategoryPath categoryPath,
			Optional<String> commentOpt,
			Optional<Integer> sizeOpt) {
		if (dtm.getDataType(categoryPath, structName) != null) {
			throw new IllegalArgumentException("Data type already exists: " + categoryPath.getPath()
					+ CategoryPath.DELIMITER_CHAR + structName);
		}
		StructureDataType newStruct = new StructureDataType(categoryPath, structName,
				sizeOpt.orElse(0), dtm);
		DataType newDt = dtm.addDataType(newStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add struct '" + structName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Struct '" + newDt.getPathName() + "' created.";
	}

	private String createUnion(DataTypeManager dtm, String unionName, CategoryPath categoryPath,
			Optional<String> commentOpt) {
		if (dtm.getDataType(categoryPath, unionName) != null) {
			throw new IllegalArgumentException("Data type already exists: " + categoryPath.getPath()
					+ CategoryPath.DELIMITER_CHAR + unionName);
		}
		UnionDataType newUnion = new UnionDataType(categoryPath, unionName, dtm);
		// Size is ignored as per schema comment
		DataType newDt = dtm.addDataType(newUnion, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add union '" + unionName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Union '" + newDt.getPathName() + "' created.";
	}

	private String createEnum(DataTypeManager dtm, String enumName, CategoryPath categoryPath,
			Optional<String> commentOpt,
			Optional<Integer> sizeOpt) {
		if (dtm.getDataType(categoryPath, enumName) != null) {
			throw new IllegalArgumentException("Data type already exists: " + categoryPath.getPath()
					+ CategoryPath.DELIMITER_CHAR + enumName);
		}
		int enumSize = sizeOpt.orElse(1); // Default to 1 byte if not specified
		if (enumSize != 1 && enumSize != 2 && enumSize != 4 && enumSize != 8) {
			throw new IllegalArgumentException("Invalid ARG_SIZE for ENUM: Must be 1, 2, 4, or 8. Got: " + enumSize);
		}
		EnumDataType newEnum = new EnumDataType(categoryPath, enumName, enumSize, dtm);
		DataType newDt = dtm.addDataType(newEnum, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add enum '" + enumName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Enum '" + newDt.getPathName() + "' created.";
	}

	private String createTypedef(DataTypeManager dtm, String typedefName, CategoryPath categoryPath,
			Optional<String> commentOpt, String baseTypePath) {
		DataType baseDt = dtm.getDataType(baseTypePath);
		if (baseDt == null) {
			throw new IllegalArgumentException("Base data type not found for TYPEDEF: " + baseTypePath);
		}
		if (dtm.getDataType(categoryPath, typedefName) != null) {
			throw new IllegalArgumentException("Data type already exists: " + categoryPath.getPath()
					+ CategoryPath.DELIMITER_CHAR + typedefName);
		}
		TypedefDataType newTypedef = new TypedefDataType(categoryPath, typedefName, baseDt, dtm);
		DataType newDt = dtm.addDataType(newTypedef, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add typedef '" + typedefName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Typedef '" + newDt.getPathName() + "' created.";
	}

	private String createFunctionDefinition(ghidra.program.model.listing.Program program, Map<String, Object> args,
			DataTypeManager dtm, String funcDefName, CategoryPath categoryPath) {
		if (dtm.getDataType(categoryPath, funcDefName) != null) {
			throw new IllegalArgumentException("Data type already exists: " + categoryPath.getPath()
					+ CategoryPath.DELIMITER_CHAR + funcDefName);
		}

		// Resolve optional arguments with defaults
		Optional<String> commentOpt = getOptionalStringArgument(args, ARG_COMMENT);
		String returnTypePath = getOptionalStringArgument(args, ARG_FD_RETURN_TYPE_PATH)
				.orElse(VoidDataType.dataType.getPathName()); // Default to void
		DataType returnDt = dtm.getDataType(returnTypePath);
		if (returnDt == null) {
			throw new IllegalArgumentException("Return data type not found for FUNCTION_DEFINITION: " + returnTypePath);
		}

		List<ParameterDefinition> paramDefs = new ArrayList<>();
		Optional<List<Map<String, Object>>> paramsListOpt = getOptionalListArgument(args, ARG_FD_PARAMETERS);
		if (paramsListOpt.isPresent()) {
			for (Map<String, Object> paramMap : paramsListOpt.get()) {
				String paramName = getRequiredStringArgument(paramMap, ARG_NAME);
				String paramDtPath = getRequiredStringArgument(paramMap, ARG_DATA_TYPE_PATH);
				Optional<String> paramCommentOpt = getOptionalStringArgument(paramMap, ARG_COMMENT);
				DataType paramDt = dtm.getDataType(paramDtPath);
				if (paramDt == null) {
					throw new IllegalArgumentException("Parameter data type not found: " + paramDtPath);
				}
				paramDefs.add(new ParameterDefinitionImpl(paramName, paramDt, paramCommentOpt.orElse(null)));
			}
		}

		String callingConvention = getOptionalStringArgument(args, ARG_FD_CALLING_CONVENTION_NAME)
				.orElse(program.getCompilerSpec().getDefaultCallingConvention().getName());
		boolean hasVarArgs = getOptionalBooleanArgument(args, ARG_FD_HAS_VAR_ARGS).orElse(false);
		boolean noReturn = getOptionalBooleanArgument(args, ARG_FD_NO_RETURN).orElse(false);

		// Create and configure the FunctionDefinitionDataType
		FunctionDefinitionDataType newFuncDef = new FunctionDefinitionDataType(categoryPath, funcDefName, dtm);
		newFuncDef.setReturnType(returnDt);
		newFuncDef.setArguments(paramDefs.toArray(new ParameterDefinition[0]));
		try {
			newFuncDef.setCallingConvention(callingConvention);
		} catch (InvalidInputException e) {
			throw new RuntimeException("Invalid calling convention name '" + callingConvention + "': " + e.getMessage(), e);
		}
		newFuncDef.setVarArgs(hasVarArgs);
		newFuncDef.setNoReturn(noReturn);

		// Add to manager
		DataType newDt = dtm.addDataType(newFuncDef, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add function definition '" + funcDefName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Function Definition '" + newDt.getPathName() + "' created.";
	}

	private static class DataTypeManagerUtils {
		public static void ensureCategoryExists(DataTypeManager dtm, CategoryPath categoryPath) {
			if (categoryPath == null || categoryPath.equals(CategoryPath.ROOT)) {
				return;
			}
			if (dtm.getCategory(categoryPath) == null) {
				ghidra.program.model.data.Category created = dtm.createCategory(categoryPath);
				if (created == null) {
					if (dtm.getCategory(categoryPath) == null) {
						throw new RuntimeException("Failed to create or find category: " + categoryPath.getPath());
					}
				}
			}
		}
	}
}