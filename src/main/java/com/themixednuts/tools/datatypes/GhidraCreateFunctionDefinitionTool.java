package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Function Definition", mcpName = "create_function_definition", category = ToolCategory.DATATYPES, description = "Creates a new function definition data type.", mcpDescription = "Creates a new function definition data type.")
public class GhidraCreateFunctionDefinitionTool implements IGhidraMcpSpecification {

	// Constants from IGhidraMcpSpecification are used directly in schema if defined
	// there.
	// Local constants for arguments specific to this tool's schema or for clarity
	// if also in IGhidraMcpSpecification.
	protected static final String ARG_FD_RETURN_TYPE_PATH = "returnTypePath";
	protected static final String ARG_FD_PARAMETERS = "parameters";
	protected static final String ARG_FD_CALLING_CONVENTION_NAME = "callingConventionName";
	protected static final String ARG_FD_HAS_VAR_ARGS = "hasVarArgs";
	protected static final String ARG_FD_NO_RETURN = "noReturn";
	// ARG_DATA_TYPE_PATH is used inside parameter definition, already in
	// IGhidraMcpSpecification

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper)
				.description("The file name of the Ghidra tool window to target."), true);
		schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
				.description("Name for the new function definition (e.g., MyFunctionDef)."), true);
		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional category path for the new function definition (e.g., /MyCategory). If omitted, uses default/root path."));
		schemaRoot.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
				.description("Optional comment for the new function definition."));
		schemaRoot.property(ARG_FD_RETURN_TYPE_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Data type path for the return type (e.g., 'void', 'int', '/MyStructs/Result'). Defaults to 'void' if not specified."));

		IObjectSchemaBuilder fdParamSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition for a single function parameter.")
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Parameter name."))
				.property(ARG_DATA_TYPE_PATH, JsonSchemaBuilder.string(mapper)
						.description("Data type path for the parameter (e.g., 'float *', '/MyEnums/Status')."))
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper).description("Optional comment for the parameter."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		schemaRoot.property(ARG_FD_PARAMETERS, JsonSchemaBuilder.array(mapper)
				.description("Optional ordered list of parameters.")
				.items(fdParamSchema));
		schemaRoot.property(ARG_FD_CALLING_CONVENTION_NAME, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional calling convention name (e.g., '__stdcall', 'default'). Defaults to program's default calling convention."));
		schemaRoot.property(ARG_FD_HAS_VAR_ARGS, JsonSchemaBuilder.bool(mapper)
				.description("Whether the function accepts variable arguments. Defaults to false.")
				.defaultValue(false));
		schemaRoot.property(ARG_FD_NO_RETURN, JsonSchemaBuilder.bool(mapper)
				.description("Whether the function has no return (annotated as noreturn). Defaults to false.")
				.defaultValue(false));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String funcDefName = getRequiredStringArgument(args, ARG_NAME);
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					CategoryPath categoryPath = pathOpt.map(CategoryPath::new).orElse(CategoryPath.ROOT);
					String transactionName = "Create Function Definition: " + funcDefName;

					// All argument parsing for function definition happens inside the transaction
					// to ensure DataTypeManager is available for resolving type paths.
					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						ensureCategoryExists(dtm, categoryPath);
						return createFunctionDefinitionInternal(program, args, dtm, funcDefName, categoryPath);
					});
				});
	}

	private String createFunctionDefinitionInternal(ghidra.program.model.listing.Program program,
			Map<String, Object> args,
			DataTypeManager dtm, String funcDefName, CategoryPath categoryPath) {
		if (dtm.getDataType(categoryPath, funcDefName) != null) {
			throw new IllegalArgumentException("Data type already exists: " + categoryPath.getPath()
					+ CategoryPath.DELIMITER_CHAR + funcDefName);
		}

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

		DataType newDt = dtm.addDataType(newFuncDef, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add function definition '" + funcDefName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Function Definition '" + newDt.getPathName() + "' created.";
	}

	private static void ensureCategoryExists(DataTypeManager dtm, CategoryPath categoryPath) {
		if (categoryPath == null || categoryPath.equals(CategoryPath.ROOT)) {
			return;
		}
		if (dtm.getCategory(categoryPath) == null) {
			ghidra.program.model.data.Category created = dtm.createCategory(categoryPath);
			if (created == null) {
				// Attempt to re-fetch in case of race condition
				if (dtm.getCategory(categoryPath) == null) {
					throw new RuntimeException("Failed to create or find category: " + categoryPath.getPath());
				}
			}
		}
	}
}