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

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.listing.Program;

import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(name = "Create Function Definition", category = ToolCategory.DATATYPES, description = "Creates a new function definition data type.", mcpName = "create_function_definition", mcpDescription = "Define a new function signature data type.")
public class GhidraCreateFunctionDefinitionTool implements IGhidraMcpSpecification {

	public static final String ARG_RETURN_TYPE = "returnType";
	public static final String ARG_PARAMETERS = "parameters";
	public static final String ARG_DATA_TYPE_PATH = "dataType";
	public static final String ARG_VAR_ARGS = "varArgs";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_FUNC_DEF_PATH, JsonSchemaBuilder.string(mapper)
				.description("Full path for the new function definition (e.g., '/MyFuncDefs/MyFunc')."));
		schemaRoot.property(ARG_RETURN_TYPE, JsonSchemaBuilder.string(mapper)
				.description("Data type path for the return type (e.g., 'int', '/MyStructs/Result')."));
		schemaRoot.property(ARG_VAR_ARGS, JsonSchemaBuilder.bool(mapper)
				.description("Whether the function accepts variable arguments.").defaultValue(false));

		// Define parameter schema
		IObjectSchemaBuilder paramSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Parameter name."))
				.property(ARG_DATA_TYPE_PATH, JsonSchemaBuilder.string(mapper)
						.description("Data type path for the parameter (e.g., 'float *', '/MyEnums/Status')."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		schemaRoot.property(ARG_PARAMETERS, JsonSchemaBuilder.array(mapper)
				.description("Optional ordered list of parameters.")
				.items(paramSchema));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_FUNC_DEF_PATH)
				.requiredProperty(ARG_RETURN_TYPE);

		return schemaRoot.build();
	}

	// Context record for passing data between reactive stages
	private static record FuncDefContext(
			Program program,
			CategoryPath categoryPath,
			String funcName,
			DataType returnType,
			List<ParameterDefinition> parameters,
			boolean varArgs,
			String originalPathStr) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup and validation
					// Parse args
					String funcDefPathStr = getRequiredStringArgument(args, ARG_FUNC_DEF_PATH);
					String returnTypeStr = getRequiredStringArgument(args, ARG_RETURN_TYPE);
					boolean varArgs = getOptionalBooleanArgument(args, ARG_VAR_ARGS).orElse(false);
					Optional<List<Map<String, Object>>> paramsOpt = getOptionalListArgument(args, ARG_PARAMETERS);

					CategoryPath fullPath = new CategoryPath(funcDefPathStr); // Create once
					CategoryPath catPath = fullPath.getParent();
					String funcName = fullPath.getName();

					if (funcName.isBlank()) {
						throw new IllegalArgumentException("Function definition name cannot be blank in path: " + funcDefPathStr);
					}

					if (catPath == null) { // Ensure ROOT category if needed
						catPath = CategoryPath.ROOT;
					}

					DataType returnType = program.getDataTypeManager().getDataType(returnTypeStr);
					if (returnType == null) {
						throw new IllegalArgumentException("Return type not found: " + returnTypeStr);
					}

					// Resolve parameters
					List<ParameterDefinition> parameters = new ArrayList<>();
					if (paramsOpt.isPresent()) {
						for (Map<String, Object> paramMap : paramsOpt.get()) {
							String paramName = getRequiredStringArgument(paramMap, ARG_NAME);
							String paramTypeStr = getRequiredStringArgument(paramMap, ARG_DATA_TYPE_PATH);
							DataType paramType = program.getDataTypeManager().getDataType(paramTypeStr);
							if (paramType == null) {
								throw new IllegalArgumentException("Parameter type not found: " + paramTypeStr);
							}
							parameters.add(new ParameterDefinitionImpl(paramName, paramType, null));
						}
					}

					// Don't check existence here, do it in the transaction
					return new FuncDefContext(program, catPath, funcName, returnType, parameters, varArgs, funcDefPathStr);
				})
				.flatMap(context -> { // .flatMap for transaction
					return executeInTransaction(context.program(), "Create Function Definition " + context.funcName(), () -> {
						DataTypeManager dtm = context.program().getDataTypeManager();

						// Check existence *inside* transaction
						if (dtm.getDataType(context.categoryPath(), context.funcName()) != null) {
							throw new IllegalArgumentException(
									"Function definition already exists (checked in transaction): " + context.originalPathStr());
						}

						// Ensure category exists *inside* transaction
						Category category = dtm.createCategory(context.categoryPath());
						if (category == null) {
							category = dtm.getCategory(context.categoryPath()); // Try getting if create failed concurrently
							if (category == null) {
								throw new RuntimeException(
										"Failed to create or find category in transaction: " + context.categoryPath());
							}
						}

						// Creation inside transaction, using correct category path
						FunctionDefinitionDataType newFuncDef = new FunctionDefinitionDataType(category.getCategoryPath(),
								context.funcName(), dtm);
						newFuncDef.setReturnType(context.returnType());
						newFuncDef.setArguments(context.parameters().toArray(new ParameterDefinition[0]));
						newFuncDef.setVarArgs(context.varArgs());

						// Add to DTM using default conflict handler
						DataType resolvedDataType = dtm.addDataType(newFuncDef, DataTypeConflictHandler.DEFAULT_HANDLER);
						if (!(resolvedDataType instanceof FunctionDefinitionDataType)) {
							// addDataType might return the existing type on conflict if handler allows,
							// or null/throw exception depending on handler/error
							throw new RuntimeException(
									"Failed to add function definition to data type manager, or unexpected type returned: "
											+ context.originalPathStr());
						}

						return "Function definition created successfully: " + resolvedDataType.getPathName();
					}); // End executeInTransaction lambda
				}); // End flatMap
	}
}