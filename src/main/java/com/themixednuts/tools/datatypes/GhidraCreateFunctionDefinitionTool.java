package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.data.*;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

import ghidra.program.model.lang.CompilerSpec;
import ghidra.framework.plugintool.PluginTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Create Function Definition", category = ToolCategory.DATATYPES, description = "Creates a new function definition (signature) data type.", mcpName = "create_function_definition", mcpDescription = "Defines a new function signature data type, specifying return type, parameters, calling convention, etc.")
public class GhidraCreateFunctionDefinitionTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_FUNC_DEF_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path for the new function definition (e.g., /MyTypes/MyFunctionSig)"));

		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the return data type (e.g., 'int', '/MyStruct*', 'void')."));

		List<String> standardCallingConventions = Arrays.asList(
				CompilerSpec.CALLING_CONVENTION_cdecl,
				CompilerSpec.CALLING_CONVENTION_stdcall,
				CompilerSpec.CALLING_CONVENTION_fastcall,
				CompilerSpec.CALLING_CONVENTION_thiscall,
				CompilerSpec.CALLING_CONVENTION_pascal,
				CompilerSpec.CALLING_CONVENTION_vectorcall,
				CompilerSpec.CALLING_CONVENTION_rustcall);

		schemaRoot.property("callingConventionName",
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional calling convention name. Must be one of the standard known conventions. Defaults to program's default if omitted. Allowed values: "
										+ String.join(", ", standardCallingConventions))
						.enumValues(standardCallingConventions.toArray(new String[0])));

		schemaRoot.property("hasVarArgs",
				JsonSchemaBuilder.bool(mapper)
						.description(
								"Optional flag indicating if the function takes variable arguments (like printf). Defaults to false.")
						.defaultValue(false));

		// Schema for a single parameter
		IObjectSchemaBuilder parameterSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition for a single function parameter.")
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Optional name for the parameter. Can be omitted."))
				.property(ARG_DATA_TYPE_PATH,
						JsonSchemaBuilder.string(mapper)
								.description("Full path or name of the parameter's data type (e.g., 'dword', '/MyStruct')."))
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional comment for the parameter."))
				.requiredProperty(ARG_DATA_TYPE_PATH);

		// Optional parameters array
		schemaRoot.property("parameters",
				JsonSchemaBuilder.array(mapper)
						.items(parameterSchema)
						.description("Optional list of parameters for the function definition."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_FUNC_DEF_PATH)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, resolve types, check existence, ensure category
			// Argument parsing errors caught by onErrorResume
			String functionDefinitionPathString = getRequiredStringArgument(args, ARG_FUNC_DEF_PATH);
			String returnTypePath = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
			final Optional<String> callingConventionNameOpt = getOptionalStringArgument(args, "callingConventionName"); // Final
			Optional<ArrayNode> parametersOpt = getOptionalArrayNodeArgument(args, "parameters");
			final boolean hasVarArgs = getOptionalBooleanArgument(args, "hasVarArgs").orElse(false); // Final

			CategoryPath categoryPath; // Not final here
			final String functionName; // Final
			try {
				CategoryPath fullPath = new CategoryPath(functionDefinitionPathString);
				functionName = fullPath.getName();
				categoryPath = fullPath.getParent();
				if (categoryPath == null) {
					categoryPath = CategoryPath.ROOT;
				}
				if (functionName.isBlank()) {
					return createErrorResult("Invalid function definition path: Name cannot be blank.");
				}
			} catch (IllegalArgumentException e) {
				return createErrorResult("Invalid function definition path format: " + functionDefinitionPathString);
			}

			final DataTypeManager dtm = program.getDataTypeManager(); // Final

			// Check if data type already exists
			if (dtm.getDataType(functionDefinitionPathString) != null) {
				return createErrorResult("Data type already exists at path: " + functionDefinitionPathString);
			}

			// Resolve Return Type
			DataType resolvedReturnDt;
			if ("void".equalsIgnoreCase(returnTypePath)) {
				resolvedReturnDt = VoidDataType.dataType;
			} else {
				resolvedReturnDt = dtm.getDataType(returnTypePath);
				if (resolvedReturnDt == null) {
					return createErrorResult("Return type not found: " + returnTypePath);
				}
				resolvedReturnDt = resolvedReturnDt.clone(dtm); // Clone non-void
			}
			final DataType returnDt = resolvedReturnDt; // Final

			// Resolve Parameters
			final List<ParameterDefinition> paramDefs = new ArrayList<>(); // Final
			if (parametersOpt.isPresent()) {
				ArrayNode paramsArray = parametersOpt.get();
				for (JsonNode paramNode : paramsArray) {
					if (!paramNode.isObject()) {
						return createErrorResult("Invalid parameter definition: Expected an object.");
					}
					String paramTypePath = getRequiredStringArgument(paramNode, ARG_DATA_TYPE_PATH);
					Optional<String> paramNameOpt = getOptionalStringArgument(paramNode, ARG_NAME);
					Optional<String> paramCommentOpt = getOptionalStringArgument(paramNode, ARG_COMMENT);

					DataType paramDt = dtm.getDataType(paramTypePath);
					if (paramDt == null) {
						return createErrorResult("Parameter type not found: " + paramTypePath);
					}
					paramDt = paramDt.clone(dtm);

					String paramName = paramNameOpt.orElse(null);
					try {
						paramDefs.add(new ParameterDefinitionImpl(paramName, paramDt, paramCommentOpt.orElse(null)));
					} catch (IllegalArgumentException e) {
						return createErrorResult("Invalid parameter name '" + paramName + "': " + e.getMessage());
					}
				}
			}

			dtm.createCategory(categoryPath);

			final String finalFuncDefPath = functionDefinitionPathString; // Capture for message
			final CategoryPath finalCategoryPath = categoryPath; // Capture for lambda

			return executeInTransaction(program, "MCP - Create Function Definition", () -> {
				// Inner Callable logic:
				// Create the Function Definition Data Type
				FunctionDefinitionDataType newFuncDef = new FunctionDefinitionDataType(finalCategoryPath, functionName, dtm);

				// Set properties
				newFuncDef.setReturnType(returnDt);
				newFuncDef.setArguments(paramDefs.toArray(new ParameterDefinition[0]));
				newFuncDef.setVarArgs(hasVarArgs);

				// Set calling convention if provided (let tx catch exception if invalid)
				if (callingConventionNameOpt.isPresent()) {
					String ccName = callingConventionNameOpt.get().trim();
					if (!ccName.isBlank()) {
						newFuncDef.setCallingConvention(ccName);
					}
				}

				// Add to manager
				DataType addedType = dtm.addDataType(newFuncDef, DataTypeConflictHandler.DEFAULT_HANDLER);

				if (addedType != null) {
					return createSuccessResult(
							"Function Definition '" + finalFuncDefPath + "' created successfully.");
				} else {
					// This case might indicate an unexpected conflict despite pre-check
					return createErrorResult(
							"Failed to add Function Definition '" + finalFuncDefPath + "' after creation (unexpected conflict?).");
				}
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}

}