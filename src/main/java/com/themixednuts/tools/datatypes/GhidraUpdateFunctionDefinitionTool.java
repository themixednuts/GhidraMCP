package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Update Function Definition", category = ToolCategory.DATATYPES, description = "Updates an existing function definition data type.", mcpName = "update_function_definition", mcpDescription = "Updates the return type, parameters, calling convention, or varargs status of an existing function definition.")
public class GhidraUpdateFunctionDefinitionTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = schemaObject.toJsonString(mapper);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to serialize schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder parameterSchema = JsonSchemaBuilder.object(mapper)
				.property("name", JsonSchemaBuilder.string(mapper).description("Parameter name"), true)
				.property("type", JsonSchemaBuilder.string(mapper).description("Parameter data type name"), true)
				.property("comment", JsonSchemaBuilder.string(mapper).description("Optional parameter comment"))
				.description("Definition of a single parameter.");

		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("functionDefinitionName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function definition data type to update."));
		schemaRoot.property("newReturnType",
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new return data type name."));
		schemaRoot.property("newParameters",
				JsonSchemaBuilder.array(mapper)
						.items(parameterSchema)
						.description("Optional: A new list of parameters. Replaces existing parameters."));
		schemaRoot.property("newComment",
				JsonSchemaBuilder.string(mapper)
						.description("Optional: A new comment for the function definition."));

		List<String> standardCallingConventions = List.of(
				CompilerSpec.CALLING_CONVENTION_cdecl,
				CompilerSpec.CALLING_CONVENTION_stdcall,
				CompilerSpec.CALLING_CONVENTION_fastcall,
				CompilerSpec.CALLING_CONVENTION_thiscall,
				CompilerSpec.CALLING_CONVENTION_pascal,
				CompilerSpec.CALLING_CONVENTION_vectorcall,
				CompilerSpec.CALLING_CONVENTION_rustcall);

		schemaRoot.property("newCallingConvention",
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new calling convention name. Must be one of the standard known conventions.")
						.enumValues(standardCallingConventions));
		schemaRoot.property("removeVarArgs",
				JsonSchemaBuilder.bool(mapper)
						.description("Optional: Set to true to remove varargs. Defaults to false.")
						.defaultValue(false));
		schemaRoot.property("addVarArgs",
				JsonSchemaBuilder.bool(mapper)
						.description("Optional: Set to true to add varargs. Defaults to false.")
						.defaultValue(false));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("functionDefinitionName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			DataTypeManager dtm = program.getDataTypeManager();
			String funcDefName = getRequiredStringArgument(args, "functionDefinitionName");
			Optional<String> newReturnTypeOpt = getOptionalStringArgument(args, "newReturnType");
			Optional<List<Map<String, Object>>> newParamsOpt = getOptionalListArgument(args, "newParameters");
			Optional<String> newCommentOpt = getOptionalStringArgument(args, "newComment");
			Optional<String> newCallingConventionOpt = getOptionalStringArgument(args, "newCallingConvention");
			boolean removeVarArgs = getOptionalBooleanArgument(args, "removeVarArgs").orElse(false);
			boolean addVarArgs = getOptionalBooleanArgument(args, "addVarArgs").orElse(false);

			return executeInTransaction(program, "Update Function Definition: " + funcDefName, () -> {
				DataType dt = dtm.getDataType(funcDefName);
				if (dt == null) {
					return createErrorResult("Function definition data type not found: " + funcDefName);
				}
				if (!(dt instanceof FunctionDefinition)) {
					return createErrorResult("Data type '".concat(funcDefName).concat("' is not a Function Definition."));
				}
				FunctionDefinition funcDef = (FunctionDefinition) dt;

				if (newReturnTypeOpt.isPresent()) {
					DataType returnDt = dtm.getDataType(newReturnTypeOpt.get());
					if (returnDt == null) {
						return createErrorResult("New return data type not found: " + newReturnTypeOpt.get());
					}
					funcDef.setReturnType(returnDt);
				}

				if (newParamsOpt.isPresent()) {
					List<ParameterDefinition> params = new ArrayList<>();
					for (Map<String, Object> paramMap : newParamsOpt.get()) {
						String paramName = getRequiredStringArgument(paramMap, "name");
						String paramTypeName = getRequiredStringArgument(paramMap, "type");
						String paramComment = getOptionalStringArgument(paramMap, "comment").orElse(null);
						DataType paramDt = dtm.getDataType(paramTypeName);
						if (paramDt == null) {
							return createErrorResult("Parameter data type not found: " + paramTypeName);
						}
						params.add(new ParameterDefinitionImpl(paramName, paramDt, paramComment));
					}
					funcDef.setArguments(params.toArray(new ParameterDefinition[0]));
				}

				if (removeVarArgs && addVarArgs) {
					return createErrorResult("Cannot both add and remove varargs in the same operation.");
				}
				if (removeVarArgs) {
					funcDef.setVarArgs(false);
				}
				if (addVarArgs) {
					funcDef.setVarArgs(true);
				}

				newCommentOpt.ifPresent(funcDef::setComment);

				if (newCallingConventionOpt.isPresent()) {
					funcDef.setCallingConvention(newCallingConventionOpt.get());
				}

				return createSuccessResult("Function definition '" + funcDefName + "' updated successfully.");
			});
		}).onErrorResume(e -> createErrorResult(e));
	}
}