package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Update Function Definition", category = "Data Types", description = "Enable the MCP tool to update properties of a function definition data type.", mcpName = "update_function_definition", mcpDescription = "Updates mutable properties (return type, calling convention, varargs, etc.) of an existing function definition data type. Does not currently support parameter modification.")
public class GhidraUpdateFunctionDefinitionTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schema),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public ObjectNode schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property("functionDefinitionPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the function definition to update (e.g., /MyTypes/MyFunctionSig)"));

		schemaRoot.property("newReturnTypePath",
				JsonSchemaBuilder.string(mapper)
						.description("Optional new return type path (e.g., 'int', '/MyStruct*', 'void')."));

		List<String> standardCallingConventions = Arrays.asList(
				CompilerSpec.CALLING_CONVENTION_cdecl,
				CompilerSpec.CALLING_CONVENTION_stdcall,
				CompilerSpec.CALLING_CONVENTION_fastcall,
				CompilerSpec.CALLING_CONVENTION_thiscall,
				CompilerSpec.CALLING_CONVENTION_pascal,
				CompilerSpec.CALLING_CONVENTION_vectorcall,
				CompilerSpec.CALLING_CONVENTION_rustcall);

		schemaRoot.property("newCallingConventionName",
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional new calling convention name. Must be one of the standard known conventions. Allowed values: "
										+ String.join(", ", standardCallingConventions))
						.enumValues(standardCallingConventions.toArray(new String[0])));

		schemaRoot.property("newHasVarArgs",
				JsonSchemaBuilder.bool(mapper)
						.description("Optional new value for the varargs flag."));

		schemaRoot.property("newHasNoReturn",
				JsonSchemaBuilder.bool(mapper)
						.description("Optional new value for the no-return flag."));

		schemaRoot.property("newDescription",
				JsonSchemaBuilder.string(mapper)
						.description("Optional new description text."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("functionDefinitionPath");

		// Note: The logic for requiring at least one 'new...' property is handled
		// in the execute method.

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String funcDefPathString = getRequiredStringArgument(args, "functionDefinitionPath");

			final Optional<String> newReturnTypePathOpt = getOptionalStringArgument(args, "newReturnTypePath");
			final Optional<String> newCallingConventionNameOpt = getOptionalStringArgument(args,
					"newCallingConventionName");
			final Optional<Boolean> newHasVarArgsOpt = getOptionalBooleanArgument(args, "newHasVarArgs");
			final Optional<Boolean> newHasNoReturnOpt = getOptionalBooleanArgument(args, "newHasNoReturn");
			final Optional<String> newDescriptionOpt = getOptionalStringArgument(args, "newDescription");

			if (newReturnTypePathOpt.isEmpty() && newCallingConventionNameOpt.isEmpty() &&
					newHasVarArgsOpt.isEmpty() && newHasNoReturnOpt.isEmpty() && newDescriptionOpt.isEmpty()) {
				return createErrorResult(
						"No update properties provided. Please specify at least one 'new...' argument.");
			}

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(funcDefPathString);

			if (dt == null) {
				return createErrorResult("Function Definition not found at path: " + funcDefPathString);
			}
			if (!(dt instanceof FunctionDefinitionDataType)) {
				return createErrorResult(
						"Data type at path is not a modifiable Function Definition: " + funcDefPathString);
			}
			final FunctionDefinitionDataType funcDef = (FunctionDefinitionDataType) dt;

			final List<String> updatedFields = new ArrayList<>();
			DataType resolvedNewReturnDt = null;

			if (newReturnTypePathOpt.isPresent()) {
				String newReturnTypePath = newReturnTypePathOpt.get();
				if ("void".equalsIgnoreCase(newReturnTypePath)) {
					resolvedNewReturnDt = VoidDataType.dataType;
				} else {
					resolvedNewReturnDt = dtm.getDataType(newReturnTypePath);
					if (resolvedNewReturnDt == null) {
						return createErrorResult("New return type not found: " + newReturnTypePath);
					}
					resolvedNewReturnDt = resolvedNewReturnDt.clone(dtm);
				}
				updatedFields.add("returnType");
			}
			final DataType finalNewReturnDt = resolvedNewReturnDt;

			final String finalFuncDefPathString = funcDefPathString;
			final List<String> finalUpdatedFields = new ArrayList<>(updatedFields);
			if (newCallingConventionNameOpt.isPresent() && !newCallingConventionNameOpt.get().isBlank())
				finalUpdatedFields.add("callingConvention");
			if (newHasVarArgsOpt.isPresent())
				finalUpdatedFields.add("hasVarArgs");
			if (newHasNoReturnOpt.isPresent())
				finalUpdatedFields.add("hasNoReturn");
			if (newDescriptionOpt.isPresent())
				finalUpdatedFields.add("description");

			return executeInTransaction(program, "MCP - Update Function Definition", () -> {
				if (finalNewReturnDt != null) {
					funcDef.setReturnType(finalNewReturnDt);
				}

				if (newCallingConventionNameOpt.isPresent()) {
					String newCcName = newCallingConventionNameOpt.get().trim();
					if (!newCcName.isBlank()) {
						funcDef.setCallingConvention(newCcName);
					}
				}

				newHasVarArgsOpt.ifPresent(funcDef::setVarArgs);
				newHasNoReturnOpt.ifPresent(funcDef::setNoReturn);
				newDescriptionOpt.ifPresent(funcDef::setDescription);

				return createSuccessResult("Function Definition '" + finalFuncDefPathString
						+ "' updated successfully. Modified fields: " + String.join(", ", finalUpdatedFields));
			});

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}