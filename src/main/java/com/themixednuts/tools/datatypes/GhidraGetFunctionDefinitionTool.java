package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.DataTypeInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get Function Definition", category = "Data Types", description = "Retrieve the definition of a specific function signature data type.", mcpName = "get_function_definition", mcpDescription = "Get detailed definition of a function signature data type by its name.")
public class GhidraGetFunctionDefinitionTool implements IGhidraMcpSpecification {

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
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("functionDefinitionName",
				JsonSchemaBuilder.string(mapper)
						.description(
								"The name of the function definition data type (e.g., 'MyFuncSig', '/windows/FuncSig_WINAPI')."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("functionDefinitionName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String funcDefName = getRequiredStringArgument(args, "functionDefinitionName");
			DataType dt = program.getDataTypeManager().getDataType(funcDefName);

			if (dt == null) {
				return createErrorResult("Function definition data type not found: " + funcDefName);
			}

			if (!(dt instanceof FunctionDefinition)) {
				return createErrorResult(
						"Data type '".concat(funcDefName).concat("' is not a Function Definition. Found: ")
								.concat(dt.getClass().getSimpleName()));
			}

			DataTypeInfo funcDefInfo = new DataTypeInfo(dt);
			return createSuccessResult(funcDefInfo);

		}).onErrorResume(e -> createErrorResult(e));
	}
}