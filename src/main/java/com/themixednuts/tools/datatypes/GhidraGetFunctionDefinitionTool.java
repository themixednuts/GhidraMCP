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
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(key = "Get Function Definition", category = ToolCategory.DATATYPES, description = "Gets the definition of an existing function definition.", mcpName = "get_function_definition", mcpDescription = "Retrieves the definition (name, return type, parameters, etc.) of a function definition data type.")
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
		schemaRoot.property(IGhidraMcpSpecification.ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(IGhidraMcpSpecification.ARG_FUNC_DEF_PATH,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The name or path of the function definition data type (e.g., 'MyFuncSig', '/windows/FuncSig_WINAPI')."));

		schemaRoot.requiredProperty(IGhidraMcpSpecification.ARG_FILE_NAME)
				.requiredProperty(IGhidraMcpSpecification.ARG_FUNC_DEF_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String funcDefPath = getRequiredStringArgument(args, IGhidraMcpSpecification.ARG_FUNC_DEF_PATH);
			DataType dt = program.getDataTypeManager().getDataType(funcDefPath);

			if (dt == null) {
				return createErrorResult("Function definition data type not found: " + funcDefPath);
			}

			if (!(dt instanceof FunctionDefinition)) {
				return createErrorResult(
						"Data type '".concat(funcDefPath).concat("' is not a Function Definition. Found: ")
								.concat(dt.getClass().getSimpleName()));
			}

			DataTypeInfo funcDefInfo = new DataTypeInfo(dt);
			return createSuccessResult(funcDefInfo);

		}).onErrorResume(e -> createErrorResult(e));
	}
}