package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.program.model.listing.Function;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Get Function By Name", category = "Functions", description = "Retrieve a specific function by its exact name.", mcpName = "get_function_by_name", mcpDescription = "Returns details of the function matching the specified name.")
public class GhidraGetFunctionByNameTool implements IGhidraMcpSpecification {

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
		schemaRoot.property("functionName",
				JsonSchemaBuilder.string(mapper)
						.description("The exact name of the function to retrieve."));
		schemaRoot.requiredProperty("fileName")
				.requiredProperty("functionName");
		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String functionName = getRequiredStringArgument(args, "functionName");

			Optional<Function> targetFunctionOpt = StreamSupport
					.stream(program.getSymbolTable().getSymbolIterator(functionName, true).spliterator(), false)
					.filter(symbol -> symbol instanceof FunctionSymbol)
					.map(symbol -> (Function) symbol.getObject())
					.findFirst();

			if (targetFunctionOpt.isPresent()) {
				FunctionInfo functionInfo = new FunctionInfo(targetFunctionOpt.get());
				return createSuccessResult(functionInfo);
			} else {
				return createErrorResult("Error: Function '" + functionName + "' not found.");
			}
		}).onErrorResume(e -> createErrorResult(e));
	}

}
