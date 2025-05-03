package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.FunctionSymbol;

@GhidraMcpTool(key = "Rename Function by Name", category = ToolCategory.FUNCTIONS, description = "Renames a function identified by its current name.", mcpName = "rename_function_by_name", mcpDescription = "Finds a function by its current name and renames it.")
public class GhidraRenameFunctionByNameTool implements IGhidraMcpSpecification {

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
		schemaRoot.property("currentName",
				JsonSchemaBuilder.string(mapper)
						.description("The current name of the function to rename."));
		schemaRoot.property("newName",
				JsonSchemaBuilder.string(mapper)
						.description("The new name for the function."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("currentName")
				.requiredProperty("newName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String currentFunctionName = getRequiredStringArgument(args, "currentName");
			String newName = getRequiredStringArgument(args, "newName");

			Optional<Function> targetFunctionOpt = StreamSupport
					.stream(program.getSymbolTable().getSymbolIterator(currentFunctionName, true).spliterator(), false)
					.filter(symbol -> symbol instanceof FunctionSymbol)
					.map(symbol -> (Function) symbol.getObject())
					.findFirst();

			if (targetFunctionOpt.isEmpty()) {
				return createErrorResult("Error: Function '" + currentFunctionName + "' not found.");
			}
			Function targetFunction = targetFunctionOpt.get();

			return executeInTransaction(program, "Rename Function: " + newName, () -> {
				targetFunction.setName(newName, SourceType.USER_DEFINED);
				return createSuccessResult("Function renamed successfully to " + newName);
			});
		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}

}
