package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraFunctionsToolInfo;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.program.model.listing.Function;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Get Function by Name", category = "Functions", description = "Enable the MCP tool to get a function by name.", mcpName = "get_function_by_name", mcpDescription = "Retrieve details (entry point, etc.) for a function identified by its exact name.")
public class GhidraGetFunctionByNameTool implements IGhidraMcpSpecification {

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
						.description("The file name of the Ghidra tool window to target."));
		schemaRoot.property("functionName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function to retrieve."));

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
				GhidraFunctionsToolInfo functionInfo = new GhidraFunctionsToolInfo(targetFunctionOpt.get());
				return createSuccessResult(functionInfo);
			} else {
				return createErrorResult("Error: Function '" + functionName + "' not found.");
			}
		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}

}
