package com.themixednuts.tools.functions;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraFunctionsToolInfo;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get Current Function", category = "Functions", description = "Enable the MCP tool to get the function currently selected in the active Ghidra tool.", mcpName = "get_current_function", mcpDescription = "Retrieve details of the function containing the current cursor location in the active Ghidra Code Browser window for the specified program.")
public class GhidraGetCurrentFunctionTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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
						.description("The name of the program file."));
		schemaRoot.requiredProperty("fileName");
		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			CodeViewerService service = tool.getService(CodeViewerService.class);
			if (service == null) {
				return createErrorResult("Code viewer service not available in the current tool.");
			}

			ProgramLocation location = service.getCurrentLocation();
			if (location == null || location.getAddress() == null) {
				return createErrorResult("No current location or address available in the Code Browser.");
			}

			if (location.getProgram() != program) {
				return createErrorResult(
						"Code viewer service is not focused on the requested program: " + program.getName());
			}

			Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
			if (func == null) {
				return createErrorResult("No function found at current location: " + location.getAddress());
			}

			GhidraFunctionsToolInfo functionInfo = new GhidraFunctionsToolInfo(func);
			return createSuccessResult(functionInfo);

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}