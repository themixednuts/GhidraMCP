package com.themixednuts.tools.memory;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get Current Address", category = "Memory", description = "Enable the MCP tool to get the current address in the active Ghidra tool.", mcpName = "get_current_address", mcpDescription = "Retrieve the memory address currently indicated by the cursor in the active Ghidra Code Browser window associated with the specified program.")
public class GhidraGetCurrentAddressTool implements IGhidraMcpSpecification {
	public GhidraGetCurrentAddressTool() {
	}

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

			return createSuccessResult(location.getAddress().toString());

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}