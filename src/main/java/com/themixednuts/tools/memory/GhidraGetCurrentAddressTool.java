package com.themixednuts.tools.memory;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Current Address", category = ToolCategory.MEMORY, description = "Gets the current cursor address in the specified program window.", mcpName = "get_current_address", mcpDescription = "Returns the memory address currently indicated by the cursor in the Ghidra listing view.")
public class GhidraGetCurrentAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return Mono.fromCallable(() -> {
			CodeViewerService service = tool.getService(CodeViewerService.class);
			if (service == null) {
				throw new IllegalStateException("CodeViewerService not available in the current tool.");
			}

			ProgramLocation currentLocation = service.getCurrentLocation();
			if (currentLocation == null || currentLocation.getAddress() == null) {
				return null; // Return empty Mono if no location
			}
			return currentLocation.getAddress().toString();
		});
	}
}