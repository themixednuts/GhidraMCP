package com.themixednuts.tools.functions;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import reactor.core.publisher.Mono;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import com.themixednuts.tools.ToolCategory;
import ghidra.app.services.GoToService;
import ghidra.app.nav.Navigatable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionManager;

@GhidraMcpTool(name = "Get Current Function", category = ToolCategory.FUNCTIONS, description = "Gets details about the function containing the current cursor location.", mcpName = "get_current_function", mcpDescription = "Returns details of the function at the current cursor location in the active Ghidra listing.")
public class GhidraGetCurrentFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return Mono.fromCallable(() -> {
			GoToService goToService = tool.getService(GoToService.class);
			if (goToService == null) {
				throw new IllegalStateException("GoToService not available");
			}
			Navigatable navigatable = goToService.getDefaultNavigatable();
			if (navigatable == null) {
				throw new IllegalStateException("Default Navigatable not available");
			}

			ProgramLocation location = navigatable.getLocation();
			if (location == null) {
				throw new IllegalStateException("Current location not available");
			}

			Program program = location.getProgram();
			if (program == null) {
				throw new IllegalStateException("Current program context not available from location");
			}

			FunctionManager functionManager = program.getFunctionManager();
			Function function = functionManager.getFunctionContaining(location.getAddress());

			if (function == null) {
				return null;
			}

			return new FunctionInfo(function);
		});
	}
}