package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import reactor.core.publisher.Mono;

import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(key = "Get Current Function", category = ToolCategory.FUNCTIONS, description = "Gets details about the function containing the current cursor location.", mcpName = "get_current_function", mcpDescription = "Returns details of the function at the current cursor location in the active Ghidra listing.")
public class GhidraGetCurrentFunctionTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		Optional<String> schemaStringOpt = parseSchema(schema());
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
		schemaRoot.requiredProperty(IGhidraMcpSpecification.ARG_FILE_NAME);
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

			FunctionInfo functionInfo = new FunctionInfo(func);
			return createSuccessResult(functionInfo);

		}).onErrorResume(e -> createErrorResult(e));
	}
}