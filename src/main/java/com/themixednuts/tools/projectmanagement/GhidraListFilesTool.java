package com.themixednuts.tools.projectmanagement;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(key = "List Files", category = ToolCategory.PROJECT_MANAGEMENT, description = "Lists the files currently open in the Ghidra project.", mcpName = "list_open_files", mcpDescription = "Returns a list of files currently open in the Ghidra project.")
public class GhidraListFilesTool implements IGhidraMcpSpecification {
	public GhidraListFilesTool() {
	}

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
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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
		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return Mono.fromCallable(() -> {
			ghidra.framework.model.Project project = tool.getProject();
			if (project == null) {
				return createErrorResult("Internal Error: Ghidra Project became unavailable unexpectedly.");
			}

			return project.getOpenData()
					.stream()
					.map(DomainFile::getName)
					.sorted()
					.collect(Collectors.toList());

		}).flatMap(files -> createSuccessResult(files)).onErrorResume(e -> createErrorResult(e));
	}
}
