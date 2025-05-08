package com.themixednuts.tools.projectmanagement;

import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;

import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "List Open Files", category = ToolCategory.PROJECT_MANAGEMENT, description = "Lists all currently open files in the Ghidra project.", mcpName = "list_open_files", mcpDescription = "Provides a list of names of all files currently open in the project.")
public class GhidraListOpenFilesTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		return IGhidraMcpSpecification.createBaseSchemaNode().build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {

		return Mono.fromCallable(() -> {
			ghidra.framework.model.Project project = tool.getProject();
			if (project == null) {
				throw new IllegalStateException("Ghidra Project is not available.");
			}

			return project.getOpenData()
					.stream()
					.map(DomainFile::getName)
					.sorted()
					.collect(Collectors.toList());
		});
	}
}
