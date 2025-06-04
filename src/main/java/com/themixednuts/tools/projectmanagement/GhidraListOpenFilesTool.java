package com.themixednuts.tools.projectmanagement;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Open Files", category = ToolCategory.PROJECT_MANAGEMENT, description = "Lists all currently open programs in Ghidra.", mcpName = "list_open_files", mcpDescription = "List all currently open program files in the Ghidra project. Returns file details including name, path, version, and modification status.")
public class GhidraListOpenFilesTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		// No required arguments for this tool
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return Mono.fromCallable(() -> {
			try {
				DomainFile[] domainFiles = tool.getProject().getProjectData().getRootFolder().getFiles();
				return Arrays.stream(domainFiles)
						.filter(file -> file.isOpen())
						.map(file -> Map.of(
								"name", file.getName(),
								"path", file.getPathname(),
								"version", file.getVersion(),
								"isChanged", file.isChanged(),
								"isReadOnly", file.isReadOnly()))
						.toList();
			} catch (Exception e) {
				throw new GhidraMcpException(
						GhidraMcpError.execution()
								.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
								.message("Failed to list open files: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										"list_open_files",
										getMcpName(),
										Map.of(),
										Map.of("operation", "list_open_files"),
										Map.of("exception_type", e.getClass().getSimpleName(),
												"exception_message", e.getMessage())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Ensure Ghidra project is properly opened",
												"Verify project state and accessibility",
												null,
												null)))
								.build());
			}
		});
	}
}
