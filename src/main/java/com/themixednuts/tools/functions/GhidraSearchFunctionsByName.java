package com.themixednuts.tools.functions;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraFunctionsToolInfo;

import ghidra.framework.model.Project;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Search Functions by Name", category = "Functions", description = "Enable the MCP tool to search for functions by name.", mcpName = "search_function_by_name", mcpDescription = "Search for functions whose names contain the provided search term (case-insensitive) and return a list of matching functions with details.")
public class GhidraSearchFunctionsByName implements IGhidraMcpSpecification {
	public GhidraSearchFunctionsByName() {
	}

	@Override
	public AsyncToolSpecification specification(Project project) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		Optional<String> schemaJson = schema();
		if (schemaJson.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null; // Signal failure
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson.get()),
				(ex, args) -> {
					return getProgram(args, project).flatMap(program -> {
						String searchTerm = getRequiredStringArgument(args, "searchTerm");
						List<GhidraFunctionsToolInfo> functions = StreamSupport
								.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
								.filter(f -> f.getName().toLowerCase().contains(searchTerm.toLowerCase()))
								.map(GhidraFunctionsToolInfo::new)
								.collect(Collectors.toList());

						if (functions.isEmpty()) {
							return Mono.just(new CallToolResult("No functions found", true));
						} else {
							try {
								return Mono.just(new CallToolResult(
										IGhidraMcpSpecification.mapper.writeValueAsString(functions), false));
							} catch (JsonProcessingException e) {
								Msg.error(this, "Error serializing function info to JSON", e);
								return Mono.just(new CallToolResult("Error serializing function info to JSON", true));
							}
						}

					}).onErrorResume(e -> {
						Msg.error(this, e.getMessage());
						return Mono.just(new CallToolResult(e.getMessage(), true));
					});
				});
	}

	@Override
	public Optional<String> schema() {
		try {
			ObjectNode schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
			ObjectNode properties = schemaRoot.putObject("properties");

			ObjectNode fileNameProp = properties.putObject("fileName");
			fileNameProp.put("type", "string");
			fileNameProp.put("description", "The file name of the Ghidra tool window to target.");

			ObjectNode searchTermProp = properties.putObject("searchTerm");
			searchTermProp.put("type", "string");
			searchTermProp.put("description", "The search term to find function names containing it.");

			schemaRoot.putArray("required").add("fileName").add("searchTerm");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for search_function_by_name tool", e);
			return Optional.empty();
		}
	}

}
