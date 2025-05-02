package com.themixednuts.tools.symbols;

import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.framework.model.Project;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "List Namespaces", category = "Symbols", description = "Enable the MCP tool to list namespaces in a file.", mcpName = "list_namespaces", mcpDescription = "List the names of all symbol namespaces (groupings for symbols like classes, functions, etc.) defined within the specified program.")
public class GhidraListNamespacesTool implements IGhidraMcpSpecification {
	public GhidraListNamespacesTool() {
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
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson.get()),
				(ex, args) -> {
					return getProgram(args, project).flatMap(program -> {
						return Mono.just(new CallToolResult(
								String.join("\n",
										StreamSupport.stream(program.getSymbolTable().getAllSymbols(true).spliterator(), false)
												.filter(symbol -> symbol instanceof Namespace)
												.map(symbol -> ((Namespace) symbol).getName())
												.collect(Collectors.toList())),
								false));
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
			fileNameProp.put("description", "The file name of the Ghidra tool window to target");

			schemaRoot.putArray("required").add("fileName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for list_namespaces tool", e);
			return Optional.empty();
		}
	}

}
