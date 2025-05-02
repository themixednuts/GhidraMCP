package com.themixednuts.tools.projectmanagement;

import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.util.Msg;

import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "List Files", category = "Project Management", description = "Enable the MCP tool to list project files.", mcpName = "list_open_programs", mcpDescription = "List the file names of all currently open programs within the active Ghidra project.")
public class GhidraListFilesTool implements IGhidraMcpSpecification {
	// Removed project field
	// private final Project project;

	// Added public no-arg constructor (required by ServiceLoader when using
	// provider.get())
	public GhidraListFilesTool() {
	}

	// Removed constructor accepting Project
	// public GhidraListFilesTool(Project project) {
	// this.project = project;
	// }

	@Override
	// Updated signature to accept Project
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
					// Use the project parameter directly
					if (project == null) {
						return Mono.just(new CallToolResult("Error: Ghidra Project is not available.", true));
					}
					List<DomainFile> domainFiles = project.getOpenData();
					String fileNames = String.join("\n", domainFiles.stream().map(DomainFile::getName).toArray(String[]::new));
					return Mono.just(new CallToolResult(fileNames.isEmpty() ? "No programs currently open." : fileNames, false));
				});
	}

	@Override
	public Optional<String> schema() {
		try {
			ObjectNode schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
			ObjectNode properties = schemaRoot.putObject("properties");

			// Define properties... (if any, this one might have none besides base)
			ObjectNode dummyProp = properties.putObject("random_string");
			dummyProp.put("type", "string");
			dummyProp.put("description", "Dummy parameter for no-parameter tools");

			// Define required fields (if any)
			// schemaRoot.putArray("required"); // No required fields for this tool

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for list_open_programs tool", e);
			return Optional.empty();
		}
	}
}
