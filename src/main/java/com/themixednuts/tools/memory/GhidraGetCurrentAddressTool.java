package com.themixednuts.tools.memory;

import java.util.Arrays;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;

@GhidraMcpTool(key = "Get Current Address", category = "Memory", description = "Enable the MCP tool to get the current address in the active Ghidra tool.", mcpName = "get_current_address", mcpDescription = "Retrieve the memory address currently indicated by the cursor in the active Ghidra Code Browser window associated with the specified program.")
public class GhidraGetCurrentAddressTool implements IGhidraMcpSpecification {
	public GhidraGetCurrentAddressTool() {
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
						PluginTool tool = Arrays.stream(project.getToolManager().getRunningTools())
								.filter(t -> {
									ProgramManager pm = t.getService(ProgramManager.class);
									return pm != null && pm.getCurrentProgram() == program;
								})
								.findFirst()
								.orElse(null);

						if (tool == null) {
							return Mono
									.just(new CallToolResult("Could not find running tool for program: " + program.getName(), true));
						}
						CodeViewerService service = tool.getService(CodeViewerService.class);
						if (service == null) {
							return Mono.just(new CallToolResult("Code viewer service not available", true));
						}

						ProgramLocation location = service.getCurrentLocation();
						if (location == null) {
							return Mono.just(new CallToolResult("No current location", true));
						}

						return Mono.just(new CallToolResult(location.getAddress().toString(), false));
					});
				}

		);
	}

	@Override
	public Optional<String> schema() {
		try {
			ObjectNode schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
			ObjectNode properties = schemaRoot.putObject("properties");

			ObjectNode fileNameProp = properties.putObject("fileName");
			fileNameProp.put("type", "string");
			fileNameProp.put("description", "The name of the Ghidra tool window to target");

			schemaRoot.putArray("required").add("fileName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));

		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for get_current_address tool", e);
			return Optional.empty();
		}
	}

}