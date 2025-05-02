package com.themixednuts.tools.projectmanagement;

import java.util.Arrays;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.functions.GhidraFunctionsToolInfo;

import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;

@GhidraMcpTool(key = "Get Current Function", category = "Project Management", description = "Enable the MCP tool to get the function currently selected in the active Ghidra tool.", mcpName = "get_current_function", mcpDescription = "Retrieve details of the function containing the current cursor location in the active Ghidra Code Browser window for the specified program.")
public class GhidraGetCurrentFunctionTool implements IGhidraMcpSpecification {
	public GhidraGetCurrentFunctionTool() {
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

						Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
						if (func == null) {
							return Mono.just(new CallToolResult("No function at current location: " + location.getAddress(), true));
						}

						try {
							return Mono.just(new CallToolResult(
									IGhidraMcpSpecification.mapper.writeValueAsString(new GhidraFunctionsToolInfo(func)),
									false));
						} catch (JsonProcessingException e) {
							Msg.error(this, "Error serializing function info to JSON", e);
							return Mono.just(new CallToolResult("Error serializing function info to JSON", true));
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
			fileNameProp.put("description", "The name of the Ghidra tool window to target");

			schemaRoot.putArray("required").add("fileName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Failed to generate schema for get_current_function tool. Tool will be disabled.");
			return Optional.empty();
		}
	}

}
