package com.themixednuts.tools.functions;

import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Rename Function by Address", category = "Functions", description = "Enable the MCP tool to rename a function by address.", mcpName = "rename_function_by_address", mcpDescription = "Rename a function, identifying it by its memory address and specifying the desired new name.")
public class GhidraRenameFunctionByAddressTool implements IGhidraMcpSpecification {
	public GhidraRenameFunctionByAddressTool() {
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
						String addressStr = getRequiredStringArgument(args, "address");
						Address addr = program.getAddressFactory().getAddress(addressStr);
						Function function = program.getFunctionManager().getFunctionAt(addr);

						if (function == null) {
							return Mono.just(new CallToolResult("Error: Function not found at address: " + addressStr, true));
						}
						String newName = getRequiredStringArgument(args, "newName");

						CallToolResult result = executeInTransaction(program, "Rename Function: " + function.getName(), () -> {
							function.setName(newName, SourceType.USER_DEFINED);
							return new CallToolResult("Function renamed successfully.", false);
						});

						return Mono.just(result);

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

			ObjectNode addressProp = properties.putObject("address");
			addressProp.put("type", "string");
			addressProp.put("description", "The memory address of the function to rename.");

			ObjectNode newNameProp = properties.putObject("newName");
			newNameProp.put("type", "string");
			newNameProp.put("description", "The new name for the function.");

			schemaRoot.putArray("required").add("fileName").add("address").add("newName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for rename_function_by_address tool", e);
			return Optional.empty();
		}
	}

}
