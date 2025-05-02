package com.themixednuts.tools.functions;

import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get Function Containing Location", category = "Functions", description = "Enable the MCP tool to get the function containing a given location.", mcpName = "get_function_containing_location", mcpDescription = "Identify and return details of the function that encompasses the specified memory address.")
public class GhidraGetFunctionContainingLocationTool implements IGhidraMcpSpecification {
	public GhidraGetFunctionContainingLocationTool() {
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
						Function func = program.getFunctionManager().getFunctionContaining(addr);
						if (func == null) {
							return Mono.just(new CallToolResult("No function at current location: " + addressStr, true));
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

			ObjectNode addressProp = properties.putObject("address");
			addressProp.put("type", "string");
			addressProp.put("description", "The address to get the function containing");

			schemaRoot.putArray("required").add("fileName").add("address");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Failed to generate schema for get_current_function tool. Tool will be disabled.");
			return Optional.empty();
		}
	}
}
