package com.themixednuts.tools.symbols;

import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Rename Data at Address", category = "Symbols", description = "Enable the MCP tool to rename data at a specific address.", mcpName = "rename_data_at_address", mcpDescription = "Assign or change the symbolic label (name) for the data item located at the specified memory address.")
public class GhidraRenameDataAtAddressTool implements IGhidraMcpSpecification {
	public GhidraRenameDataAtAddressTool() {
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
						Data data = program.getListing().getDefinedDataAt(addr);
						if (data == null) {
							return Mono.just(new CallToolResult("Data not found at address: " + addressStr, true));
						}
						String newName = getRequiredStringArgument(args, "newName");

						CallToolResult result = executeInTransaction(program, "Rename data", () -> {
							program.getSymbolTable().createLabel(addr, newName, SourceType.USER_DEFINED);
							return new CallToolResult("Data renamed successfully.", false);
						});

						if (result == null) {
							Msg.error(this, "Swing.runNow did not return a result for rename_data_at_address");
							return Mono.just(new CallToolResult("Internal error: Swing operation failed to provide result.", true));
						}

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
			schemaRoot.putObject("properties");
			ObjectNode fileNameProp = schemaRoot.putObject("fileName");
			fileNameProp.put("type", "string");
			fileNameProp.put("description", "The file name of the Ghidra tool window to target");
			schemaRoot.putArray("required").add("fileName");
			ObjectNode addressProp = schemaRoot.putObject("address");
			addressProp.put("type", "string");
			addressProp.put("description", "The address of the data to rename");
			schemaRoot.putArray("required").add("address");
			ObjectNode newNameProp = schemaRoot.putObject("newName");
			newNameProp.put("type", "string");
			newNameProp.put("description", "The new name of the data");
			schemaRoot.putArray("required").add("newName").add("address").add("fileName");
			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for rename_data_at_address tool", e);
			return Optional.empty();
		}
	}

}
