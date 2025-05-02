package com.themixednuts.tools.memory;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get XRefs From", category = "Memory", description = "Enable the MCP tool to get the xrefs from a specific address.", mcpName = "get_x_refs_from", mcpDescription = "Retrieve a list of all cross-references (XRefs) originating *from* the specified memory address, showing where this address calls or references other locations.")
public class GhidraGetXRefsFromTool implements IGhidraMcpSpecification {
	public GhidraGetXRefsFromTool() {
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
						ReferenceManager refManager = program.getReferenceManager();
						Reference[] refIter = refManager.getReferencesFrom(addr);

						List<ObjectNode> refs = Arrays.stream(refIter)
								.map(ref -> {
									ObjectNode refNode = IGhidraMcpSpecification.mapper.createObjectNode();
									refNode.put("fromAddress", ref.getFromAddress().toString());
									refNode.put("toAddress", ref.getToAddress().toString());
									refNode.put("type", ref.getReferenceType().getName());
									return refNode;
								})
								.collect(Collectors.toList());

						try {
							return Mono.just(new CallToolResult(
									IGhidraMcpSpecification.mapper.writeValueAsString(refs), false));
						} catch (JsonProcessingException e) {
							Msg.error(this, "Error serializing xrefs to JSON", e);
							return Mono.just(new CallToolResult("Error serializing xrefs to JSON", true));
						}
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
			addressProp.put("description", "The address to find references from.");

			schemaRoot.putArray("required").add("fileName").add("address");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for get_xrefs_from tool", e);
			return Optional.empty();
		}
	}

}
