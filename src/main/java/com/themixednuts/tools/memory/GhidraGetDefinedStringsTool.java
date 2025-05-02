package com.themixednuts.tools.memory;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get Defined Strings", category = "Memory", description = "Enable the MCP tool to get the defined strings in the project.", mcpName = "get_defined_strings", mcpDescription = "Retrieve a list of defined string data items from the specified program, including their label, address, value, and type. Supports pagination and optional minimum length filtering.")
public class GhidraGetDefinedStringsTool implements IGhidraMcpSpecification {
	private static final int PAGE_SIZE = 100; // Number of strings per page

	public GhidraGetDefinedStringsTool() {
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
						Listing listing = program.getListing();

						Address cursor = getOptionalStringArgument(args, "cursor").map(program.getAddressFactory()::getAddress)
								.orElse(null);

						List<Data> dataNodes = StreamSupport.stream(listing.getDefinedData(true).spliterator(), false)
								.filter(Data::hasStringValue)
								.dropWhile(data -> cursor != null && data.getAddress().compareTo(cursor) <= 0)
								.limit(PAGE_SIZE + 1)
								.collect(Collectors.toList());

						boolean hasMore = dataNodes.size() > PAGE_SIZE;
						dataNodes = dataNodes.subList(0, PAGE_SIZE);

						List<ObjectNode> pageNodes = dataNodes.stream().map(data -> {
							ObjectNode dataNode = IGhidraMcpSpecification.mapper.createObjectNode();
							dataNode.put("label", data.getLabel());
							dataNode.put("address", data.getAddress().toString());
							dataNode.put("value", data.getDefaultValueRepresentation());
							dataNode.put("type", data.getDataType().getDisplayName());
							return dataNode;
						}).collect(Collectors.toList());

						Address nextCursor = hasMore ? dataNodes.stream()
								.map(Data::getAddress)
								.max(Address::compareTo)
								.orElse(null) : null;

						ObjectNode result = IGhidraMcpSpecification.mapper.createObjectNode();
						result.set("strings", IGhidraMcpSpecification.mapper.valueToTree(pageNodes));
						if (nextCursor != null) {
							result.put("nextCursor", nextCursor.toString());
						}

						try {
							return Mono.just(new CallToolResult(IGhidraMcpSpecification.mapper.writeValueAsString(result), false));
						} catch (JsonProcessingException e) {
							Msg.error(this, "Error serializing data nodes to JSON", e);
							return Mono.just(new CallToolResult("Error serializing data nodes to JSON", true));
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

			ObjectNode minLengthProp = properties.putObject("minLength");
			minLengthProp.put("type", "integer");
			minLengthProp.put("description", "Optional minimum length for strings to be included.");

			schemaRoot.putArray("required").add("fileName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for get_defined_strings tool", e);
			return Optional.empty();
		}
	}

}
