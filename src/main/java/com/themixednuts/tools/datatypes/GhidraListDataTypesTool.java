package com.themixednuts.tools.datatypes;

import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Comparator;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.framework.model.Project;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "List Data Types", category = "Data Types", description = "Enable the MCP tool to list data types.", mcpName = "list_data_types", mcpDescription = "List all data types (structs, unions, enums, typedefs, pointers, etc.) defined within the specified program, returning detailed information like name, path, category, size, and type flags. Supports pagination.")
public class GhidraListDataTypesTool implements IGhidraMcpSpecification {
	private static final int PAGE_SIZE = 100;

	public GhidraListDataTypesTool() {
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
						ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
						String cursor = getOptionalStringArgument(args, "cursor").orElse(null);

						Iterator<DataType> allDataTypesIterator = dtm.getAllDataTypes();
						Spliterator<DataType> spliterator = Spliterators.spliteratorUnknownSize(
								allDataTypesIterator, Spliterator.ORDERED);

						List<DataType> dataTypes = StreamSupport.stream(spliterator, false)
								.sorted(Comparator.comparing(DataType::getPathName))
								.dropWhile(dataType -> cursor != null && dataType.getPathName().compareTo(cursor) <= 0)
								.limit(PAGE_SIZE + 1)
								.collect(Collectors.toList());

						boolean hasMore = dataTypes.size() > PAGE_SIZE;
						int actualPageSize = Math.min(dataTypes.size(), PAGE_SIZE);
						dataTypes = dataTypes.subList(0, actualPageSize);

						String nextCursor = (hasMore && !dataTypes.isEmpty())
								? dataTypes.get(dataTypes.size() - 1).getPathName()
								: null;

						List<ObjectNode> pageNodes = dataTypes.stream().map(dataType -> {
							ObjectNode dataTypeNode = IGhidraMcpSpecification.mapper.createObjectNode();
							dataTypeNode.put("pathName", dataType.getPathName());
							dataTypeNode.put("name", dataType.getName());
							dataTypeNode.put("displayName", dataType.getDisplayName());
							dataTypeNode.put("description", dataType.getDescription());
							dataTypeNode.put("category", dataType.getCategoryPath().getPath());
							dataTypeNode.put("size", dataType.getLength());
							dataTypeNode.put("alignment", dataType.getAlignment());
							dataTypeNode.put("isStructure", dataType instanceof ghidra.program.model.data.Structure);
							dataTypeNode.put("isUnion", dataType instanceof ghidra.program.model.data.Union);
							dataTypeNode.put("isEnum", dataType instanceof ghidra.program.model.data.Enum);
							dataTypeNode.put("isTypeDef", dataType instanceof ghidra.program.model.data.TypeDef);
							dataTypeNode.put("isPointer", dataType instanceof ghidra.program.model.data.Pointer);

							return dataTypeNode;
						}).collect(Collectors.toList());

						ObjectNode result = IGhidraMcpSpecification.mapper.createObjectNode();
						result.set("dataTypes", IGhidraMcpSpecification.mapper.valueToTree(pageNodes));
						if (nextCursor != null && !nextCursor.isEmpty()) {
							result.put("nextCursor", nextCursor);
						}

						try {
							return Mono.just(new CallToolResult(
									IGhidraMcpSpecification.mapper.writeValueAsString(result),
									false));
						} catch (JsonProcessingException e) {
							Msg.error(this, "Error serializing data types to JSON", e);
							return Mono.just(new CallToolResult("Error serializing data types to JSON", true));
						}

					}).onErrorResume(e -> {
						Msg.error(this, "Error processing list_data_types: " + e.getMessage(), e);
						return Mono.just(new CallToolResult("Error processing request: " + e.getMessage(), true));
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

			schemaRoot.putArray("required").add("fileName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for list_data_types tool", e);
			return Optional.empty();
		}
	}

}
