package com.themixednuts.tools.datatypes;

import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.framework.model.Project;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Add Struct Member", category = "Data Types", description = "Enable the MCP tool to add a member to a struct.", mcpName = "add_struct_member", mcpDescription = "Add a new member field to an existing struct data type. Specify the struct, member name, member type, and optionally offset, size, and comment.")
public class GhidraAddStructMemeberTool implements IGhidraMcpSpecification {
	public GhidraAddStructMemeberTool() {
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

						CallToolResult result = executeInTransaction(program, "Add Struct Member (MCP)", () -> {
							// Required arguments
							String structPath = getRequiredStringArgument(args, "structPath");
							String memberName = getRequiredStringArgument(args, "memberName");
							String memberTypePath = getRequiredStringArgument(args, "memberTypePath");

							// Optional arguments
							Integer offset = getOptionalIntArgument(args, "offset").orElse(null);
							Integer memberSize = getOptionalIntArgument(args, "memberSize").orElse(null);
							String comment = getOptionalStringArgument(args, "comment").orElse(null);

							ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

							// Find the target structure
							DataType targetDt = dtm.getDataType(structPath);
							if (targetDt == null) {
								throw new IllegalArgumentException("Structure not found: " + structPath);
							}
							if (!(targetDt instanceof Structure)) {
								throw new IllegalArgumentException("Data type is not a structure: " + structPath);
							}
							Structure struct = (Structure) targetDt;

							// Find the data type for the new member using the DTM.
							DataType memberDt = dtm.getDataType(memberTypePath);
							if (memberDt == null) {
								throw new IllegalArgumentException("Member data type not found: " + memberTypePath);
							}

							// Determine member size
							int resolvedSize = (memberSize != null && memberSize > 0) ? memberSize : memberDt.getLength();
							if (resolvedSize <= 0) {
								throw new IllegalArgumentException("Could not determine a positive size for member type: "
										+ memberTypePath + ". Specify 'memberSize' explicitly.");
							}

							// Add or insert the member
							if (offset != null) {
								struct.insert(offset, memberDt, resolvedSize, memberName, comment);
							} else {
								struct.add(memberDt, resolvedSize, memberName, comment);
							}

							return new CallToolResult("Successfully added member '" + memberName + "' to " + structPath, false);

						});

						if (result == null) {
							Msg.error(this, "Swing.runNow did not return a result for add_struct_member");
							return Mono.just(new CallToolResult("Internal error: Swing operation failed to provide result.", true));
						}

						return Mono.just(result);

					}).onErrorResume(e -> {
						Msg.error(this, "Error during tool execution (getProgram or Swing.runNow): " + e.getMessage(), e);
						return Mono.just(new CallToolResult("Execution Error: " + e.getMessage(), true));
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

			ObjectNode structPathProp = properties.putObject("structPath");
			structPathProp.put("type", "string");
			structPathProp.put("description", "The full path of the struct data type (e.g., /Category/StructName).");

			ObjectNode memberNameProp = properties.putObject("memberName");
			memberNameProp.put("type", "string");
			memberNameProp.put("description", "The name for the new member.");

			ObjectNode memberTypePathProp = properties.putObject("memberTypePath");
			memberTypePathProp.put("type", "string");
			memberTypePathProp.put("description",
					"The full path or name of the member's data type (e.g., /Category/TypeName, or built-in like 'int', 'char*').");

			ObjectNode offsetProp = properties.putObject("offset");
			offsetProp.put("type", "integer");
			offsetProp.put("description",
					"Optional offset within the struct to insert the member. If omitted, adds to the end.");

			ObjectNode memberSizeProp = properties.putObject("memberSize");
			memberSizeProp.put("type", "integer");
			memberSizeProp.put("description",
					"Optional explicit size for the member. If omitted, the default size of the member type is used.");

			ObjectNode commentProp = properties.putObject("comment");
			commentProp.put("type", "string");
			commentProp.put("description", "Optional comment for the new member.");

			// Define required fields
			schemaRoot.putArray("required")
					.add("fileName")
					.add("structPath")
					.add("memberName")
					.add("memberTypePath");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for add_struct_member tool", e);
			return Optional.empty();
		}
	}

}
