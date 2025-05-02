package com.themixednuts.tools.symbols;

import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;

import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.Msg;

@GhidraMcpTool(key = "Get Comment at Address", category = "Symbols", description = "Enable the MCP tool to get a comment at a specific address.", mcpName = "get_comment_at_address", mcpDescription = "Retrieve the comment text for a specific comment type (e.g., EOL_COMMENT, PRE_COMMENT) at the given memory address.")
public class GhidraGetCommentAtAddressTool implements IGhidraMcpSpecification {
	public GhidraGetCommentAtAddressTool() {
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
						String commentType = getRequiredStringArgument(args, "commentType");

						int codeUnit;
						switch (commentType) {
							case "PRE_COMMENT":
								codeUnit = CodeUnit.PRE_COMMENT;
								break;
							case "EOL_COMMENT":
								codeUnit = CodeUnit.EOL_COMMENT;
								break;
							case "POST_COMMENT":
								codeUnit = CodeUnit.POST_COMMENT;
								break;
							case "PLATE_COMMENT":
								codeUnit = CodeUnit.PLATE_COMMENT;
								break;
							case "REPEATABLE_COMMENT":
								codeUnit = CodeUnit.REPEATABLE_COMMENT;
								break;
							default:
								throw new IllegalArgumentException("Invalid comment type: " + commentType);
						}

						String comment = program.getListing().getComment(codeUnit, addr);
						return Mono.just(new CallToolResult(comment, false));
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
			addressProp.put("description", "The address of the function to get the comment for");

			ObjectNode commentTypeProp = properties.putObject("commentType");
			commentTypeProp.put("type", "string");
			commentTypeProp.put("description",
					"The type of comment to get. Valid values are 'PRE_COMMENT' (before code unit), 'EOL_COMMENT' (end of line), 'POST_COMMENT' (after code unit), 'PLATE_COMMENT' (above function), 'REPEATABLE_COMMENT' (associated with specific lines).");

			ArrayNode commentTypeEnum = commentTypeProp.putArray("enum");
			commentTypeEnum.add("PRE_COMMENT");
			commentTypeEnum.add("EOL_COMMENT");
			commentTypeEnum.add("POST_COMMENT");
			commentTypeEnum.add("PLATE_COMMENT");
			commentTypeEnum.add("REPEATABLE_COMMENT");

			schemaRoot.putArray("required").add("fileName").add("address").add("commentType");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for get_comment_at_address tool", e);
			return Optional.empty();
		}

	}

}
