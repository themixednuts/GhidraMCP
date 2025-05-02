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

@GhidraMcpTool(key = "Set Comment at Address", category = "Symbols", description = "Enable the MCP tool to set a comment at a specific address.", mcpName = "set_comment_at_address", mcpDescription = "Set or replace a comment of a specific type (e.g., EOL_COMMENT, PRE_COMMENT, PLATE_COMMENT) at the given memory address.")
public class GhidraSetCommentAtAddressTool implements IGhidraMcpSpecification {
	public GhidraSetCommentAtAddressTool() {
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
						String comment = getRequiredStringArgument(args, "comment");
						String commentType = getRequiredStringArgument(args, "commentType");

						CallToolResult result = executeInTransaction(program, "Set Decompiler Comment: " + addr.toString(), () -> {

							int codeUnit;
							switch (commentType) {
								case "EOL_COMMENT":
									codeUnit = CodeUnit.EOL_COMMENT;
									break;
								case "PRE_COMMENT":
									codeUnit = CodeUnit.PRE_COMMENT;
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

							program.getListing().setComment(addr, codeUnit, comment);
							return new CallToolResult("Decompiler comment set successfully.", false);
						});

						if (result == null) {
							Msg.error(this, "Swing.runNow did not return a result for set_decompiler_comment");
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
			ObjectNode properties = schemaRoot.putObject("properties");

			ObjectNode fileNameProp = properties.putObject("fileName");
			fileNameProp.put("type", "string");
			fileNameProp.put("description", "The file name of the Ghidra tool window to target");

			ObjectNode addressProp = properties.putObject("address");
			addressProp.put("type", "string");
			addressProp.put("description", "The address of the function to set the comment for");

			ObjectNode commentProp = properties.putObject("comment");
			commentProp.put("type", "string");
			commentProp.put("description", "The comment to set for the function");

			ObjectNode commentTypeProp = properties.putObject("commentType");
			commentTypeProp.put("type", "string");

			commentTypeProp.put("description",
					"The type of comment to set. Valid values are 'PRE_COMMENT' (before code unit), 'EOL_COMMENT' (end of line), 'POST_COMMENT' (after code unit), 'PLATE_COMMENT' (above function), 'REPEATABLE_COMMENT' (associated with specific lines).");

			ArrayNode commentTypeEnum = commentTypeProp.putArray("enum");
			commentTypeEnum.add("PRE_COMMENT");
			commentTypeEnum.add("EOL_COMMENT");
			commentTypeEnum.add("POST_COMMENT");
			commentTypeEnum.add("PLATE_COMMENT");
			commentTypeEnum.add("REPEATABLE_COMMENT");

			schemaRoot.putArray("required").add("fileName").add("address").add("comment").add("commentType");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for set_decompiler_comment tool", e);
			return Optional.empty();
		}
	}

}
