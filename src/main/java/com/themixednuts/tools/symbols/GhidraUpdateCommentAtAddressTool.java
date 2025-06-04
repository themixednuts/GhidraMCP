package com.themixednuts.tools.symbols;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Comment at Address", category = ToolCategory.SYMBOLS, description = "Sets or replaces a comment of a specific type at a given memory address.", mcpName = "update_comment_at_address", mcpDescription = "Set or update a comment at a specific address. Choose from EOL, PRE, POST, PLATE, or REPEATABLE comment types.")
public class GhidraUpdateCommentAtAddressTool implements IGhidraMcpSpecification {

	public static final String ARG_COMMENT_TYPE = "commentType";

	private static record UpdateCommentContext(
			Program program,
			Address address,
			int commentType,
			String commentToSet) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address where the comment should be set (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_COMMENT_TYPE,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The type of comment to set (e.g., 'EOL_COMMENT', 'PRE_COMMENT', 'POST_COMMENT', 'PLATE_COMMENT', 'REPEATABLE_COMMENT').")
						.enumValues("EOL_COMMENT", "PRE_COMMENT", "POST_COMMENT", "PLATE_COMMENT", "REPEATABLE_COMMENT"));

		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("The text content of the comment to set. Use null or empty string to clear."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_COMMENT_TYPE)
				.requiredProperty(ARG_COMMENT);

		return schemaRoot.build();
	}

	private int getCommentTypeInt(String commentTypeStr) {
		switch (commentTypeStr) {
			case "EOL_COMMENT":
				return CodeUnit.EOL_COMMENT;
			case "PRE_COMMENT":
				return CodeUnit.PRE_COMMENT;
			case "POST_COMMENT":
				return CodeUnit.POST_COMMENT;
			case "PLATE_COMMENT":
				return CodeUnit.PLATE_COMMENT;
			case "REPEATABLE_COMMENT":
				return CodeUnit.REPEATABLE_COMMENT;
			default:
				throw new IllegalArgumentException("Invalid comment type: " + commentTypeStr);
		}
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				throw new IllegalArgumentException("Invalid address format: " + addressStr);
			}

			String comment = getRequiredStringArgument(args, ARG_COMMENT);
			String commentTypeStr = getRequiredStringArgument(args, ARG_COMMENT_TYPE);
			int commentTypeInt;
			try {
				commentTypeInt = getCommentTypeInt(commentTypeStr);
			} catch (IllegalArgumentException e) {
				throw e;
			}
			String commentToSet = (comment == null || comment.isEmpty()) ? null : comment;

			return new UpdateCommentContext(program, addr, commentTypeInt, commentToSet);

		}).flatMap(context -> {
			return executeInTransaction(context.program(), "MCP - Set Comment at " + context.address().toString(), () -> {
				SetCommentCmd cmd = new SetCommentCmd(context.address(), context.commentType(), context.commentToSet());
				if (cmd.applyTo(context.program())) {
					return "Comment set successfully at " + context.address().toString();
				} else {
					throw new RuntimeException("Failed to set comment: " + cmd.getStatusMsg());
				}
			});
		});
	}

}
