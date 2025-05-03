package com.themixednuts.tools.symbols;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.Msg;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Get Comment at Address", category = "Symbols", description = "Enable the MCP tool to get a comment at a specific address.", mcpName = "get_comment_at_address", mcpDescription = "Retrieve the comment text for a specific comment type (e.g., EOL_COMMENT, PRE_COMMENT) at the given memory address.")
public class GhidraGetCommentAtAddressTool implements IGhidraMcpSpecification {
	public GhidraGetCommentAtAddressTool() {
	}

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schema),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public ObjectNode schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("address",
				JsonSchemaBuilder.string(mapper)
						.description("The address to get comments from (e.g., '0x1004010')."));
		schemaRoot.property("commentType",
				JsonSchemaBuilder.string(mapper)
						.description("The type of comment to retrieve.")
						.enumValues("EOL_COMMENT", "PRE_COMMENT", "POST_COMMENT", "PLATE_COMMENT", "REPEATABLE_COMMENT"));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("address")
				.requiredProperty("commentType");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String addressStr = getRequiredStringArgument(args, "address");
			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				return createErrorResult("Invalid address provided: " + addressStr);
			}
			String commentTypeStr = getRequiredStringArgument(args, "commentType");

			int commentTypeInt;
			switch (commentTypeStr) {
				case "PRE_COMMENT":
					commentTypeInt = CodeUnit.PRE_COMMENT;
					break;
				case "EOL_COMMENT":
					commentTypeInt = CodeUnit.EOL_COMMENT;
					break;
				case "POST_COMMENT":
					commentTypeInt = CodeUnit.POST_COMMENT;
					break;
				case "PLATE_COMMENT":
					commentTypeInt = CodeUnit.PLATE_COMMENT;
					break;
				case "REPEATABLE_COMMENT":
					commentTypeInt = CodeUnit.REPEATABLE_COMMENT;
					break;
				default:
					return createErrorResult("Invalid comment type provided: " + commentTypeStr);
			}

			String comment = program.getListing().getComment(commentTypeInt, addr);
			return createSuccessResult(comment != null ? comment : "");
		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}

}
