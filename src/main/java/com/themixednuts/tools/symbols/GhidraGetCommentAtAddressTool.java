package com.themixednuts.tools.symbols;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.Msg;
import ghidra.framework.plugintool.PluginTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(key = "Get Comment at Address", category = ToolCategory.SYMBOLS, description = "Enable the MCP tool to get a comment at a specific address.", mcpName = "get_comment_at_address", mcpDescription = "Retrieve the comment text for a specific comment type (e.g., EOL_COMMENT, PRE_COMMENT) at the given memory address.")
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

		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address to retrieve the comment from (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property("commentType",
				JsonSchemaBuilder.string(mapper)
						.description("The type of comment to retrieve (e.g., EOL_COMMENT, PRE_COMMENT). Optional, defaults to all.")
						.enumValues("EOL_COMMENT", "PRE_COMMENT", "POST_COMMENT", "PLATE_COMMENT", "REPEATABLE_COMMENT"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty("commentType");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
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
