package com.themixednuts.tools.symbols;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.framework.plugintool.PluginTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Get Comment at Address", category = ToolCategory.SYMBOLS, description = "Enable the MCP tool to get a comment at a specific address.", mcpName = "get_comment_at_address", mcpDescription = "Retrieve the comment text for a specific comment type (e.g., EOL_COMMENT, PRE_COMMENT) at the given memory address.")
public class GhidraGetCommentAtAddressTool implements IGhidraMcpSpecification {
	private static final String ARG_COMMENT_TYPE = "commentType";

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
		schemaRoot.property(ARG_COMMENT_TYPE,
				JsonSchemaBuilder.string(mapper)
						.description("The type of comment to retrieve (e.g., EOL_COMMENT, PRE_COMMENT). Optional, defaults to all.")
						.enumValues("EOL_COMMENT", "PRE_COMMENT", "POST_COMMENT", "PLATE_COMMENT", "REPEATABLE_COMMENT"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_COMMENT_TYPE);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				throw new IllegalArgumentException("Invalid address provided: " + addressStr);
			}
			String commentTypeStr = getRequiredStringArgument(args, ARG_COMMENT_TYPE);

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
					throw new IllegalArgumentException("Invalid comment type provided: " + commentTypeStr);
			}

			String comment = program.getListing().getComment(commentTypeInt, addr);
			return (Object) (comment != null ? comment : "");
		});
	}

}
