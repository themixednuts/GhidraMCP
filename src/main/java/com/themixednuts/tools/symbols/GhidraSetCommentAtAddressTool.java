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

@GhidraMcpTool(key = "Set Comment at Address", category = "Symbols", description = "Enable the MCP tool to set a comment at a specific address.", mcpName = "set_comment_at_address", mcpDescription = "Set or replace a comment of a specific type (e.g., EOL_COMMENT, PRE_COMMENT, PLATE_COMMENT) at the given memory address.")
public class GhidraSetCommentAtAddressTool implements IGhidraMcpSpecification {

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
			return null; // Signal failure
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file to target within the project."));
		schemaRoot.property("address",
				JsonSchemaBuilder.string(mapper)
						.description("The address where the comment should be set (e.g., '0x1004010')."));
		schemaRoot.property("commentType",
				JsonSchemaBuilder.string(mapper) // This returns IStringSchemaBuilder
						.description(
								"The type of comment to set (e.g., 'EOL_COMMENT', 'PRE_COMMENT', 'POST_COMMENT', 'PLATE_COMMENT', 'REPEATABLE_COMMENT').")
						.enumValues("EOL_COMMENT", "PRE_COMMENT", "POST_COMMENT", "PLATE_COMMENT", "REPEATABLE_COMMENT"));

		schemaRoot.property("comment",
				JsonSchemaBuilder.string(mapper)
						.description("The text content of the comment to set."));
		// Add optional properties
		schemaRoot.property("functionName",
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional name of the function containing the address. If provided, the address is relative to the function's entry point."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("address")
				.requiredProperty("commentType")
				.requiredProperty("comment");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// --- Setup Phase --- (Argument parsing, address validation, comment type
			// validation)
			String addressStr = getRequiredStringArgument(args, "address");
			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				return createErrorResult("Invalid address format: " + addressStr);
			}

			String comment = getRequiredStringArgument(args, "comment");
			String commentTypeStr = getRequiredStringArgument(args, "commentType");

			int commentTypeInt;
			switch (commentTypeStr) {
				case "EOL_COMMENT":
					commentTypeInt = CodeUnit.EOL_COMMENT;
					break;
				case "PRE_COMMENT":
					commentTypeInt = CodeUnit.PRE_COMMENT;
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
					return createErrorResult("Invalid comment type: " + commentTypeStr);
			}

			// --- Modification Phase --- (Execute within transaction)
			return executeInTransaction(program, "MCP - Set Comment at " + addressStr, () -> {
				// Modification
				program.getListing().setComment(addr, commentTypeInt, comment);
				// Return success
				return createSuccessResult("Comment set successfully at " + addressStr + ".");
			});

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup, or unexpected transaction errors
			return createErrorResult(e);
		});
	}

}
