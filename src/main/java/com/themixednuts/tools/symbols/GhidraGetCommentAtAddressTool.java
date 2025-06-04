package com.themixednuts.tools.symbols;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
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

@GhidraMcpTool(name = "Get Comment at Address", category = ToolCategory.SYMBOLS, description = "Enable the MCP tool to get a comment at a specific address.", mcpName = "get_comment_at_address", mcpDescription = "Get a comment of a specific type at a memory address. Returns the comment text or empty string if none exists.")
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
			String commentTypeStr = getRequiredStringArgument(args, ARG_COMMENT_TYPE);
			final String toolMcpName = getMcpName();

			Address addr;
			try {
				addr = program.getAddressFactory().getAddress(addressStr);
			} catch (Exception e) {
				GhidraMcpError error = GhidraMcpError.execution()
						.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
						.message("Invalid address format: " + addressStr)
						.context(new GhidraMcpError.ErrorContext(
								toolMcpName,
								"address parsing",
								args,
								Map.of(ARG_ADDRESS, addressStr),
								Map.of("parseError", e.getMessage())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use valid address format",
										"Provide address in hexadecimal format",
										List.of("0x401000", "0x00401000", "401000"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			if (addr == null) {
				GhidraMcpError error = GhidraMcpError.execution()
						.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
						.message("Invalid address format: " + addressStr)
						.context(new GhidraMcpError.ErrorContext(
								toolMcpName,
								"address parsing",
								args,
								Map.of(ARG_ADDRESS, addressStr),
								Map.of("addressResult", "null")))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use valid address format",
										"Provide address in hexadecimal format",
										List.of("0x401000", "0x00401000", "401000"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

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
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
							.message("Invalid comment type: " + commentTypeStr)
							.context(new GhidraMcpError.ErrorContext(
									toolMcpName,
									"comment type validation",
									args,
									Map.of(ARG_COMMENT_TYPE, commentTypeStr),
									null))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Use valid comment type",
											"Provide one of the valid comment types",
											List.of("EOL_COMMENT", "PRE_COMMENT", "POST_COMMENT", "PLATE_COMMENT", "REPEATABLE_COMMENT"),
											null)))
							.build();
					throw new GhidraMcpException(error);
			}

			String comment = program.getListing().getComment(commentTypeInt, addr);
			return (Object) (comment != null ? comment : "");
		});
	}

}
