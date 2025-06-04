package com.themixednuts.tools.symbols;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Undefine Code Unit at Address", category = ToolCategory.SYMBOLS, description = "Clears the definition (instruction or data) at a specific address.", mcpName = "undefine_at_address", mcpDescription = "Clear the code unit definition at an address. Removes instruction or data definitions, returning the area to undefined bytes.")
public class GhidraUndefineAtAddressTool implements IGhidraMcpSpecification {

	private static record UndefineContext(
			Program program,
			Address address) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address where the code unit definition should be cleared (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			final String toolMcpName = getMcpName();

			Address targetAddress;
			try {
				targetAddress = program.getAddressFactory().getAddress(addressStr);
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

			if (targetAddress == null) {
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

			return new UndefineContext(program, targetAddress);

		}).flatMap(context -> {
			Listing listing = context.program().getListing();

			return executeInTransaction(context.program(), "MCP - Undefine at " + context.address(), () -> {
				listing.clearCodeUnits(context.address(), context.address(), false);
				return "Successfully cleared code unit definition at address " + context.address().toString();
			});
		});
	}
}