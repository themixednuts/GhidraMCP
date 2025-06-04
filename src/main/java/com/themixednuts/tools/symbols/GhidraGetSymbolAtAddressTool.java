package com.themixednuts.tools.symbols;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.SymbolInfo; // Use the existing POJO
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Symbol at Address", category = ToolCategory.SYMBOLS, description = "Retrieves details of symbols at a specific memory address.", mcpName = "get_symbol_at_address", mcpDescription = "Get all symbols at a specific address. Returns symbol details including name, type, and namespace information.")
public class GhidraGetSymbolAtAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address to retrieve symbol information from (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
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

					SymbolTable symbolTable = program.getSymbolTable();
					Symbol[] symbols = symbolTable.getSymbols(targetAddress);

					if (symbols.length == 0) {
						return List.<SymbolInfo>of();
					}

					List<SymbolInfo> symbolResults = Arrays.stream(symbols)
							.map(SymbolInfo::new)
							.collect(Collectors.toList());

					return symbolResults;
				});
	}
}