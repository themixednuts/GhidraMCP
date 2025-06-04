package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DataTypeInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Data Type at Address", category = ToolCategory.DATATYPES, description = "Gets the defined data type instance at a specific address.", mcpName = "get_data_type_at_address", mcpDescription = "Get the data type applied at a specific memory address in a Ghidra program. Returns information about the defined data type instance.")
public class GhidraGetDataTypeAtAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address to retrieve the data type from (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					Address targetAddress = program.getAddressFactory().getAddress(addressStr);

					if (targetAddress == null) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
								.message("Invalid address format: " + addressStr)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"address parsing",
										Map.of(ARG_ADDRESS, addressStr),
										Map.of(ARG_ADDRESS, addressStr),
										Map.of("expectedFormat", "hexadecimal address", "providedValue", addressStr)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use valid hexadecimal address format",
												"Provide address as hexadecimal value",
												List.of("0x401000", "401000", "0x00401000"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					Listing listing = program.getListing();
					Data data = listing.getDataAt(targetAddress);

					if (data == null) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
								.message("No defined data starts exactly at this address: " + addressStr)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"data lookup",
										Map.of(ARG_ADDRESS, addressStr),
										Map.of("targetAddress", addressStr),
										Map.of("hasData", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify address contains defined data",
												"Use an address that has a defined data type",
												null,
												List.of(getMcpName(GhidraListDataTypesTool.class))),
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Try a different address",
												"Use an address with defined data",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					DataTypeInfo dataTypeInfo = new DataTypeInfo(data.getDataType());

					return dataTypeInfo;
				});
	}
}