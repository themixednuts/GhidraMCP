package com.themixednuts.tools.functions;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Function Containing Location", category = ToolCategory.FUNCTIONS, description = "Gets the function that contains a specific memory address.", mcpName = "get_function_containing_location", mcpDescription = "Get the function that contains the specified memory address. Useful for finding which function contains a specific instruction or data reference.")
public class GhidraGetFunctionContainingLocationTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The memory address contained within the desired function.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).map(program -> {
			String addressString = getRequiredStringArgument(args, ARG_ADDRESS);
			Address locationAddress;

			// Handle address parsing with structured error
			try {
				locationAddress = program.getAddressFactory().getAddress(addressString);
				if (locationAddress == null) {
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
							.message("Invalid address format")
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"address parsing",
									args,
									Map.of(ARG_ADDRESS, addressString),
									Map.of("expectedFormat", "hexadecimal address", "providedValue", addressString)))
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
			} catch (Exception e) {
				if (e instanceof GhidraMcpException) {
					throw e; // Re-throw our structured error
				}
				// Handle other address parsing exceptions
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
						.message("Failed to parse address: " + e.getMessage())
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"address parsing",
								args,
								Map.of(ARG_ADDRESS, addressString),
								Map.of("parseError", e.getMessage(), "providedValue", addressString)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use valid address format for the current program",
										"Ensure address exists in the program's address space",
										List.of("0x401000", "401000"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Search for containing function
			FunctionManager functionManager = program.getFunctionManager();
			Function function = functionManager.getFunctionContaining(locationAddress);

			if (function == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
						.message("No function found containing the specified address")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"function containing address: " + addressString,
								args,
								Map.of(ARG_ADDRESS, addressString),
								Map.of("addressValid", true, "functionExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify address is within a function",
										"Check if the address falls within any defined function boundaries",
										null,
										null),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
										"Create a function at this location",
										"Use function creation tools if this should be part of a function",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			return new FunctionInfo(function);
		});
	}
}
