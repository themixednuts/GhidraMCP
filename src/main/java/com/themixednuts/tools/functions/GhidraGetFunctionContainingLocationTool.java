package com.themixednuts.tools.functions;

import java.util.Map;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;
import com.themixednuts.tools.ToolCategory;
import ghidra.program.model.listing.FunctionManager;

@GhidraMcpTool(name = "Get Function Containing Location", category = ToolCategory.FUNCTIONS, description = "Gets the function that contains a specific memory address.", mcpName = "get_function_containing_location", mcpDescription = "Finds and returns the function containing the given address.")
public class GhidraGetFunctionContainingLocationTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address contained within the desired function (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressString = getRequiredStringArgument(args, ARG_ADDRESS);
			Address locationAddress = program.getAddressFactory().getAddress(addressString);

			if (locationAddress == null) {
				throw new IllegalArgumentException("Invalid address format: " + addressString);
			}

			FunctionManager functionManager = program.getFunctionManager();
			Function function = functionManager.getFunctionContaining(locationAddress);

			if (function == null) {
				throw new IllegalArgumentException("No function found containing address: " + addressString);
			}

			return new FunctionInfo(function);
		});
	}
}
