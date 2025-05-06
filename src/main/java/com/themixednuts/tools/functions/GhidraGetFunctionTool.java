package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(name = "Get Function", category = ToolCategory.FUNCTIONS, description = "Gets details about a function specified either by its name or entry point address.", mcpName = "get_function", mcpDescription = "Retrieves details of a function using its name or entry point address.")
public class GhidraGetFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function. Either this or address must be provided."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional entry point address of the function (e.g., '0x1004010'). Preferred over name if provided.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
			Optional<String> nameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

			if (addressOpt.isEmpty() && nameOpt.isEmpty()) {
				throw new IllegalArgumentException("Either function address ('" + ARG_ADDRESS + "') or function name ('"
						+ ARG_FUNCTION_NAME + "') must be provided.");
			}

			Function functionToReturn = null;
			FunctionManager functionManager = program.getFunctionManager();
			String identifier = "";

			if (addressOpt.isPresent()) {
				String addressString = addressOpt.get();
				identifier = addressString;
				Address entryPointAddress = program.getAddressFactory().getAddress(addressString);
				if (entryPointAddress != null) {
					functionToReturn = functionManager.getFunctionAt(entryPointAddress);
				} else {
					if (nameOpt.isEmpty()) {
						throw new IllegalArgumentException("Invalid address format: " + addressString);
					}
				}
			}

			if (functionToReturn == null && nameOpt.isPresent()) {
				String functionName = nameOpt.get();
				identifier = functionName;
				functionToReturn = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
						.filter(f -> f.getName(true).equals(functionName))
						.findFirst()
						.orElse(null);
			}

			if (functionToReturn == null) {
				throw new IllegalArgumentException("Function not found using identifier: " + identifier);
			}

			return new FunctionInfo(functionToReturn);
		});
	}

}