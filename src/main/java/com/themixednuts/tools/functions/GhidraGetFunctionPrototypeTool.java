package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
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

@GhidraMcpTool(name = "Get Function Prototype", category = ToolCategory.FUNCTIONS, description = "Retrieves the full signature string for a function.", mcpName = "get_function_prototype", mcpDescription = "Retrieve the full signature string (return type, name, parameters, calling convention) for a function by name or address.")
public class GhidraGetFunctionPrototypeTool implements IGhidraMcpSpecification {

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
		// Validation for requiring at least one identifier done in execute

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

			Function function = null;
			FunctionManager functionManager = program.getFunctionManager();

			if (addressOpt.isPresent()) {
				String addressString = addressOpt.get();
				Address entryPointAddress = program.getAddressFactory().getAddress(addressString);
				if (entryPointAddress != null) {
					function = functionManager.getFunctionAt(entryPointAddress);
					if (function == null) {
						throw new IllegalArgumentException("Function not found at address: " + addressString);
					}
				} else {
					if (nameOpt.isEmpty()) {
						throw new IllegalArgumentException("Invalid address format: " + addressString);
					}
				}
			}

			if (function == null && nameOpt.isPresent()) {
				String functionName = nameOpt.get();
				function = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
						.filter(f -> f.getName(true).equals(functionName))
						.findFirst()
						.orElse(null);
				if (function == null) {
					throw new IllegalArgumentException("Function not found with name: " + functionName);
				}
			}

			if (function == null) {
				throw new IllegalStateException("Could not find function by address or name, though one was provided.");
			}

			return function.getSignature(true).getPrototypeString();
		});
	}
}