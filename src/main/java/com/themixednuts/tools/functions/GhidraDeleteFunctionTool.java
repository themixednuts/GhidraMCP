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
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Remove Function", category = ToolCategory.FUNCTIONS, description = "Removes a function by name or address.", mcpName = "remove_function", mcpDescription = "Removes a function specified either by its name or entry point address.")
public class GhidraRemoveFunctionTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		Optional<String> schemaStringOpt = parseSchema(schema());
		if (schemaStringOpt.isEmpty()) {
			return null;
		}
		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaStringOpt.get()),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		// Allow identification by either name or address
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function to remove. Either this or address must be provided."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional entry point address of the function to remove (e.g., '0x1004010'). Preferred over name if provided.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		// Requires at least one of functionName or address, validation done in execute

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					// --- Setup Phase ---
					Optional<String> functionNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);
					Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);

					// Validate that exactly one identifier is provided
					if (functionNameOpt.isEmpty() && addressOpt.isEmpty()) {
						return createErrorResult("Either functionName or address must be provided.");
					}
					if (functionNameOpt.isPresent() && addressOpt.isPresent()) {
						return createErrorResult("Provide either functionName or address, not both.");
					}

					Function targetFunction;
					String functionIdentifier;

					FunctionManager functionManager = program.getFunctionManager();

					if (addressOpt.isPresent()) {
						String addressStr = addressOpt.get();
						functionIdentifier = addressStr;
						Address entryPointAddress;
						// Let .onErrorResume handle AddressFormatException
						entryPointAddress = program.getAddressFactory().getAddress(addressStr);
						if (entryPointAddress == null) {
							// Handle null return separately if getAddress doesn't throw for all invalid
							// cases
							return createErrorResult("Invalid address string (resolved to null or unparsable): " + addressStr);
						}
						targetFunction = functionManager.getFunctionAt(entryPointAddress);
						if (targetFunction == null) {
							return createErrorResult("Function not found at address: " + addressStr);
						}
					} else { // functionNameOpt must be present
						String functionName = functionNameOpt.get();
						functionIdentifier = functionName;
						targetFunction = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
								.filter(f -> f.getName().equals(functionName))
								.findFirst().orElse(null);
						if (targetFunction == null) {
							return createErrorResult("Function not found with name: " + functionName);
						}
					}

					final Function finalTargetFunction = targetFunction; // Final for lambda
					final String finalIdentifier = functionIdentifier; // Final for message

					// --- Modification Phase ---
					return executeInTransaction(program, "Remove Function: " + finalIdentifier, () -> {
						boolean removed = functionManager.removeFunction(finalTargetFunction.getEntryPoint());
						if (removed) {
							return createSuccessResult("Successfully removed function: " + finalIdentifier);
						} else {
							return createErrorResult("Failed to remove function: " + finalIdentifier
									+ ". It might have been removed already or removal failed.");
						}
					});
				})
				.onErrorResume(e -> createErrorResult(e));
	}
}