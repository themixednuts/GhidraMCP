package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Add Function", category = ToolCategory.FUNCTIONS, description = "Adds a new function at a specified address.", mcpName = "add_function", mcpDescription = "Adds a new function at a specified address.")
public class GhidraAddFunctionTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		Optional<String> schemaStringOpt = parseSchema(schema());
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The entry point address for the new function (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional name for the new function. Ghidra assigns a default if omitted."));
		// Add other options like isThunk later if needed

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					// --- Setup Phase (Inside flatMap, before transaction) ---
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					Optional<String> functionNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);
					Address entryPointAddress;
					entryPointAddress = program.getAddressFactory().getAddress(addressStr);
					if (entryPointAddress == null) {
						return createErrorResult("Invalid address string (resolved to null): " + addressStr);
					}

					// Check if function already exists (specific validation before transaction)
					Function existingFunc = program.getFunctionManager().getFunctionAt(entryPointAddress);
					if (existingFunc != null) {
						return createErrorResult(
								"Function already exists at address " + addressStr + " named '" + existingFunc.getName() + "'");
					}

					// Final address needed for the transaction lambda
					final Address finalEntryPointAddress = entryPointAddress;

					// --- Modification Phase (Inside transaction) ---
					return executeInTransaction(program, "Add Function at " + addressStr, () -> {
						// This lambda MUST return Mono<CallToolResult>
						FunctionManager functionManager = program.getFunctionManager();
						String name = functionNameOpt.orElse(null);
						AddressSet body = new AddressSet(finalEntryPointAddress);

						Function newFunction = functionManager.createFunction(name, finalEntryPointAddress, body,
								SourceType.USER_DEFINED);

						if (newFunction == null) {
							// Wrap error result in Mono
							return createErrorResult(
									"Failed to create function at " + addressStr + ", createFunction returned null.");
						}
						// Wrap success result in Mono
						return createSuccessResult(
								"Successfully added function '" + newFunction.getName() + "' at address " + addressStr);
					});
				})
				.onErrorResume(e -> createErrorResult(e));
	}
}