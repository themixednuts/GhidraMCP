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

import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Delete Function", category = ToolCategory.FUNCTIONS, description = "Removes a function specified either by its name or entry point address.", mcpName = "delete_function", mcpDescription = "Removes a function specified either by its name or entry point address.")
public class GhidraDeleteFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function to remove. Either this or address must be provided."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional entry point address of the function to remove (e.g., '0x1004010'). Preferred over name if provided.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	private static record DeleteFunctionContext(
			Program program,
			Address addressToDelete) {
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

			Function functionToDelete = null;
			FunctionManager functionManager = program.getFunctionManager();
			String identifier = "";
			Address entryPointAddress = null;

			if (addressOpt.isPresent()) {
				String addressString = addressOpt.get();
				identifier = addressString;
				entryPointAddress = program.getAddressFactory().getAddress(addressString);
				functionToDelete = functionManager.getFunctionAt(entryPointAddress);
			}

			if (functionToDelete == null && nameOpt.isPresent()) {
				String functionName = nameOpt.get();
				identifier = functionName;
				functionToDelete = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
						.filter(f -> f.getName(true).equals(functionName))
						.findFirst()
						.orElse(null);
				if (functionToDelete != null) {
					entryPointAddress = functionToDelete.getEntryPoint();
				}
			}

			if (functionToDelete == null || entryPointAddress == null) {
				throw new IllegalArgumentException(
						"Function not found or address could not be determined for identifier: " + identifier);
			}

			return new DeleteFunctionContext(program, entryPointAddress);

		}).flatMap(context -> {
			final String entryPointStr = context.addressToDelete().toString();

			return executeInTransaction(context.program(), "MCP - Delete Function at " + entryPointStr, () -> {
				DeleteFunctionCmd cmd = new DeleteFunctionCmd(context.addressToDelete());
				if (!cmd.applyTo(context.program())) {
					throw new RuntimeException("Failed to delete function at " + entryPointStr + ": " + cmd.getStatusMsg());
				}
				return "Successfully deleted function at address " + entryPointStr;
			});
		});
	}
}