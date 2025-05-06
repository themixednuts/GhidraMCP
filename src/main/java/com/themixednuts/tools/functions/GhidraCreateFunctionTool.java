package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.utils.GhidraMcpTaskMonitor;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Function", category = ToolCategory.FUNCTIONS, description = "Adds a new function at a specified address, optionally naming it.", mcpName = "create_function", mcpDescription = "Adds a new function at a specified address.")
public class GhidraCreateFunctionTool implements IGhidraMcpSpecification {

	private static record CreateFunctionContext(Program program, Address functionAddress, Optional<String> functionName) {
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

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressString = getRequiredStringArgument(args, ARG_ADDRESS);
			Optional<String> nameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

			Address functionAddress = program.getAddressFactory().getAddress(addressString);

			if (program.getFunctionManager().getFunctionAt(functionAddress) != null) {
				throw new IllegalArgumentException("Function already exists at address: " + addressString);
			}

			return new CreateFunctionContext(program, functionAddress, nameOpt);

		}).flatMap(context -> {
			Program program = context.program();
			Address funcAddr = context.functionAddress();
			Optional<String> funcNameOpt = context.functionName();
			String transactionName = "MCP - Create Function at " + funcAddr;

			return executeInTransaction(program, transactionName, () -> {
				CreateFunctionCmd cmd = new CreateFunctionCmd(
						funcNameOpt.orElse(null),
						funcAddr,
						new AddressSet(funcAddr),
						SourceType.USER_DEFINED);

				GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
				if (!cmd.applyTo(program, monitor)) {
					throw new RuntimeException("Failed to create function at " + funcAddr + ": " + cmd.getStatusMsg());
				}

				Function createdFunction = cmd.getFunction();
				if (createdFunction == null) {
					throw new RuntimeException("CreateFunctionCmd succeeded but returned null function at " + funcAddr);
				}

				return new FunctionInfo(createdFunction);
			});
		});
	}
}