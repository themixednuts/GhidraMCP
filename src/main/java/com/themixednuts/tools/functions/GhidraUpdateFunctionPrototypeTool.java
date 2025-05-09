package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;
import io.modelcontextprotocol.spec.McpSchema.LoggingMessageNotification;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

@GhidraMcpTool(name = "Update Function Prototype", category = ToolCategory.FUNCTIONS, description = "Updates the prototype (signature) of an existing function.", mcpName = "update_function_prototype", mcpDescription = "Modifies the return type, parameters, calling convention, or varargs status of an existing function.")
public class GhidraUpdateFunctionPrototypeTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));

		schemaRoot.property(ARG_FUNCTION_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("Optional: Symbol ID of the function. Preferred identifier."))
				.property(ARG_FUNCTION_ADDRESS,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: Entry point address of the function (e.g., '0x1004010'). Used if Symbol ID is not provided or not found.")
								.pattern("^(0x)?[0-9a-fA-F]+$"))
				.property(ARG_FUNCTION_NAME,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: Name of the function. Used if Symbol ID and Address are not provided or not found."));

		schemaRoot.property("prototype",
				JsonSchemaBuilder.string(mapper)
						.description("The new function prototype string (e.g., 'void FUN_00401000(int param1, char *param2)')."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty("prototype");

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
			Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_FUNCTION_ADDRESS);
			Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

			String newPrototypeString = getRequiredStringArgument(args, "prototype");

			if (funcSymbolIdOpt.isEmpty() && funcAddressOpt.isEmpty() && funcNameOpt.isEmpty()) {
				return Mono.error(new IllegalArgumentException(
						"At least one function identifier (functionSymbolId, functionAddress, or functionName) must be provided."));
			}

			return Mono.fromCallable(() -> {
				Function targetFunction = resolveFunction(program, funcSymbolIdOpt, funcAddressOpt, funcNameOpt);

				return Tuples.of(targetFunction, newPrototypeString);
			})
					.flatMap(tuple -> {
						Function functionToUpdate = tuple.getT1();
						String prototypeStr = tuple.getT2();

						ex.loggingNotification(LoggingMessageNotification.builder()
								.level(LoggingLevel.INFO)
								.logger(this.getClass().getSimpleName())
								.data("Attempting to update prototype for " + functionToUpdate.getName() + " at "
										+ functionToUpdate.getEntryPoint()
										+ " with signature: " + prototypeStr)
								.build());

						return executeInTransaction(program,
								"MCP - Update Function Prototype: " + functionToUpdate.getName(),
								() -> {
									DataTypeManager dtm = program.getDataTypeManager();
									DataTypeQueryService service = tool.getService(DataTypeQueryService.class);
									if (service == null) {
										throw new IllegalStateException("DataTypeQueryService not available.");
									}
									FunctionSignatureParser parser = new FunctionSignatureParser(dtm, service);
									FunctionDefinitionDataType parsedSignature = parser.parse(functionToUpdate.getSignature(),
											prototypeStr);
									ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(functionToUpdate.getEntryPoint(),
											parsedSignature, SourceType.USER_DEFINED);
									GhidraMcpTaskMonitor mcpMonitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
									if (!cmd.applyTo(program, mcpMonitor)) {
										throw new RuntimeException("Failed to apply signature: " + cmd.getStatusMsg());
									}
									return "Function prototype updated successfully for " + functionToUpdate.getName();
								});
					});
		});
	}

	// Helper method to resolve function by Symbol ID, Address, or Name
	private Function resolveFunction(Program program, Optional<Long> funcSymbolIdOpt, Optional<String> funcAddressOpt,
			Optional<String> funcNameOpt) {
		FunctionManager funcMan = program.getFunctionManager();
		Function function = null;

		// Attempt 1: Resolve by Symbol ID
		if (funcSymbolIdOpt.isPresent()) {
			long symbolID = funcSymbolIdOpt.get();
			ghidra.program.model.symbol.Symbol symbol = program.getSymbolTable().getSymbol(symbolID);
			if (symbol != null && symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
				function = funcMan.getFunctionAt(symbol.getAddress());
				if (function != null) {
					return function; // Successfully found by Symbol ID
				}
			}
		}

		// Attempt 2: Resolve by Address
		if (funcAddressOpt.isPresent()) {
			Address funcAddr = program.getAddressFactory().getAddress(funcAddressOpt.get());
			if (funcAddr == null) {
				ghidra.util.Msg.warn(this, "Invalid function address format or address not found: " + funcAddressOpt.get());
			}
			if (funcAddr != null) {
				function = funcMan.getFunctionAt(funcAddr);
				if (function != null) {
					return function; // Successfully found by address
				}
			}
		}

		// Attempt 3: Resolve by Name
		if (funcNameOpt.isPresent()) {
			String functionName = funcNameOpt.get();
			java.util.List<Function> foundFunctionsByName = java.util.stream.StreamSupport
					.stream(funcMan.getFunctions(true).spliterator(), false)
					.filter(f -> f.getName().equals(functionName))
					.collect(java.util.stream.Collectors.toList());

			if (foundFunctionsByName.size() == 1) {
				return foundFunctionsByName.get(0); // Found unique function by name
			} else if (foundFunctionsByName.size() > 1) {
				throw new IllegalArgumentException(
						"Multiple functions found with name: '" + functionName +
								"'. Please use a more specific identifier like address or symbol ID.");
			}
		}

		// If not found by any means
		StringBuilder errorMessage = new StringBuilder("Function not found using any of the provided identifiers: ");
		funcSymbolIdOpt.ifPresent(id -> errorMessage.append("functionSymbolId='").append(id).append("' "));
		funcAddressOpt.ifPresent(addr -> errorMessage.append("functionAddress='").append(addr).append("' "));
		funcNameOpt.ifPresent(name -> errorMessage.append("functionName='").append(name).append("' "));
		throw new IllegalArgumentException(errorMessage.toString().trim());
	}
}
