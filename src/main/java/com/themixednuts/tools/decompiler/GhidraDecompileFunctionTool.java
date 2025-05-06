package com.themixednuts.tools.decompiler;

import java.util.Map;
import java.util.stream.StreamSupport;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Decompile Function", category = ToolCategory.DECOMPILER, description = "Decompiles a function given its name or address and returns the C code representation.", mcpName = "decompile_function", mcpDescription = "Decompiles a function by its name or address.")
public class GhidraDecompileFunctionTool implements IGhidraMcpSpecification {
	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function to decompile (provide name or address)."));
		schemaRoot.property(ARG_FUNCTION_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address of the function to decompile (provide name or address)."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).map(program -> {
			String functionName = getOptionalStringArgument(args, ARG_FUNCTION_NAME).orElse(null);
			String functionAddressStr = getOptionalStringArgument(args, ARG_FUNCTION_ADDRESS).orElse(null);

			Function targetFunction;

			if (functionName != null && !functionName.isEmpty() && functionAddressStr != null
					&& !functionAddressStr.isEmpty()) {
				throw new IllegalArgumentException("Please provide either function name or function address, not both.");
			} else if (functionName != null && !functionName.isEmpty()) {
				targetFunction = StreamSupport
						.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
						.filter(f -> f.getName().equals(functionName))
						.findFirst()
						.orElse(null);
				if (targetFunction == null) {
					throw new IllegalArgumentException(
							"Error: Function '" + functionName + "' not found in file '"
									+ program.getDomainFile().getName() + "'.");
				}
			} else {
				Address address = program.getAddressFactory().getAddress(functionAddressStr);
				if (address == null) {
					throw new IllegalArgumentException("Invalid address format: " + functionAddressStr);
				}
				targetFunction = program.getFunctionManager().getFunctionContaining(address);
				if (targetFunction == null) {
					throw new IllegalArgumentException(
							"Error: No function found at address '" + functionAddressStr + "' in file '"
									+ program.getDomainFile().getName() + "'.");
				}
			}

			return Tuples.of(program, targetFunction);

		}).flatMap(programAndFunctionTuple -> {
			ghidra.program.model.listing.Program program = programAndFunctionTuple.getT1();
			Function targetFunction = programAndFunctionTuple.getT2();

			return Mono.fromCallable(() -> {
				decomp.openProgram(program);
				GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
				DecompileResults result = decomp.decompileFunction(targetFunction, 30, monitor);

				if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
					String decompiledCode = result.getDecompiledFunction().getC();
					return Map.of("decompiledCode",
							decompiledCode != null ? decompiledCode : "// Decompilation produced null output.");
				} else {
					String errorMsg = result != null ? result.getErrorMessage() : "Unknown decompiler error";
					throw new RuntimeException(
							"Decompilation failed for function '" + targetFunction.getName() + "': " + errorMsg);
				}
			});
		}).doFinally(signalType -> {
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}

}
