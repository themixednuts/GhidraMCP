package com.themixednuts.tools.decompiler;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Decompile Function By Name", category = "Decompiler", description = "Decompiles a function specified by name.", mcpName = "decompile_function_by_name", mcpDescription = "Returns the C-like decompiled source code for the function with the given name.")
public class GhidraDecompileFunctionByNameTool implements IGhidraMcpSpecification {
	public GhidraDecompileFunctionByNameTool() {
	}

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schema),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public ObjectNode schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("functionName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function to decompile."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("functionName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).flatMap(program -> {
			String functionName = getRequiredStringArgument(args, "functionName");

			Optional<Function> targetFunctionOpt = StreamSupport
					.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
					.filter(f -> f.getName().equals(functionName))
					.findFirst();

			if (targetFunctionOpt.isEmpty()) {
				return createErrorResult("Error: Function '" + functionName + "' not found.");
			}
			Function targetFunction = targetFunctionOpt.get();

			decomp.openProgram(program);
			DecompileResults result = decomp.decompileFunction(targetFunction, 30, new ConsoleTaskMonitor());

			if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
				String decompiledCode = result.getDecompiledFunction().getC();
				return createSuccessResult(
						decompiledCode != null ? decompiledCode : "// Decompilation produced null output.");
			} else {
				String errorMsg = result != null ? result.getErrorMessage() : "Unknown decompiler error";
				return createErrorResult("Decompilation failed: " + errorMsg);
			}

		}).onErrorResume(e -> {
			return createErrorResult(e);
		}).doFinally(signalType -> {
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}

}
