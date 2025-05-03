package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.models.HighSymbolInfo;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get Symbol By Name In Function", category = "Functions", description = "Gets details of a specific symbol (variable/parameter) within a function by its name.", mcpName = "get_symbol_by_name_in_function", mcpDescription = "Retrieves details (type, storage, etc.) for a specific symbol identified by its name within a given function.")
public class GhidraGetSymbolByNameInFunctionTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to serialize schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> {
					return execute(ex, args, tool);
				});
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("functionName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function containing the symbol."));
		schemaRoot.property("symbolName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the symbol (local variable or parameter) to retrieve."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("functionName")
				.requiredProperty("symbolName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).flatMap(program -> {
			String functionName = getRequiredStringArgument(args, "functionName");
			String symbolName = getRequiredStringArgument(args, "symbolName");

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

			if (result == null || !result.decompileCompleted()) {
				String errorMsg = "Decompilation failed: "
						+ (result != null ? result.getErrorMessage() : "Unknown decompiler error");
				return createErrorResult(errorMsg);
			}
			HighFunction highFunction = result.getHighFunction();
			if (highFunction == null) {
				return createErrorResult("Decompilation failed (no high function)");
			}
			LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
			if (localSymbolMap == null) {
				return createErrorResult("Decompilation failed (no local symbol map)");
			}

			Map<String, HighSymbol> nameToSymbolMap = localSymbolMap.getNameToSymbolMap();
			HighSymbol highSymbol = nameToSymbolMap.get(symbolName);
			if (highSymbol == null) {
				return createErrorResult(
						"Symbol '" + symbolName + "' not found in function '" + functionName + "'");
			}

			HighSymbolInfo symbolInfo = new HighSymbolInfo(highSymbol);
			return createSuccessResult(symbolInfo);

		}).onErrorResume(e -> {
			return createErrorResult(e);
		}).doFinally(signalType -> {
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}

}
