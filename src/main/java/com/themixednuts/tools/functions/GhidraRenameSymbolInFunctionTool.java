package com.themixednuts.tools.functions;

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
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Rename Symbol In Function", category = "Functions", description = "Renames a local variable or parameter within a specific function.", mcpName = "rename_symbol_in_function", mcpDescription = "Finds a symbol (local variable or parameter) by its current name within a function and renames it.")
public class GhidraRenameSymbolInFunctionTool implements IGhidraMcpSpecification {

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
						.description("The name of the function containing the symbol."));
		schemaRoot.property("currentSymbolName",
				JsonSchemaBuilder.string(mapper)
						.description("The current name of the local variable or parameter to rename."));
		schemaRoot.property("newSymbolName",
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the symbol."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("functionName")
				.requiredProperty("currentSymbolName")
				.requiredProperty("newSymbolName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).flatMap(program -> {
			String functionName = getRequiredStringArgument(args, "functionName");
			String currentSymbolName = getRequiredStringArgument(args, "currentSymbolName");
			String newSymbolName = getRequiredStringArgument(args, "newSymbolName");

			Optional<Function> targetFunctionOpt = StreamSupport
					.stream(program.getSymbolTable().getSymbolIterator(functionName, true).spliterator(), false)
					.filter(symbol -> symbol instanceof FunctionSymbol)
					.map(symbol -> (Function) symbol.getObject())
					.findFirst();

			if (targetFunctionOpt.isEmpty()) {
				return createErrorResult("Error: Function '" + functionName + "' not found.");
			}
			Function targetFunction = targetFunctionOpt.get();

			decomp.openProgram(program);
			DecompileResults result = decomp.decompileFunction(targetFunction, 30, new ConsoleTaskMonitor());

			if (result == null || !result.decompileCompleted()) {
				String errorMsg = result != null ? result.getErrorMessage() : "Unknown decompiler error";
				return createErrorResult("Error: Decompilation failed: " + errorMsg);
			}
			HighFunction highFunction = result.getHighFunction();
			if (highFunction == null) {
				return createErrorResult("Error: Decompilation failed (no high function)");
			}
			LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
			Map<String, HighSymbol> nameToSymbolMap = localSymbolMap.getNameToSymbolMap();

			HighSymbol highSymbol = nameToSymbolMap.get(currentSymbolName);
			if (highSymbol == null) {
				return createErrorResult(
						"Error: Symbol '" + currentSymbolName + "' not found in function '" + functionName + "'");
			}

			if (nameToSymbolMap.containsKey(newSymbolName)) {
				return createErrorResult(
						"Error: Symbol '" + newSymbolName + "' already exists in function '" + functionName + "'");
			}

			return executeInTransaction(program, "Rename Symbol: " + newSymbolName, () -> {
				HighFunctionDBUtil.updateDBVariable(highSymbol, newSymbolName, null, SourceType.USER_DEFINED);
				return createSuccessResult("Symbol renamed successfully to " + newSymbolName);
			});

		}).onErrorResume(e -> {
			return createErrorResult(e);
		}).doFinally(signalType -> {
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}
}
