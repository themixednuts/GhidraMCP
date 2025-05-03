package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

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
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Rename Symbol in Function", category = ToolCategory.FUNCTIONS, description = "Renames a symbol (variable or parameter) within a specific function.", mcpName = "rename_symbol_in_function", mcpDescription = "Renames a local variable or parameter within a function.")
public class GhidraRenameSymbolInFunctionTool implements IGhidraMcpSpecification {

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
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function containing the symbol."));
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The current name of the local variable or parameter to rename."));
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the symbol."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_FUNCTION_NAME)
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_NEW_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).flatMap(program -> {
			String functionName = getRequiredStringArgument(args, ARG_FUNCTION_NAME);
			String currentSymbolName = getRequiredStringArgument(args, ARG_NAME);
			String newSymbolName = getRequiredStringArgument(args, ARG_NEW_NAME);

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
			GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
			DecompileResults result = decomp.decompileFunction(targetFunction, 30, monitor);

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

		}).onErrorResume(e -> createErrorResult(e)).doFinally(signalType -> {
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}
}
