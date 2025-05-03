package com.themixednuts.tools.functions;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.models.DataTypeSuggestionInfo;
import com.themixednuts.tools.ToolCategory;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
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

@GhidraMcpTool(key = "Change Symbol Data Type in Function", category = ToolCategory.FUNCTIONS, description = "Changes the data type of a symbol (variable or parameter) within a specific function.", mcpName = "change_symbol_data_type_in_function", mcpDescription = "Changes the data type of a local variable or parameter within a function.")
public class GhidraChangeSymbolDataTypeInFunctionTool implements IGhidraMcpSpecification {

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
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("functionName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function containing the symbol."));
		schemaRoot.property("symbolName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the local variable or parameter whose data type will be changed."));
		schemaRoot.property("newDataType",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the new data type to apply (e.g., 'int', 'char*', 'MyStruct')."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("functionName")
				.requiredProperty("symbolName")
				.requiredProperty("newDataType");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).flatMap(program -> { // Program is available

			String functionName = getRequiredStringArgument(args, "functionName");
			String symbolName = getRequiredStringArgument(args, "symbolName");
			String newDataTypeName = getRequiredStringArgument(args, "newDataType");

			Optional<Function> targetFunctionOpt = StreamSupport
					.stream(program.getSymbolTable().getSymbolIterator(functionName, true).spliterator(), false)
					.filter(symbol -> symbol instanceof FunctionSymbol)
					.map(symbol -> (Function) symbol.getObject())
					.findFirst();

			if (targetFunctionOpt.isEmpty()) {
				String errorMsg = "Error: Function '" + functionName + "' not found.";
				return createErrorResult(errorMsg);
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
				String errorMsg = "Decompilation failed (no high function)";
				return createErrorResult(errorMsg);
			}
			LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
			Map<String, HighSymbol> nameToSymbolMap = localSymbolMap.getNameToSymbolMap();
			HighSymbol highSymbol = nameToSymbolMap.get(symbolName);

			if (highSymbol == null) {
				String errorMsg = "Symbol '" + symbolName + "' not found in function '" + functionName + "'";
				return createErrorResult(errorMsg);
			}

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dataType = dtm.getDataType(newDataTypeName);

			if (dataType == null) {
				Iterator<DataType> iterator = dtm.getAllDataTypes();
				List<DataTypeSuggestionInfo> suggestions = new ArrayList<>();
				iterator.forEachRemaining(t -> {
					if (t.getName().toLowerCase().contains(newDataTypeName.toLowerCase())) {
						suggestions.add(new DataTypeSuggestionInfo(t));
					}
				});

				String baseMsg = "Data type '" + newDataTypeName + "' not found. Possible types";
				return createErrorResult(baseMsg, suggestions);
			}

			final DataType finalDataType = dataType;
			return executeInTransaction(program, "Change Symbol DataType: " + symbolName, () -> {
				DataType resolvedDataType = finalDataType.clone(dtm);
				HighFunctionDBUtil.updateDBVariable(highSymbol, null, resolvedDataType, SourceType.USER_DEFINED);
				return createSuccessResult(
						"Symbol '" + symbolName + "' data type changed successfully to '" + newDataTypeName + "'");
			});

		}).onErrorResume(e -> createErrorResult(e)).doFinally(signalType -> {
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}

}
