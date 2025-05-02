package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.model.Project;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Rename Symbol in Function", category = "Functions", description = "Enable the MCP tool to rename a symbol in a function.", mcpName = "rename_symbol_in_function", mcpDescription = "Rename a symbol (local variable or parameter) within a specified function, identifying it by its current name.")
public class GhidraRenameSymbolInFunctionTool implements IGhidraMcpSpecification {
	public GhidraRenameSymbolInFunctionTool() {
	}

	@Override
	public AsyncToolSpecification specification(Project project) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		Optional<String> schemaJson = schema();
		if (schemaJson.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null; // Signal failure
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson.get()),
				(ex, args) -> {
					return getProgram(args, project).flatMap(program -> {
						String functionName = getRequiredStringArgument(args, "functionName");
						String symbolName = getRequiredStringArgument(args, "oldSymbolName");
						String newSymbolName = getRequiredStringArgument(args, "newSymbolName");

						Optional<Function> targetFunctionOpt = StreamSupport
								.stream(program.getSymbolTable().getSymbolIterator(functionName, true).spliterator(), false)
								.filter(symbol -> symbol instanceof FunctionSymbol)
								.map(symbol -> (Function) symbol.getObject())
								.findFirst();

						if (targetFunctionOpt.isEmpty()) {
							return Mono.just(new CallToolResult("Error: Function '" + functionName + "' not found.", true));
						}

						Function targetFunction = targetFunctionOpt.get();
						DecompInterface decomp = new DecompInterface();
						decomp.openProgram(program);
						DecompileResults result = decomp.decompileFunction(targetFunction, 30, new ConsoleTaskMonitor());

						if (result == null || !result.decompileCompleted()) {
							return Mono.just(new CallToolResult("Error: Decompilation failed", true));
						}

						HighFunction highFunction = result.getHighFunction();
						LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
						Map<String, HighSymbol> nameToSymbolMap = localSymbolMap.getNameToSymbolMap();
						HighSymbol highSymbol = nameToSymbolMap.get(symbolName);

						if (highSymbol == null) {
							return Mono.just(new CallToolResult(
									"Error: Symbol '" + symbolName + "' not found in function '" + functionName + "'", true));
						}

						if (nameToSymbolMap.containsKey(newSymbolName)) {
							return Mono.just(new CallToolResult(
									"Error: Symbol '" + newSymbolName + "' already exists in function '" + functionName + "'",
									true));
						}

						CallToolResult toolResult = executeInTransaction(program, "Rename Symbol: " + symbolName, () -> {

							HighFunctionDBUtil.updateDBVariable(highSymbol, newSymbolName, highSymbol.getDataType(),
									SourceType.USER_DEFINED);

							return new CallToolResult("Symbol renamed successfully", false);

						});

						if (toolResult == null) {
							Msg.error(this, "Swing.runNow did not return a result for rename_symbol_in_function");
							return Mono.just(new CallToolResult("Internal error: Swing operation failed to provide result.", true));
						}

						return Mono.just(toolResult);

					}).onErrorResume(e -> {
						Msg.error(this, e.getMessage());
						return Mono.just(new CallToolResult(e.getMessage(), true));
					});
				});
	}

	@Override
	public Optional<String> schema() {
		try {
			ObjectNode schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
			ObjectNode properties = schemaRoot.putObject("properties");

			ObjectNode fileNameProp = properties.putObject("fileName");
			fileNameProp.put("type", "string");
			fileNameProp.put("description", "The file name of the Ghidra tool window to target.");

			ObjectNode functionNameProp = properties.putObject("functionName");
			functionNameProp.put("type", "string");
			functionNameProp.put("description", "The name of the function containing the symbol.");

			ObjectNode oldSymbolNameProp = properties.putObject("oldSymbolName");
			oldSymbolNameProp.put("type", "string");
			oldSymbolNameProp.put("description", "The current name of the symbol (variable or parameter) to rename.");

			ObjectNode newSymbolNameProp = properties.putObject("newSymbolName");
			newSymbolNameProp.put("type", "string");
			newSymbolNameProp.put("description", "The new name for the symbol.");

			schemaRoot.putArray("required")
					.add("fileName")
					.add("functionName")
					.add("oldSymbolName")
					.add("newSymbolName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for rename_symbol_in_function tool", e);
			return Optional.empty();
		}
	}

}
