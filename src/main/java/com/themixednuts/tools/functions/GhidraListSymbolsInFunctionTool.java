package com.themixednuts.tools.functions;

import java.util.Iterator;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "List Symbols in Function", category = "Functions", description = "Enable the MCP tool to list symbols in a function.", mcpName = "list_symbols_in_function", mcpDescription = "List symbols (variables, parameters) within a specified function, returning details like name, type, storage, and parameter status as JSON.")
public class GhidraListSymbolsInFunctionTool implements IGhidraMcpSpecification {
	public GhidraListSymbolsInFunctionTool() {
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

						Optional<Function> targetFunction = StreamSupport
								.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
								.filter(f -> f.getName().equals(functionName))
								.findFirst();

						if (targetFunction.isEmpty()) {
							return Mono.just(new CallToolResult("Error: Function '" + functionName + "' not found.", true));
						}

						// Use Decompiler to get HighFunction representation
						DecompInterface decomp = new DecompInterface();
						decomp.openProgram(program);
						DecompileResults result = decomp.decompileFunction(targetFunction.get(), 30, new ConsoleTaskMonitor());

						if (result == null || !result.decompileCompleted()) {
							return Mono.just(new CallToolResult("Decompilation failed: " + result.getErrorMessage(), true));
						}

						HighFunction highFunction = result.getHighFunction();
						if (highFunction == null) {
							return Mono.just(new CallToolResult("Decompilation failed (no high function)", true));
						}

						LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
						if (localSymbolMap == null) {
							return Mono.just(new CallToolResult("Decompilation failed (no local symbol map)", true));
						}

						ArrayNode variablesArray = IGhidraMcpSpecification.mapper.createArrayNode();
						Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
						while (symbols.hasNext()) {
							HighSymbol symbol = symbols.next();
							ObjectNode varNode = variablesArray.addObject();
							varNode.put("name", symbol.getName());
							varNode.put("type", symbol.getDataType().getName());
							varNode.put("isParameter", symbol.isParameter());
							varNode.put("storage", symbol.getStorage().toString());
						}

						try {
							return Mono.just(new CallToolResult(
									IGhidraMcpSpecification.mapper.writeValueAsString(variablesArray),
									false));

						} catch (JsonProcessingException e) {
							Msg.error(this, "Error serializing local variables", e);
							return Mono.just(new CallToolResult("Error creating JSON response: " + e.getMessage(), true));
						}
					}).onErrorResume(e -> {
						Msg.error(this, "Unexpected error in tool execution", e);
						return Mono.just(new CallToolResult("Unexpected error: " + e.getMessage(), true));
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
			functionNameProp.put("description", "The name of the function to list symbols from.");

			schemaRoot.putArray("required").add("fileName").add("functionName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for list_symbols_in_function tool", e);
			return Optional.empty();
		}
	}

}
