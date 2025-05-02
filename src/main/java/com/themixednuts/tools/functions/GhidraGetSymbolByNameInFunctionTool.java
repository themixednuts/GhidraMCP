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

@GhidraMcpTool(key = "Get Symbol by Name in Function", category = "Functions", description = "Enable the MCP tool to get a symbol by name in a function.", mcpName = "get_symbol_by_name_in_function", mcpDescription = "Retrieve details (name, type, storage, parameter status) for a specific symbol (variable or parameter) identified by its name within a given function.")
public class GhidraGetSymbolByNameInFunctionTool implements IGhidraMcpSpecification {
	public GhidraGetSymbolByNameInFunctionTool() {
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
						String symbolName = getRequiredStringArgument(args, "symbolName");

						Optional<Function> targetFunction = StreamSupport
								.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
								.filter(f -> f.getName().equals(functionName))
								.findFirst();

						if (targetFunction.isEmpty()) {
							return Mono.just(new CallToolResult("Error: Function '" + functionName + "' not found.", true));
						}

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

						Map<String, HighSymbol> nameToSymbolMap = localSymbolMap.getNameToSymbolMap();
						HighSymbol highSymbol = nameToSymbolMap.get(symbolName);
						if (highSymbol == null) {
							return Mono.just(new CallToolResult(
									"Symbol '" + symbolName + "' not found in function '" + functionName + "'", true));
						}

						try {
							return Mono.just(new CallToolResult(
									IGhidraMcpSpecification.mapper.writeValueAsString(highSymbol),
									false));
						} catch (JsonProcessingException e) {
							Msg.error(this, "Error serializing symbol", e);
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
			functionNameProp.put("description", "The name of the function containing the symbol.");

			ObjectNode symbolNameProp = properties.putObject("symbolName");
			symbolNameProp.put("type", "string");
			symbolNameProp.put("description", "The name of the symbol (variable or parameter) to retrieve.");

			schemaRoot.putArray("required")
					.add("fileName")
					.add("functionName")
					.add("symbolName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for get_symbol_by_name_in_function tool", e);
			return Optional.empty();
		}
	}

}
