package com.themixednuts.tools.decompiler;

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
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Decompile Function by Name", category = "Decompiler", description = "Enable the MCP tool to decompile a function by name.", mcpName = "decompile_function_by_name", mcpDescription = "Decompile a function specified by its exact name, returning the generated pseudo-C source code as a string.")
public class GhidraDecompileFunctionByNameTool implements IGhidraMcpSpecification {
	public GhidraDecompileFunctionByNameTool() {
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

						DecompInterface decomp = new DecompInterface();
						decomp.openProgram(program);
						DecompileResults result = decomp.decompileFunction(targetFunction.get(), 30, new ConsoleTaskMonitor());

						if (result != null && result.decompileCompleted()) {
							String decompiledCode = result.getDecompiledFunction().getC();
							return Mono.just(new CallToolResult(decompiledCode, false));
						} else {
							return Mono.just(new CallToolResult("Decompilation failed", true));
						}

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
			functionNameProp.put("description", "The name of the function to decompile.");

			schemaRoot.putArray("required").add("fileName").add("functionName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for decompile_function_by_name tool", e);
			return Optional.empty();
		}
	}

}
