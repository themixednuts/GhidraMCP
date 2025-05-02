package com.themixednuts.tools.functions;

import java.util.Optional;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraFunctionsToolInfo;

import ghidra.framework.model.Project;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.program.model.listing.Function;

@GhidraMcpTool(key = "Get Function by Name", category = "Functions", description = "Enable the MCP tool to get a function by name.", mcpName = "get_function_by_name", mcpDescription = "Retrieve details (entry point, etc.) for a function identified by its exact name.")
public class GhidraGetFunctionByNameTool implements IGhidraMcpSpecification {
	public GhidraGetFunctionByNameTool() {
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

						Optional<Function> targetFunctionOpt = StreamSupport
								.stream(program.getSymbolTable().getSymbolIterator(functionName, true).spliterator(), false)
								.filter(symbol -> symbol instanceof FunctionSymbol)
								.map(symbol -> (Function) symbol.getObject())
								.findFirst();

						if (targetFunctionOpt.isPresent()) {
							GhidraFunctionsToolInfo functionInfo = new GhidraFunctionsToolInfo(targetFunctionOpt.get());
							try {
								String jsonResult = IGhidraMcpSpecification.mapper.writeValueAsString(functionInfo);
								return Mono.just(new CallToolResult(jsonResult, false));
							} catch (JsonProcessingException e) {
								String errorMsg = "Error serializing function info to JSON for '" + functionName + "': "
										+ e.getMessage();
								Msg.error(this, errorMsg, e);
								return Mono.just(new CallToolResult(errorMsg, true));
							}
						} else {
							return Mono.just(new CallToolResult("Error: Function '" + functionName + "' not found.", true));
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
			functionNameProp.put("description", "The name of the function to retrieve.");

			schemaRoot.putArray("required").add("fileName").add("functionName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for get_function_by_name tool", e);
			return Optional.empty();
		}
	}

}
