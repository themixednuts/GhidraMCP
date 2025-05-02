package com.themixednuts.tools.functions;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraFunctionsToolInfo;

import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.util.Msg;

import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "List Function Names", category = "Functions", description = "Enable the MCP tool to list function names in a file.", mcpName = "list_function_names", mcpDescription = "List the names and entry point addresses of functions defined within a specific program. Supports pagination.")
public class GhidraListFunctionNamesTool implements IGhidraMcpSpecification {
	private static final int PAGE_SIZE = 100;

	public GhidraListFunctionNamesTool() {
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
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson.get()),
				(ex, args) -> {
					return getProgram(args, project).flatMap(program -> {

						Address cursor = getOptionalStringArgument(args, "cursor").map(program.getAddressFactory()::getAddress)
								.orElse(null);

						List<Function> functions = StreamSupport
								.stream(program.getSymbolTable().getSymbolIterator().spliterator(), false)
								.filter(symbol -> symbol instanceof FunctionSymbol)
								.map(symbol -> (Function) symbol.getObject())
								.dropWhile(function -> cursor != null && function.getEntryPoint().compareTo(cursor) <= 0)
								.limit(PAGE_SIZE + 1)
								.collect(Collectors.toList());

						boolean hasMore = functions.size() > PAGE_SIZE;
						int actualPageSize = Math.min(functions.size(), PAGE_SIZE);
						functions = functions.subList(0, actualPageSize);

						Address nextCursor = hasMore ? functions.stream()
								.map(Function::getEntryPoint)
								.max(Address::compareTo)
								.orElse(null) : null;

						List<GhidraFunctionsToolInfo> functionNodes = functions.stream()
								.map(GhidraFunctionsToolInfo::new)
								.collect(Collectors.toList());

						ObjectNode result = IGhidraMcpSpecification.mapper.createObjectNode();
						result.set("functions", IGhidraMcpSpecification.mapper.valueToTree(functionNodes));
						if (nextCursor != null) {
							result.put("nextCursor", nextCursor.toString());
						}

						try {
							return Mono.just(new CallToolResult(IGhidraMcpSpecification.mapper.writeValueAsString(result), false));
						} catch (JsonProcessingException e) {
							Msg.error(this, "Error serializing function list to JSON", e);
							return Mono
									.just(new CallToolResult("Error serializing function list to JSON: " + e.getMessage(), true));
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
			fileNameProp.put("description", "The file name of the Ghidra tool window to target");

			schemaRoot.putArray("required").add("fileName");

			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for list_function_names tool", e);
			return Optional.empty();
		}
	}
}
