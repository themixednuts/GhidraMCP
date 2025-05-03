package com.themixednuts.tools.functions;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Comparator;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraFunctionsToolInfo;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "List Function Names", category = "Functions", description = "Enable the MCP tool to list function names in a file.", mcpName = "list_function_names", mcpDescription = "List the names and entry point addresses of functions defined within a specific program. Supports pagination.")
public class GhidraListFunctionNamesTool implements IGhidraMcpSpecification {

	public GhidraListFunctionNamesTool() {
	}

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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
				JsonSchemaBuilder.string(IGhidraMcpSpecification.mapper)
						.description("The name of the program file."));
		schemaRoot.requiredProperty("fileName");
		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String cursorStr = getOptionalStringArgument(args, "cursor").orElse(null);
			Address cursorAddr = null;
			if (cursorStr != null) {
				cursorAddr = program.getAddressFactory().getAddress(cursorStr);
				if (cursorAddr == null) {
					return createErrorResult("Invalid cursor format (could not parse address): " + cursorStr);
				}
			}

			final Address finalCursorAddr = cursorAddr;

			List<Function> limitedFunctions = StreamSupport.stream(
					program.getFunctionManager().getFunctions(true).spliterator(), false)
					.sorted(Comparator.comparing(Function::getEntryPoint))
					.dropWhile(function -> finalCursorAddr != null && function.getEntryPoint().compareTo(finalCursorAddr) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			boolean hasMore = limitedFunctions.size() > DEFAULT_PAGE_LIMIT;

			List<Function> pageFunctions = limitedFunctions.subList(0,
					Math.min(limitedFunctions.size(), DEFAULT_PAGE_LIMIT));

			List<GhidraFunctionsToolInfo> pageResults = pageFunctions.stream()
					.map(GhidraFunctionsToolInfo::new)
					.collect(Collectors.toList());

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getAddress();
			}

			PaginatedResult<GhidraFunctionsToolInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return createSuccessResult(paginatedResult);

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}
