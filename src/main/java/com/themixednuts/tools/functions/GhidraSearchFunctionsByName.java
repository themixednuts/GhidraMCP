package com.themixednuts.tools.functions;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraFunctionsToolInfo;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;

import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Search Functions By Name", category = "Functions", description = "Searches for functions matching a name pattern.", mcpName = "search_functions_by_name", mcpDescription = "Returns a paginated list of functions whose names contain the specified search term.")
public class GhidraSearchFunctionsByName implements IGhidraMcpSpecification {

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
		schemaRoot.property("searchTerm",
				JsonSchemaBuilder.string(mapper)
						.description("The text to search for within function names."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("searchTerm");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String searchTerm = getRequiredStringArgument(args, "searchTerm").toLowerCase();
			String cursor = getOptionalStringArgument(args, "cursor").orElse(null);
			final String finalCursor = cursor; // For lambda capture

			List<Function> limitedFunctions = StreamSupport
					.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
					.filter(f -> f.getName().toLowerCase().contains(searchTerm))
					.sorted(Comparator.comparing(Function::getName))
					.dropWhile(f -> finalCursor != null && f.getName().compareTo(finalCursor) <= 0)
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
				nextCursor = pageResults.get(pageResults.size() - 1).getName();
			}

			PaginatedResult<GhidraFunctionsToolInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return createSuccessResult(paginatedResult);

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}

}
