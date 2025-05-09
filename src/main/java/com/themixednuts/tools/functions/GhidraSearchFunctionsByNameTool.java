package com.themixednuts.tools.functions;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Comparator;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.address.Address;

@GhidraMcpTool(name = "Search Functions by Name", category = ToolCategory.FUNCTIONS, description = "Searches for functions whose names contain a given substring.", mcpName = "search_functions_by_name", mcpDescription = "Returns a paginated list of functions whose names match a search query.")
public class GhidraSearchFunctionsByNameTool implements IGhidraMcpSpecification {

	public static final int DEFAULT_PAGE_LIMIT = 10;

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."),
				true);
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function to search for."),
				true);
		schemaRoot.property(ARG_CURSOR,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional cursor for pagination (typically the address of the last item from the previous page)."));

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String nameStr = getRequiredStringArgument(args, ARG_NAME);

			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
			Address cursorAddr = null;
			if (cursorOpt.isPresent()) {
				try {
					cursorAddr = program.getAddressFactory().getAddress(cursorOpt.get());
				} catch (Exception e) {
					throw new IllegalArgumentException("Invalid cursor format: " + cursorOpt.get());
				}
			}
			final Address finalCursorAddr = cursorAddr;

			FunctionManager functionManager = program.getFunctionManager();
			List<FunctionInfo> collectedItems = StreamSupport
					.stream(functionManager.getFunctions(true).spliterator(), false)
					.filter(f -> f.getName().toLowerCase().contains(nameStr.toLowerCase()))
					.sorted(Comparator.comparing(Function::getEntryPoint))
					.dropWhile(item -> finalCursorAddr != null && item.getEntryPoint().compareTo(finalCursorAddr) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.map(FunctionInfo::new)
					.collect(Collectors.toList());

			boolean hasMore = collectedItems.size() > DEFAULT_PAGE_LIMIT;
			List<FunctionInfo> resultsForPage = collectedItems.subList(0,
					Math.min(collectedItems.size(), DEFAULT_PAGE_LIMIT));
			String nextCursor = null;
			if (hasMore && !resultsForPage.isEmpty()) {
				nextCursor = resultsForPage.get(resultsForPage.size() - 1).getAddress();
			}

			return new PaginatedResult<>(resultsForPage, nextCursor);
		});
	}

}
