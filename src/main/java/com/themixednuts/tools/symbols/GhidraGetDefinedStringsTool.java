package com.themixednuts.tools.symbols;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Optional;
import java.util.Comparator;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.DataInfo;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(key = "Get Defined Strings", category = ToolCategory.SYMBOLS, description = "Enable the MCP tool to get the defined strings in the project.", mcpName = "get_defined_strings", mcpDescription = "Retrieve a list of defined string data items from the specified program, including their label, address, value, and type. Supports pagination and optional minimum length filtering.")
public class GhidraGetDefinedStringsTool implements IGhidraMcpSpecification {
	private static final int PAGE_SIZE = 100; // Number of strings per page

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
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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
		schemaRoot.property(IGhidraMcpSpecification.ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(IGhidraMcpSpecification.ARG_LENGTH,
				JsonSchemaBuilder.integer(mapper)
						.description("Optional minimum length for strings to be included.")
						.minimum(1));
		schemaRoot.property("filter",
				JsonSchemaBuilder.string(mapper)
						.description("Optional filter to apply to the strings."));

		schemaRoot.requiredProperty(IGhidraMcpSpecification.ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args,
			PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			Listing listing = program.getListing();
			Optional<String> cursorOpt = getOptionalStringArgument(args, IGhidraMcpSpecification.ARG_CURSOR);
			Address cursor = null;
			if (cursorOpt.isPresent()) {
				cursor = program.getAddressFactory().getAddress(cursorOpt.get());
			}
			final Address finalCursor = cursor;

			Optional<String> filterOpt = getOptionalStringArgument(args, "filter");
			Optional<Integer> minLengthOpt = getOptionalIntArgument(args, IGhidraMcpSpecification.ARG_LENGTH);

			List<Data> limitedData = StreamSupport.stream(listing.getDefinedData(true).spliterator(), false)
					.filter(Data::hasStringValue)
					.filter(data -> minLengthOpt.isEmpty() || data.getDefaultValueRepresentation().length() >= minLengthOpt.get())
					.filter(data -> filterOpt.isEmpty()
							|| data.getDefaultValueRepresentation().toLowerCase().contains(filterOpt.get().toLowerCase()))
					.sorted(Comparator.comparing(Data::getAddress))
					.dropWhile(data -> finalCursor != null && data.getAddress().compareTo(finalCursor) <= 0)
					.limit(PAGE_SIZE + 1)
					.collect(Collectors.toList());

			boolean hasMore = limitedData.size() > PAGE_SIZE;
			int actualPageSize = Math.min(limitedData.size(), PAGE_SIZE);
			List<Data> pageData = limitedData.subList(0, actualPageSize);

			List<DataInfo> pageResults = pageData.stream()
					.map(DataInfo::new)
					.collect(Collectors.toList());

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getAddress().toString();
			}

			PaginatedResult<DataInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return createSuccessResult(paginatedResult);
		}).onErrorResume(e -> createErrorResult(e));
	}

}
