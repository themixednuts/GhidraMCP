package com.themixednuts.tools.symbols;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Optional;
import java.util.Comparator;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.DataInfo;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Get Defined Strings", category = ToolCategory.SYMBOLS, description = "Enable the MCP tool to get the defined strings in the project.", mcpName = "get_defined_strings", mcpDescription = "Get analyzed string data from a Ghidra program. Faster than memory search for known strings but only returns strings identified by the decompiler. If expected strings are missing, use search_memory with type 'string' for comprehensive byte-level scanning.")
public class GhidraGetDefinedStringsTool implements IGhidraMcpSpecification {
	private static final int PAGE_SIZE = 100; // Number of strings per page

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_LENGTH,
				JsonSchemaBuilder.integer(mapper)
						.description("Optional minimum length for strings to be included.")
						.minimum(1));
		schemaRoot.property(ARG_FILTER,
				JsonSchemaBuilder.string(mapper)
						.description("Optional filter to apply to the strings."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			Listing listing = program.getListing();
			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
			Address cursor = null;
			if (cursorOpt.isPresent()) {
				try {
					cursor = program.getAddressFactory().getAddress(cursorOpt.get());
					if (cursor == null) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
								.message("Invalid cursor address format")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"cursor address parsing",
										args,
										Map.of(ARG_CURSOR, cursorOpt.get()),
										Map.of("isValidFormat", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use valid hexadecimal address format for cursor",
												"Provide cursor address in hexadecimal format",
												List.of(
														"\"" + ARG_CURSOR + "\": \"0x401000\"",
														"\"" + ARG_CURSOR + "\": \"401000\""),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
				} catch (Exception e) {
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
							.message("Failed to parse cursor address: " + e.getMessage())
							.context(new GhidraMcpError.ErrorContext(
									getMcpName(),
									"cursor address parsing",
									args,
									Map.of(ARG_CURSOR, cursorOpt.get()),
									Map.of("parseException", e.getClass().getSimpleName())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Use valid hexadecimal address format for cursor",
											"Provide cursor address in correct hexadecimal format",
											List.of(
													"\"" + ARG_CURSOR + "\": \"0x401000\"",
													"\"" + ARG_CURSOR + "\": \"401000\""),
											null)))
							.build();
					throw new GhidraMcpException(error);
				}
			}
			final Address finalCursor = cursor;

			Optional<String> filterOpt = getOptionalStringArgument(args, ARG_FILTER);
			Optional<Integer> minLengthOpt = getOptionalIntArgument(args, ARG_LENGTH);

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
			return paginatedResult;
		});
	}

}
