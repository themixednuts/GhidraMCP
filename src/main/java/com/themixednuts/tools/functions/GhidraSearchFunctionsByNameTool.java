package com.themixednuts.tools.functions;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Comparator;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
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

@GhidraMcpTool(name = "Search Functions by Name", category = ToolCategory.FUNCTIONS, description = "Searches for functions whose names contain a given substring.", mcpName = "search_functions_by_name", mcpDescription = "Search for functions whose names contain a specified substring with pagination support. Case-insensitive matching returns complete function information.")
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
						.description("The substring to search for in function names (case-insensitive)."),
				true);
		schemaRoot.property(ARG_CURSOR,
				JsonSchemaBuilder.string(mapper)
						.description("Optional cursor for pagination (address from previous page's nextCursor).")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).map(program -> {
			String nameStr = getRequiredStringArgument(args, ARG_NAME);

			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
			Address cursorAddr = null;

			// Handle cursor address parsing with structured error
			if (cursorOpt.isPresent()) {
				try {
					cursorAddr = program.getAddressFactory().getAddress(cursorOpt.get());
					if (cursorAddr == null) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid cursor address format")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"cursor address parsing",
										args,
										Map.of(ARG_CURSOR, cursorOpt.get()),
										Map.of("expectedFormat", "hexadecimal address", "providedValue", cursorOpt.get())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use valid hexadecimal address format",
												"Provide cursor as hexadecimal address",
												List.of("0x401000", "401000", "0x00401000"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
				} catch (Exception e) {
					if (e instanceof GhidraMcpException) {
						throw e; // Re-throw our structured error
					}
					// Handle other address parsing exceptions
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
							.message("Failed to parse cursor address: " + e.getMessage())
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"cursor address parsing",
									args,
									Map.of(ARG_CURSOR, cursorOpt.get()),
									Map.of("parseError", e.getMessage(), "providedValue", cursorOpt.get())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Use valid address format for the current program",
											"Ensure cursor address exists in the program's address space",
											List.of("0x401000", "401000"),
											null)))
							.build();
					throw new GhidraMcpException(error);
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
