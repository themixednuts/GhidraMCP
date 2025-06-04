package com.themixednuts.tools.functions;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Comparator;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Function Names", category = ToolCategory.FUNCTIONS, description = "Lists function names in the program with optional filtering.", mcpName = "list_function_names", mcpDescription = "List all function names in a Ghidra program. Supports filtering by name substring and pagination for large programs.")
public class GhidraListFunctionNamesTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode()
				.property(ARG_FILE_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("The name of the program file."),
						true)
				.property(ARG_FILTER,
						JsonSchemaBuilder.string(mapper)
								.description("Optional case-insensitive substring filter for function names."))
				.property(ARG_CURSOR,
						JsonSchemaBuilder.string(mapper)
								.description("Optional cursor for pagination (address from previous page's nextCursor).")
								.pattern("^(0x)?[0-9a-fA-F]+$"));

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).map(program -> {
			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
			Optional<String> filterOpt = getOptionalStringArgument(args, ARG_FILTER);
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

			// Collect function names (not full FunctionInfo objects)
			List<String> collectedNames = StreamSupport
					.stream(functionManager.getFunctions(true).spliterator(), false)
					.filter(
							function -> filterOpt.map(f -> function.getName().toLowerCase().contains(f.toLowerCase())).orElse(true))
					.sorted(Comparator.comparing(Function::getEntryPoint))
					.dropWhile(function -> finalCursorAddr != null && function.getEntryPoint().compareTo(finalCursorAddr) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.map(Function::getName) // Just get the name, not full FunctionInfo
					.collect(Collectors.toList());

			boolean hasMore = collectedNames.size() > DEFAULT_PAGE_LIMIT;
			List<String> resultsForPage = collectedNames.subList(0,
					Math.min(collectedNames.size(), DEFAULT_PAGE_LIMIT));
			String nextCursor = null;

			// For nextCursor, we need to get the address of the last function
			// We'll need to look it up by name to get its address
			if (hasMore && !resultsForPage.isEmpty()) {
				String lastFunctionName = resultsForPage.get(resultsForPage.size() - 1);
				// Find the function by name to get its address for the cursor
				Function lastFunction = StreamSupport
						.stream(functionManager.getFunctions(true).spliterator(), false)
						.filter(f -> f.getName().equals(lastFunctionName))
						.findFirst()
						.orElse(null);
				if (lastFunction != null) {
					nextCursor = lastFunction.getEntryPoint().toString();
				}
			}

			return new PaginatedResult<>(resultsForPage, nextCursor);
		});
	}
}
