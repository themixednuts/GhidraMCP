package com.themixednuts.tools.memory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Swing;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.util.exception.CancelledException;

@GhidraMcpTool(name = "Search Memory", category = ToolCategory.MEMORY, description = "Searches program memory for byte sequences or strings.", mcpName = "search_memory", mcpDescription = """
		<use_case>Search program memory for specific byte patterns or ASCII strings with optional address range filtering and pagination support.</use_case>

		<important_notes>
		• Supports two search types: "bytes" (hex patterns) and "string" (ASCII text)
		• Hex patterns must have even number of characters (case-insensitive)
		• Large memory ranges may take significant time to search
		• Results are paginated with 50 matches per page by default
		• Provides 16-byte preview context around each match
		</important_notes>

		<example>
		{
		  "fileName": "malware.exe",
		  "searchValue": "deadbeef",
		  "searchType": "bytes",
		  "startAddress": "0x401000",
		  "endAddress": "0x402000"
		}
		// Searches for hex pattern "deadbeef" in specified range
		</example>

		<workflow>
		1. Validate search parameters and address range
		2. Convert search value to bytes (hex parsing or ASCII encoding)
		3. Scan memory within specified range for pattern matches
		4. Return paginated results with address and preview context
		</workflow>
		""")
public class GhidraSearchMemoryTool implements IGhidraMcpSpecification {

	public static final String ARG_SEARCH_VALUE = "searchValue";
	public static final String ARG_SEARCH_TYPE = "searchType";
	public static final String ARG_START_ADDRESS = "startAddress";
	public static final String ARG_END_ADDRESS = "endAddress";
	public static final String ARG_CURSOR = "cursor";
	private static final int PREVIEW_BYTES = 16;

	private static class SearchResult {
		public String address;
		public String preview;

		public SearchResult(String address, String preview) {
			this.address = address;
			this.preview = preview;
		}
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_SEARCH_VALUE,
				JsonSchemaBuilder.string(mapper)
						.description("The value to search for (hex for bytes, text for string)."));
		schemaRoot.property(ARG_SEARCH_TYPE,
				JsonSchemaBuilder.string(mapper)
						.description("Type of search: 'bytes' or 'string'.")
						.enumValues("bytes", "string"));
		schemaRoot.property(ARG_START_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("Optional start address for search range (e.g., '0x1004000'). Defaults to program start.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_END_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("Optional end address for search range (e.g., '0x1005000'). Defaults to program end.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_CURSOR,
				JsonSchemaBuilder.string(mapper)
						.description("Optional cursor for pagination. Use the 'next' cursor from previous results.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_SEARCH_VALUE)
				.requiredProperty(ARG_SEARCH_TYPE);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool)
				.flatMap(program -> Mono.fromCallable(() -> {
					String searchValue = getRequiredStringArgument(args, ARG_SEARCH_VALUE);
					String searchType = getRequiredStringArgument(args, ARG_SEARCH_TYPE);
					String cursorStr = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);

					// Validate search type
					if (!"bytes".equals(searchType) && !"string".equals(searchType)) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid search type")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"search type validation",
										Map.of(ARG_SEARCH_TYPE, searchType),
										Map.of(ARG_SEARCH_TYPE, searchType),
										Map.of("expectedValues", List.of("bytes", "string"), "providedValue", searchType)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use valid search type",
												"Specify either 'bytes' or 'string' for search type",
												List.of("bytes", "string"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					// Parse and validate addresses
					AddressFactory addrFactory = program.getAddressFactory();
					Address startAddr;
					Address endAddr;

					try {
						startAddr = getOptionalStringArgument(args, ARG_START_ADDRESS)
								.map(addrFactory::getAddress).orElse(program.getMinAddress());
						endAddr = getOptionalStringArgument(args, ARG_END_ADDRESS)
								.map(addrFactory::getAddress).orElse(program.getMaxAddress());
					} catch (Exception e) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
								.message("Failed to parse address range: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"address range parsing",
										Map.of(ARG_START_ADDRESS, getOptionalStringArgument(args, ARG_START_ADDRESS).orElse("(default)"),
												ARG_END_ADDRESS, getOptionalStringArgument(args, ARG_END_ADDRESS).orElse("(default)")),
										Map.of("parseError", e.getMessage()),
										Map.of("startAddress", getOptionalStringArgument(args, ARG_START_ADDRESS).orElse("(default)"),
												"endAddress", getOptionalStringArgument(args, ARG_END_ADDRESS).orElse("(default)"))))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use valid hexadecimal address format",
												"Provide addresses as hexadecimal values",
												List.of("0x401000", "401000", "0x00401000"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					if (startAddr == null || endAddr == null || startAddr.compareTo(endAddr) > 0) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid address range")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"address range validation",
										Map.of(ARG_START_ADDRESS, getOptionalStringArgument(args, ARG_START_ADDRESS).orElse("(default)"),
												ARG_END_ADDRESS, getOptionalStringArgument(args, ARG_END_ADDRESS).orElse("(default)")),
										Map.of("startAddress", startAddr != null ? startAddr.toString() : "null",
												"endAddress", endAddr != null ? endAddr.toString() : "null"),
										Map.of("validRange", "start address must be <= end address")))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Ensure start address is before or equal to end address",
												"Verify address range is valid",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					Address initialSearchAddr;
					try {
						initialSearchAddr = calculateInitialSearchAddr(program, startAddr, cursorStr);
					} catch (AddressOverflowException e) {
						return new PaginatedResult<>(new ArrayList<>(), null);
					}

					List<SearchResult> foundItems;
					try {
						foundItems = performSearchLogic(program, initialSearchAddr, endAddr, searchValue, searchType, ex);
					} catch (Exception e) {
						GhidraMcpError error = GhidraMcpError.execution()
								.errorCode(GhidraMcpError.ErrorCode.ANALYSIS_FAILED)
								.message("Search operation failed: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"memory search execution",
										Map.of(ARG_SEARCH_VALUE, searchValue, ARG_SEARCH_TYPE, searchType),
										Map.of("searchError", e.getMessage()),
										Map.of("searchValue", searchValue, "searchType", searchType)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Verify search parameters and try again",
												"Check search value format and address range",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					boolean hasMore = foundItems.size() > DEFAULT_PAGE_LIMIT;
					List<SearchResult> pageResults = foundItems.subList(0, Math.min(foundItems.size(), DEFAULT_PAGE_LIMIT));
					String nextCursor = null;
					if (hasMore && !pageResults.isEmpty()) {
						nextCursor = pageResults.get(pageResults.size() - 1).address;
					}

					return new PaginatedResult<>(pageResults, nextCursor);
				}));
	}

	private Address calculateInitialSearchAddr(ghidra.program.model.listing.Program program, Address startAddr,
			String cursorStr) throws AddressOverflowException, GhidraMcpException {
		if (cursorStr == null) {
			return startAddr;
		}
		AddressFactory addrFactory = program.getAddressFactory();
		Address cursorAddr = addrFactory.getAddress(cursorStr);
		if (cursorAddr == null) {
			GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
					.message("Invalid cursor format: " + cursorStr)
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"cursor parsing",
							Map.of(ARG_CURSOR, cursorStr),
							Map.of("cursorValue", cursorStr),
							Map.of("expectedFormat", "hexadecimal address", "providedValue", cursorStr)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Use valid hexadecimal address format for cursor",
									"Provide cursor as hexadecimal value from previous result",
									List.of("0x401000", "401000"),
									null)))
					.build();
			throw new GhidraMcpException(error);
		}
		Address searchStartAddr = cursorAddr.addNoWrap(1);

		if (searchStartAddr.compareTo(startAddr) < 0) {
			searchStartAddr = startAddr;
		}
		return searchStartAddr;
	}

	private List<SearchResult> performSearchLogic(ghidra.program.model.listing.Program program, Address initialSearchAddr,
			Address finalEndAddr, String searchValue, String searchType, McpAsyncServerExchange ex)
			throws Exception {

		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		TaskMonitor monitor = new GhidraMcpTaskMonitor(ex, "Search Memory");
		List<SearchResult> foundItems = new ArrayList<>();
		Memory memory = program.getMemory();
		Address currentAddr = initialSearchAddr;

		// Parse search bytes based on type
		byte[] searchBytes;
		try {
			if ("bytes".equals(searchType)) {
				// Validate hex format
				if (searchValue.length() % 2 != 0) {
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
							.message("Invalid hex format: odd number of characters")
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"hex format validation",
									Map.of(ARG_SEARCH_VALUE, searchValue),
									Map.of(ARG_SEARCH_VALUE, searchValue),
									Map.of("expectedFormat", "even number of hex characters", "providedLength", searchValue.length())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Use even number of hex characters",
											"Provide hex string with even length",
											List.of("deadbeef", "41424344", "90"),
											null)))
							.build();
					throw new GhidraMcpException(error);
				}
				searchBytes = java.util.HexFormat.of().parseHex(searchValue);
			} else { // "string"
				searchBytes = searchValue.getBytes(StandardCharsets.US_ASCII);
			}
		} catch (IllegalArgumentException e) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
					.message("Invalid search value format: " + e.getMessage())
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"search value parsing",
							Map.of(ARG_SEARCH_VALUE, searchValue, ARG_SEARCH_TYPE, searchType),
							Map.of("parseError", e.getMessage()),
							Map.of("searchValue", searchValue, "searchType", searchType)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Fix search value format",
									searchType.equals("bytes") ? "Use valid hexadecimal characters only" : "Use valid ASCII text",
									searchType.equals("bytes") ? List.of("deadbeef", "41424344") : List.of("password", "http://"),
									null)))
					.build();
			throw new GhidraMcpException(error);
		}

		if (searchBytes.length == 0) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
					.message("Search value cannot be empty")
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"search value validation",
							Map.of(ARG_SEARCH_VALUE, searchValue),
							Map.of(ARG_SEARCH_VALUE, searchValue),
							Map.of("searchValueLength", 0)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Provide non-empty search value",
									"Specify bytes or string to search for",
									List.of("deadbeef", "password", "41424344"),
									null)))
					.build();
			throw new GhidraMcpException(error);
		}

		final AtomicReference<Address> foundAddrRef = new AtomicReference<>();
		final AtomicReference<Throwable> exceptionRef = new AtomicReference<>();

		// Main search loop with proper advancement
		while (currentAddr != null && currentAddr.compareTo(finalEndAddr) <= 0 && !monitor.isCancelled()) {
			final Address searchStart = currentAddr;
			foundAddrRef.set(null);
			exceptionRef.set(null);

			// Execute findBytes on EDT
			Swing.runNow(() -> {
				try {
					foundAddrRef.set(memory.findBytes(searchStart, searchBytes, null, true, monitor));
				} catch (Throwable t) {
					exceptionRef.set(t);
				}
			});

			// Check for exceptions from EDT execution
			Throwable capturedEx = exceptionRef.get();
			if (capturedEx != null) {
				if (capturedEx instanceof CancelledException) {
					// Search was cancelled - return partial results
					break;
				}
				if (capturedEx instanceof MemoryAccessException) {
					GhidraMcpError error = GhidraMcpError.execution()
							.errorCode(GhidraMcpError.ErrorCode.MEMORY_ACCESS_FAILED)
							.message("Memory access error during search: " + capturedEx.getMessage())
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"memory search access",
									Map.of("currentAddress", currentAddr.toString()),
									Map.of("memoryError", capturedEx.getMessage()),
									Map.of("searchPattern", searchType, "resultsFound", foundItems.size())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Try a different address range",
											"Search in mapped memory regions only",
											null,
											null)))
							.build();
					throw new GhidraMcpException(error);
				}
				if (capturedEx instanceof RuntimeException)
					throw (RuntimeException) capturedEx;
				throw new RuntimeException("Error during memory search: " + capturedEx.getMessage(), capturedEx);
			}

			Address foundAddr = foundAddrRef.get();
			if (foundAddr == null || foundAddr.compareTo(finalEndAddr) > 0)
				break;

			// Add the result
			foundItems.add(createSearchResult(memory, foundAddr));
			if (foundItems.size() > DEFAULT_PAGE_LIMIT)
				break;

			// CRITICAL FIX: Advance by pattern length, not just 1 byte
			// This prevents infinite loops when searching for patterns that exist at
			// consecutive addresses
			try {
				currentAddr = foundAddr.addNoWrap(Math.max(1, searchBytes.length));
			} catch (AddressOverflowException e) {
				currentAddr = null; // End of address space reached
			}
		}

		return foundItems;
	}

	private SearchResult createSearchResult(Memory memory, Address address) {
		String addressStr = address.toString();
		String previewStr = "<error reading preview>";
		try {
			byte[] previewBytes = new byte[PREVIEW_BYTES];
			int bytesRead = memory.getBytes(address, previewBytes);
			if (bytesRead > 0) {
				previewStr = java.util.HexFormat.of().formatHex(previewBytes, 0, bytesRead);
			} else {
				previewStr = "<no data>";
			}
		} catch (Exception e) {
			// Keep default error message for preview failures
		}
		return new SearchResult(addressStr, previewStr);
	}
}