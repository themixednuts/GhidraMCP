package com.themixednuts.tools.memory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Search Memory", category = ToolCategory.MEMORY, description = "Searches program memory for a pattern (hex bytes or string).", mcpName = "search_memory", mcpDescription = "Searches memory within an optional address range for a sequence of bytes (given as hex) or a string.")
public class GhidraSearchMemoryTool implements IGhidraMcpSpecification {

	private static final String ARG_PATTERN_HEX = "patternHex";
	private static final String ARG_PATTERN_STRING = "patternString";
	private static final String ARG_START_ADDRESS = "startAddress";
	private static final String ARG_END_ADDRESS = "endAddress";

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		Optional<String> schemaStringOpt = parseSchema(schema());
		if (schemaStringOpt.isEmpty()) {
			return null;
		}
		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaStringOpt.get()),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_PATTERN_HEX,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Hex string representation of bytes to search for (e.g., 'C390'). Either this or patternString must be provided.")
						.pattern("^[0-9a-fA-F]*$")); // Allow empty for validation check
		schemaRoot.property(ARG_PATTERN_STRING,
				JsonSchemaBuilder.string(mapper)
						.description("String to search for (UTF-8 encoded). Either this or patternHex must be provided."));
		schemaRoot.property(ARG_START_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("Optional starting address for the search range.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_END_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("Optional ending address for the search range.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		// Removed alignment as findBytes doesn't directly support it easily

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		// Validation for patternHex XOR patternString done in execute

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			Optional<String> patternHexOpt = getOptionalStringArgument(args, ARG_PATTERN_HEX);
			Optional<String> patternStringOpt = getOptionalStringArgument(args, ARG_PATTERN_STRING);
			Optional<String> startAddressOpt = getOptionalStringArgument(args, ARG_START_ADDRESS);
			Optional<String> endAddressOpt = getOptionalStringArgument(args, ARG_END_ADDRESS);
			String cursorStr = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);

			// Validate exactly one pattern type is provided
			if (patternHexOpt.isEmpty() && patternStringOpt.isEmpty()) {
				return createErrorResult("Either patternHex or patternString must be provided.");
			}
			if (patternHexOpt.isPresent() && patternStringOpt.isPresent()) {
				return createErrorResult("Provide either patternHex or patternString, not both.");
			}

			byte[] searchBytes;
			try {
				if (patternHexOpt.isPresent()) {
					String hex = patternHexOpt.get();
					if (hex.isEmpty() || hex.length() % 2 != 0) {
						return createErrorResult("Invalid patternHex: Must be non-empty and have an even number of characters.");
					}
					searchBytes = HexFormat.of().parseHex(hex);
				} else { // patternStringOpt must be present
					searchBytes = patternStringOpt.get().getBytes(StandardCharsets.UTF_8);
				}
			} catch (IllegalArgumentException e) {
				return createErrorResult("Invalid patternHex format: " + e.getMessage());
			}

			if (searchBytes.length == 0) {
				return createErrorResult("Search pattern cannot be empty.");
			}

			Memory memory = program.getMemory();
			Address start = startAddressOpt.map(program.getAddressFactory()::getAddress).orElse(memory.getMinAddress());
			Address end = endAddressOpt.map(program.getAddressFactory()::getAddress).orElse(memory.getMaxAddress());

			if (start == null || end == null || start.compareTo(end) > 0) {
				return createErrorResult("Invalid start/end address range.");
			}

			Address cursorAddr = null;
			if (cursorStr != null) {
				cursorAddr = program.getAddressFactory().getAddress(cursorStr);
				if (cursorAddr == null) {
					return createErrorResult("Invalid cursor address format: " + cursorStr);
				}
				// Adjust start address based on cursor for next page
				if (cursorAddr.compareTo(start) >= 0 && cursorAddr.compareTo(end) <= 0) {
					start = cursorAddr.add(1); // Start search *after* the cursor address
				}
			}
			final Address searchStartAddr = start; // Final for lambda

			// Use a task monitor
			GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());

			// Run search in background via Mono.fromCallable
			return Mono.fromCallable(() -> {
				List<Address> matches = new ArrayList<>();
				Address currentSearchStart = searchStartAddr;
				// Memory object is available from the outer scope (program.getMemory())
				// Memory memory = program.getMemory(); // REMOVED REDECLARATION

				while (currentSearchStart != null && !monitor.isCancelled()) {
					// Use memory.findBytes(Address startAddress, byte[] bytes, byte[] mask, boolean
					// forward, TaskMonitor monitor)
					// Pass null for the mask if we don't need one.
					Address foundAddr = memory.findBytes(currentSearchStart, searchBytes, null, true, monitor);

					if (foundAddr != null) {
						// Ensure the found address is within the requested range (if specified)
						if (foundAddr.compareTo(end) > 0) {
							foundAddr = null; // Treat as not found if outside the end boundary
						}
					}

					if (foundAddr != null) {
						matches.add(foundAddr);
						// Advance start address for next search iteration
						try {
							currentSearchStart = foundAddr.addNoWrap(1); // Prevent wrapping
						} catch (ghidra.program.model.address.AddressOverflowException e) {
							currentSearchStart = null; // Stop if overflow
						}
						// Redundant check as findBytes should handle bounds, but keep for safety?
						// if (currentSearchStart != null && currentSearchStart.compareTo(end) > 0) {
						// currentSearchStart = null; // Stop if past end address
						// }
					} else {
						currentSearchStart = null; // No more matches found
					}
				}

				// Limit results for pagination (do this *after* finding all matches within
				// range for simplicity here)
				List<String> limitedMatchStrings = matches.stream()
						.sorted(Comparator.naturalOrder()) // Addresses are naturally comparable
						// No need for dropWhile here as search started after cursor
						.limit(DEFAULT_PAGE_LIMIT + 1)
						.map(Address::toString)
						.collect(Collectors.toList());

				boolean hasMore = limitedMatchStrings.size() > DEFAULT_PAGE_LIMIT;
				List<String> pageResults = limitedMatchStrings.subList(0,
						Math.min(limitedMatchStrings.size(), DEFAULT_PAGE_LIMIT));

				String nextCursor = null;
				if (hasMore && !pageResults.isEmpty()) {
					nextCursor = pageResults.get(pageResults.size() - 1);
				}

				return new PaginatedResult<>(pageResults, nextCursor);

			}).flatMap(this::createSuccessResult) // Convert PaginatedResult to CallToolResult
					.onErrorResume(e -> createErrorResult("Error during memory search: " + e.getMessage()));

		}).onErrorResume(e -> createErrorResult(e)); // Handle program loading errors, etc.
	}
}