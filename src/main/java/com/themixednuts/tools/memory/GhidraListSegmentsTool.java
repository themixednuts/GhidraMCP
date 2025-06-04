package com.themixednuts.tools.memory;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.MemoryBlockInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import com.themixednuts.tools.ToolCategory;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Memory Segments", category = ToolCategory.MEMORY, description = "Lists all memory segments (blocks) defined in the program.", mcpName = "list_memory_segments", mcpDescription = "Retrieve a paginated list of all memory segments/blocks in the program. Returns details about each memory block including start address, size, permissions, and type. Results are sorted by start address and support cursor-based pagination.")
public class GhidraListSegmentsTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

			MemoryBlock[] blocks = program.getMemory().getBlocks();
			List<MemoryBlockInfo> allSegments = Arrays.stream(blocks)
					.map(MemoryBlockInfo::new)
					.sorted(Comparator.comparing(MemoryBlockInfo::getStartAddress))
					.collect(Collectors.toList());

			// Pagination logic
			Address cursorAddr = null;
			if (cursorOpt.isPresent()) {
				try {
					cursorAddr = program.getAddressFactory().getAddress(cursorOpt.get());
					if (cursorAddr == null) {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid cursor address format: " + cursorOpt.get())
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"cursor parsing",
										Map.of(ARG_CURSOR, cursorOpt.get()),
										Map.of("cursorValue", cursorOpt.get()),
										Map.of("expectedFormat", "hexadecimal address", "providedValue", cursorOpt.get())))
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
				} catch (Exception e) {
					GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
							.message("Failed to parse cursor address: " + cursorOpt.get() + " - " + e.getMessage())
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"cursor parsing",
									Map.of(ARG_CURSOR, cursorOpt.get()),
									Map.of("cursorValue", cursorOpt.get(), "parseError", e.getMessage()),
									Map.of("expectedFormat", "hexadecimal address", "providedValue", cursorOpt.get())))
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
			}
			final Address finalCursorAddr = cursorAddr;

			List<MemoryBlockInfo> paginatedSegments = allSegments.stream()
					.dropWhile(segment -> finalCursorAddr != null &&
							program.getAddressFactory().getAddress(segment.getStartAddress()).compareTo(finalCursorAddr) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			boolean hasMore = paginatedSegments.size() > DEFAULT_PAGE_LIMIT;
			List<MemoryBlockInfo> resultsForPage = paginatedSegments.subList(0,
					Math.min(paginatedSegments.size(), DEFAULT_PAGE_LIMIT));
			String nextCursor = null;
			if (hasMore && !resultsForPage.isEmpty()) {
				nextCursor = resultsForPage.get(resultsForPage.size() - 1).getStartAddress();
			}

			return new PaginatedResult<>(resultsForPage, nextCursor);

		});
	}
}
