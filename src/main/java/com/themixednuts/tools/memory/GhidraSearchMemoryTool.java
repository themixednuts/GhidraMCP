package com.themixednuts.tools.memory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
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
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Search Memory", category = ToolCategory.MEMORY, description = "Searches program memory for byte sequences or strings.", mcpName = "search_memory", mcpDescription = "Search memory for a byte sequence or string.")
public class GhidraSearchMemoryTool implements IGhidraMcpSpecification {

	public static final String ARG_SEARCH_VALUE = "searchValue";
	public static final String ARG_SEARCH_TYPE = "searchType";
	public static final String ARG_START_ADDRESS = "startAddress";
	public static final String ARG_END_ADDRESS = "endAddress";
	private static final int PREVIEW_BYTES = 16;

	private static class SearchResult {
		public String address;
		@SuppressWarnings("unused")
		public String preview;

		public SearchResult(String address, String preview) {
			this.address = address;
			this.preview = preview;
		}
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_SEARCH_VALUE, JsonSchemaBuilder.string(mapper)
				.description("The value to search for (hex for bytes, text for string)."));
		schemaRoot.property(ARG_SEARCH_TYPE, JsonSchemaBuilder.string(mapper)
				.description("Type of search: 'bytes' or 'string'.")
				.enumValues("bytes", "string"));
		schemaRoot.property(ARG_START_ADDRESS, JsonSchemaBuilder.string(mapper)
				.description("Optional start address for search range (e.g., '0x1004000'). Defaults to program start.")
				.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_END_ADDRESS, JsonSchemaBuilder.string(mapper)
				.description("Optional end address for search range (e.g., '0x1005000'). Defaults to program end.")
				.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_SEARCH_VALUE)
				.requiredProperty(ARG_SEARCH_TYPE);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> Mono.fromCallable(() -> {
					String searchValue = getRequiredStringArgument(args, ARG_SEARCH_VALUE);
					String searchType = getRequiredStringArgument(args, ARG_SEARCH_TYPE);
					String cursorStr = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);

					AddressFactory addrFactory = program.getAddressFactory();
					Address startAddr = getOptionalStringArgument(args, ARG_START_ADDRESS)
							.map(addrFactory::getAddress).orElse(program.getMinAddress());
					Address endAddr = getOptionalStringArgument(args, ARG_END_ADDRESS)
							.map(addrFactory::getAddress).orElse(program.getMaxAddress());

					if (startAddr == null || endAddr == null || startAddr.compareTo(endAddr) > 0) {
						throw new IllegalArgumentException("Invalid start/end address range.");
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
					} catch (MemoryAccessException e) {
						throw new RuntimeException("Memory access error during search: " + e.getMessage(), e);
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
			String cursorStr)
			throws AddressOverflowException, IllegalArgumentException {
		if (cursorStr == null) {
			return startAddr;
		}
		AddressFactory addrFactory = program.getAddressFactory();
		Address cursorAddr = addrFactory.getAddress(cursorStr);
		if (cursorAddr == null) {
			throw new IllegalArgumentException("Invalid cursor format: " + cursorStr);
		}
		Address searchStartAddr = cursorAddr.addNoWrap(1);

		if (searchStartAddr.compareTo(startAddr) < 0) {
			searchStartAddr = startAddr;
		}
		return searchStartAddr;
	}

	private List<SearchResult> performSearchLogic(ghidra.program.model.listing.Program program, Address initialSearchAddr,
			Address finalEndAddr, String searchValue, String searchType, McpAsyncServerExchange ex)
			throws MemoryAccessException, IllegalArgumentException {

		TaskMonitor monitor = new GhidraMcpTaskMonitor(ex, "Search Memory");
		List<SearchResult> foundItems = new ArrayList<>();
		Memory memory = program.getMemory();
		Address currentAddr = initialSearchAddr;

		if ("bytes".equals(searchType)) {
			byte[] searchBytes = java.util.HexFormat.of().parseHex(searchValue);
			while (currentAddr != null && currentAddr.compareTo(finalEndAddr) <= 0) {
				Address foundAddr = memory.findBytes(currentAddr, searchBytes, null, true, monitor);
				if (foundAddr == null || foundAddr.compareTo(finalEndAddr) > 0)
					break;
				foundItems.add(createSearchResult(memory, foundAddr));
				if (foundItems.size() > DEFAULT_PAGE_LIMIT)
					break;
				try {
					currentAddr = foundAddr.addNoWrap(1);
				} catch (AddressOverflowException e) {
					currentAddr = null;
				}
			}
		} else if ("string".equals(searchType)) {
			byte[] searchBytes = searchValue.getBytes(StandardCharsets.US_ASCII);
			while (currentAddr != null && currentAddr.compareTo(finalEndAddr) <= 0) {
				Address foundAddr = memory.findBytes(currentAddr, searchBytes, null, true, monitor);
				if (foundAddr == null || foundAddr.compareTo(finalEndAddr) > 0)
					break;
				foundItems.add(createSearchResult(memory, foundAddr));
				if (foundItems.size() > DEFAULT_PAGE_LIMIT)
					break;
				try {
					currentAddr = foundAddr.addNoWrap(1);
				} catch (AddressOverflowException e) {
					currentAddr = null;
				}
			}
		} else {
			throw new IllegalArgumentException("Invalid searchType: " + searchType);
		}

		return foundItems;
	}

	private SearchResult createSearchResult(Memory memory, Address address) {
		String addressStr = address.toString();
		String previewStr = "<error reading preview>";
		try {
			byte[] previewBytes = new byte[PREVIEW_BYTES];
			int bytesRead = memory.getBytes(address, previewBytes);
			previewStr = java.util.HexFormat.of().formatHex(previewBytes, 0, bytesRead);
		} catch (Exception e) {
			// Ignore preview errors
		}
		return new SearchResult(addressStr, previewStr);
	}
}