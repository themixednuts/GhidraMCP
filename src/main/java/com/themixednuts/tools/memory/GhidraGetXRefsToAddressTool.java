package com.themixednuts.tools.memory;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterators;
import java.util.Spliterator;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.ReferenceInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Get XRefs To Address", category = ToolCategory.MEMORY, description = "Retrieves cross-references pointing to a specific address (paginated).", mcpName = "get_xrefs_to_address", mcpDescription = "Get a paginated list of addresses that reference the given target address.")
public class GhidraGetXRefsToAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
				.description("The target address to find references to (e.g., '0x1004010').")
				.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			Address address = program.getAddressFactory().getAddress(addressStr);
			if (address == null) {
				throw new IllegalArgumentException("Invalid address format: " + addressStr);
			}
			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

			ReferenceManager refManager = program.getReferenceManager();
			ReferenceIterator refsToIter = refManager.getReferencesTo(address);

			Address cursorAddr = null;
			if (cursorOpt.isPresent()) {
				try {
					cursorAddr = program.getAddressFactory().getAddress(cursorOpt.get());
				} catch (Exception e) {
					throw new IllegalArgumentException("Invalid cursor address format: " + cursorOpt.get(), e);
				}
			}
			final Address finalCursorAddr = cursorAddr;

			List<ReferenceInfo> limitedRefs = StreamSupport.stream(
					Spliterators.spliteratorUnknownSize((java.util.Iterator<Reference>) refsToIter, Spliterator.ORDERED),
					false)
					.sorted(Comparator.comparing(Reference::getFromAddress))
					.dropWhile(ref -> finalCursorAddr != null && ref.getFromAddress().compareTo(finalCursorAddr) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.map(ReferenceInfo::new)
					.collect(Collectors.toList());

			boolean hasMore = limitedRefs.size() > DEFAULT_PAGE_LIMIT;
			List<ReferenceInfo> pageResults = limitedRefs.subList(0, Math.min(limitedRefs.size(), DEFAULT_PAGE_LIMIT));

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getFromAddress();
			}

			return new PaginatedResult<>(pageResults, nextCursor);
		});
	}

}
