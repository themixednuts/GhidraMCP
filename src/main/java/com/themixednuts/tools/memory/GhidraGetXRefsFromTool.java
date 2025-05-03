package com.themixednuts.tools.memory;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraReferenceInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get XRefs From", category = "Memory", description = "Find cross-references FROM a specific address.", mcpName = "get_xrefs_from_address", mcpDescription = "Returns a paginated list of addresses referenced by the instruction or data at the specified source address.")
public class GhidraGetXRefsFromTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null; // Signal failure
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schema),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public ObjectNode schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(IGhidraMcpSpecification.mapper)
						.description("The name of the program file."));
		schemaRoot.property("address",
				JsonSchemaBuilder.string(IGhidraMcpSpecification.mapper)
						.description("The source address to find cross-references from (e.g., '0x1004010')."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("address");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String addressStr = getRequiredStringArgument(args, "address");
			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				return createErrorResult("Invalid address provided: " + addressStr);
			}
			ReferenceManager refManager = program.getReferenceManager();
			Reference[] refsFrom = refManager.getReferencesFrom(addr);

			String cursor = getOptionalStringArgument(args, "cursor").orElse(null);
			final String finalCursor = cursor;

			List<GhidraReferenceInfo> limitedRefs = Arrays.stream(refsFrom)
					.sorted(Comparator.comparing(ref -> ref.getToAddress().toString()))
					.dropWhile(ref -> finalCursor != null && ref.getToAddress().toString().compareTo(finalCursor) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.map(GhidraReferenceInfo::new)
					.collect(Collectors.toList());

			boolean hasMore = limitedRefs.size() > DEFAULT_PAGE_LIMIT;
			List<GhidraReferenceInfo> pageResults = limitedRefs.subList(0,
					Math.min(limitedRefs.size(), DEFAULT_PAGE_LIMIT));

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getToAddress();
			}

			PaginatedResult<GhidraReferenceInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return createSuccessResult(paginatedResult);

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}

}
