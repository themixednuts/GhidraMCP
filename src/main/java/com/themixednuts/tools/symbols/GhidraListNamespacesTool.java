package com.themixednuts.tools.symbols;

import java.util.List;
import java.util.Map;
import java.util.Comparator;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.NamespaceInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(key = "List Namespaces", category = ToolCategory.SYMBOLS, description = "Enable the MCP tool to list namespaces in a file.", mcpName = "list_namespaces", mcpDescription = "List the names of all symbol namespaces (groupings for symbols like classes, functions, etc.) defined within the specified program. Supports pagination.")
public class GhidraListNamespacesTool implements IGhidraMcpSpecification {

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
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file to list namespaces from."));
		schemaRoot.requiredProperty("fileName");
		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String cursor = getOptionalStringArgument(args, "cursor").orElse(null);
			final String finalCursor = cursor;

			List<Namespace> allNamespaces = StreamSupport
					.stream(program.getSymbolTable().getSymbolIterator(true).spliterator(), false)
					.map(Symbol::getParentNamespace)
					.filter(ns -> ns != null && ns != program.getGlobalNamespace())
					.distinct()
					.collect(Collectors.toList());

			List<NamespaceInfo> limitedNamespaceInfos = allNamespaces.stream()
					.sorted(Comparator.comparing(ns -> ns.getName(true)))
					.dropWhile(ns -> finalCursor != null && ns.getName(true).compareTo(finalCursor) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.map(NamespaceInfo::new)
					.collect(Collectors.toList());

			boolean hasMore = limitedNamespaceInfos.size() > DEFAULT_PAGE_LIMIT;
			List<NamespaceInfo> pageResults = limitedNamespaceInfos.subList(0,
					Math.min(limitedNamespaceInfos.size(), DEFAULT_PAGE_LIMIT));

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getName();
			}

			PaginatedResult<NamespaceInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return createSuccessResult(paginatedResult);

		}).onErrorResume(e -> createErrorResult(e));
	}

}
