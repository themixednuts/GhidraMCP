package com.themixednuts.tools.projectmanagement;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.ScriptArgumentInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.ScriptInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import generic.jar.ResourceFile;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Ghidra Scripts", mcpName = "list_ghidra_scripts", mcpDescription = "Lists available Ghidra scripts, optionally filtering by category, and shows their arguments.", category = ToolCategory.PROJECT_MANAGEMENT, description = "Lists available Ghidra scripts and their arguments.")
public class GhidraListScriptsTool implements IGhidraMcpSpecification {

	private static final String ARG_CATEGORY_FILTER = "categoryFilter";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_CATEGORY_FILTER,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: Filter scripts by category (case-insensitive partial match)."));

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return Mono.fromCallable(() -> {
			Optional<String> categoryFilterOpt = getOptionalStringArgument(args, ARG_CATEGORY_FILTER);
			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

			PaginatedResult<ScriptArgumentInfo.ScriptInfo> paginatedResult = findAndParseScripts(categoryFilterOpt,
					cursorOpt);

			return createSuccessResult(paginatedResult);
		}).flatMap(mono -> mono)
				.onErrorResume(e -> createErrorResult(e));
	}

	// Define a record (or simple class) to hold paginated results
	// Removed PaginatedScriptsResult record

	private PaginatedResult<ScriptArgumentInfo.ScriptInfo> findAndParseScripts(Optional<String> categoryFilterOpt,
			Optional<String> cursorOpt) {

		List<ScriptInfo> allScriptInfo = new ArrayList<>();
		List<ResourceFile> scriptDirs = GhidraScriptUtil.getScriptSourceDirectories();

		// Collect ScriptInfo for all valid script files
		for (ResourceFile scriptDirFile : scriptDirs) {
			Path scriptDirPath = Path.of(scriptDirFile.getAbsolutePath());
			if (!Files.isDirectory(scriptDirPath)) {
				continue;
			}
			try (Stream<Path> stream = Files.walk(scriptDirPath)) {
				stream
						.filter(Files::isRegularFile)
						// Use GhidraScriptUtil to check provider compatibility if needed, for now
						// assume .java
						.filter(path -> path.toString().endsWith(".java"))
						.forEach(scriptPath -> {
							ResourceFile scriptFile = new ResourceFile(scriptPath.toFile());
							// Use Ghidra's method to get ScriptInfo
							ScriptInfo info = GhidraScriptUtil.newScriptInfo(scriptFile);
							if (info != null) {
								allScriptInfo.add(info);
							}
						});
			} catch (IOException e) {
				Msg.warn(this, "Error walking script directory: " + scriptDirPath, e);
			}
		}

		final String cursor = cursorOpt.orElse(null);
		final String categoryFilterLower = categoryFilterOpt.map(String::toLowerCase).orElse(null);

		// Filter, sort, apply cursor, and limit
		List<ScriptInfo> limitedResults = allScriptInfo.stream()
				// Apply category filter
				.filter(scriptInfo -> {
					if (categoryFilterLower == null) {
						return true; // No filter
					}
					String[] categories = scriptInfo.getCategory();
					String combinedCategory = categories != null ? String.join("/", categories).toLowerCase() : "";
					return combinedCategory.contains(categoryFilterLower);
				})
				// Sort by name for consistent pagination
				.sorted(Comparator.comparing(si -> si.getSourceFile().getName()))
				// Apply cursor logic: drop elements until we are past the cursor
				.dropWhile(scriptInfo -> cursor != null &&
						scriptInfo.getSourceFile().getName().compareTo(cursor) <= 0)
				// Limit results for pagination check
				.limit(DEFAULT_PAGE_LIMIT + 1)
				.collect(Collectors.toList());

		boolean hasMore = limitedResults.size() > DEFAULT_PAGE_LIMIT;
		List<ScriptInfo> pageScriptInfo = hasMore
				? limitedResults.subList(0, DEFAULT_PAGE_LIMIT)
				: limitedResults;

		// Map Ghidra ScriptInfo to our result format
		// Note: Arguments are not directly available in ScriptInfo in a parsed way.
		List<ScriptArgumentInfo.ScriptInfo> pageResults = pageScriptInfo.stream()
				.map(si -> new ScriptArgumentInfo.ScriptInfo(
						si.getName(), // Full name with extension
						si.getDescription(),
						String.join("/", si.getCategory()), // Join category array
						new ArrayList<>() // Arguments not available from ScriptInfo
				))
				.collect(Collectors.toList());

		String nextCursor = null;
		if (hasMore && !pageResults.isEmpty()) {
			nextCursor = pageResults.get(pageResults.size() - 1).name();
		}

		return new PaginatedResult<>(pageResults, nextCursor);
	}

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
}