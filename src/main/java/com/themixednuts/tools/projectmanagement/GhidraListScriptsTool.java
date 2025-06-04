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
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
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
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import generic.jar.ResourceFile;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Ghidra Scripts", mcpName = "list_ghidra_scripts", mcpDescription = "List available Ghidra scripts with optional category filtering and argument information. Essential for discovering automation scripts and their required parameters.", category = ToolCategory.PROJECT_MANAGEMENT, description = "Lists available Ghidra scripts and their arguments.")
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
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return Mono.fromCallable(() -> {
			try {
				Optional<String> categoryFilterOpt = getOptionalStringArgument(args, ARG_CATEGORY_FILTER);
				Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

				return findAndParseScripts(categoryFilterOpt, cursorOpt);
			} catch (Exception e) {
				if (e instanceof GhidraMcpException) {
					throw e;
				}
				throw new GhidraMcpException(
						GhidraMcpError.execution()
								.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
								.message("Failed to list Ghidra scripts: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										"list_scripts",
										getMcpName(),
										args,
										Map.of("operation", "discover_scripts"),
										Map.of("exception_type", e.getClass().getSimpleName(),
												"exception_message", e.getMessage())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify Ghidra script directories are accessible",
												"Check script directory permissions and availability",
												null,
												null)))
								.build());
			}
		});
	}

	private PaginatedResult<ScriptArgumentInfo.ScriptInfo> findAndParseScripts(Optional<String> categoryFilterOpt,
			Optional<String> cursorOpt) {

		List<ScriptInfo> allScriptInfo = new ArrayList<>();
		List<ResourceFile> scriptDirs = GhidraScriptUtil.getScriptSourceDirectories();

		if (scriptDirs == null || scriptDirs.isEmpty()) {
			throw new GhidraMcpException(
					GhidraMcpError.resourceNotFound()
							.errorCode(GhidraMcpError.ErrorCode.FILE_NOT_FOUND)
							.message("No Ghidra script directories found")
							.context(new GhidraMcpError.ErrorContext(
									"discover_script_directories",
									getMcpName(),
									Map.of("categoryFilter", categoryFilterOpt.orElse("none")),
									Map.of("script_directories_found", 0),
									Map.of("search_performed", "GhidraScriptUtil.getScriptSourceDirectories()")))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
											"Verify Ghidra installation and script directory configuration",
											"Check that Ghidra script directories are properly configured",
											null,
											null)))
							.build());
		}

		// Collect ScriptInfo for all valid script files
		for (ResourceFile scriptDirFile : scriptDirs) {
			try {
				Path scriptDirPath = Path.of(scriptDirFile.getAbsolutePath());
				if (!Files.isDirectory(scriptDirPath)) {
					continue;
				}

				try (Stream<Path> stream = Files.walk(scriptDirPath)) {
					stream
							.filter(Files::isRegularFile)
							.filter(path -> path.toString().endsWith(".java"))
							.forEach(scriptPath -> {
								try {
									ResourceFile scriptFile = new ResourceFile(scriptPath.toFile());
									ScriptInfo info = GhidraScriptUtil.newScriptInfo(scriptFile);
									if (info != null) {
										allScriptInfo.add(info);
									}
								} catch (Exception e) {
									// Log individual script parsing failures but continue processing
									// Don't throw exception for individual script failures
								}
							});
				}
			} catch (IOException e) {
				throw new GhidraMcpException(
						GhidraMcpError.execution()
								.errorCode(GhidraMcpError.ErrorCode.FILE_NOT_FOUND)
								.message("Failed to access script directory: " + scriptDirFile.getAbsolutePath())
								.context(new GhidraMcpError.ErrorContext(
										"access_script_directory",
										getMcpName(),
										Map.of("categoryFilter", categoryFilterOpt.orElse("none"),
												"scriptDirectory", scriptDirFile.getAbsolutePath()),
										Map.of("directory_path", scriptDirFile.getAbsolutePath()),
										Map.of("exception_type", e.getClass().getSimpleName(),
												"exception_message", e.getMessage(),
												"operation", "Files.walk()")))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify script directory permissions and accessibility",
												"Check that the script directory exists and is readable",
												null,
												null)))
								.build());
			} catch (Exception e) {
				throw new GhidraMcpException(
						GhidraMcpError.execution()
								.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
								.message("Unexpected error processing script directory: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										"process_script_directory",
										getMcpName(),
										Map.of("categoryFilter", categoryFilterOpt.orElse("none"),
												"scriptDirectory", scriptDirFile.getAbsolutePath()),
										Map.of("directory_path", scriptDirFile.getAbsolutePath()),
										Map.of("exception_type", e.getClass().getSimpleName(),
												"exception_message", e.getMessage())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify script directory state and Ghidra configuration",
												"Check directory permissions and Ghidra script system",
												null,
												null)))
								.build());
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
}