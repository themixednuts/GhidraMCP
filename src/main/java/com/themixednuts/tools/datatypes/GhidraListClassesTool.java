package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.NamespaceInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Classes", category = ToolCategory.SYMBOLS, description = "Lists classes within a program, with optional filtering.", mcpName = "list_classes", mcpDescription = "Lists classes, optionally filtering by parent namespace path and name fragment.")
public class GhidraListClassesTool implements IGhidraMcpSpecification {

	protected static final String ARG_RECURSIVE = "recursive";

	/**
	 * Gets available class and namespace names for error suggestions.
	 */
	private List<String> getAvailableClassesAndNamespaces(Program program) {
		List<String> items = new ArrayList<>();
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator iter = symbolTable.getSymbolIterator();
		int count = 0;
		while (iter.hasNext() && count < 50) { // Prevent overwhelming error messages
			Symbol symbol = iter.next();
			if (symbol.getSymbolType() == SymbolType.NAMESPACE || symbol.getSymbolType() == SymbolType.CLASS) {
				items.add(symbol.getName(true));
				count++;
			}
		}
		return items.stream().sorted().collect(Collectors.toList());
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."),
				true)
				.property(ARG_PATH,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional namespace path to start listing classes from (e.g., 'std::my_namespace', 'MyOuterClass'). Defaults to the global namespace."))
				.property(ARG_FILTER,
						JsonSchemaBuilder.string(mapper)
								.description("Optional case-insensitive substring filter to apply to class names."))
				.description("Lists classes under an optional path, optionally filtered by name.");

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					Optional<String> filterOpt = getOptionalStringArgument(args, ARG_FILTER);

					return Mono
							.fromCallable(() -> listNamespacesAndClassesInternal(program, pathOpt, filterOpt, true));
				});
	}

	private List<NamespaceInfo> listNamespacesAndClassesInternal(Program program, Optional<String> pathOpt,
			Optional<String> filterOpt, boolean classesOnly) {
		Namespace startNamespace = pathOpt
				.map(p -> NamespaceUtils.getNamespace(program, p))
				.orElse(program.getGlobalNamespace());

		if (startNamespace == null) {
			List<String> availableItems = getAvailableClassesAndNamespaces(program);

			GhidraMcpError error = GhidraMcpError.resourceNotFound()
					.errorCode(GhidraMcpError.ErrorCode.NAMESPACE_NOT_FOUND)
					.message("Namespace path not found: " + pathOpt.orElse("Global"))
					.context(new GhidraMcpError.ErrorContext(
							getMcpName(),
							"namespace lookup",
							Map.of(ARG_PATH, pathOpt.orElse("Global")),
							Map.of("requestedPath", pathOpt.orElse("Global"), "pathExists", false),
							Map.of("totalNamespaces", availableItems.size(), "searchedPath", pathOpt.orElse("Global"))))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
									"List available namespaces and classes",
									"Use tools to explore available namespaces and classes",
									null,
									List.of(getMcpName(GhidraListNamespacesTool.class), getMcpName(GhidraListClassesTool.class))),
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Use an existing namespace path",
									"Select from available namespaces or classes",
									availableItems.isEmpty() ? List.of("Global")
											: availableItems.subList(0, Math.min(10, availableItems.size())),
									null)))
					.build();
			throw new GhidraMcpException(error);
		}

		List<NamespaceInfo> namespaces = new ArrayList<>();
		String filterLower = filterOpt.map(String::toLowerCase).orElse(null);

		collectNamespaces(program, startNamespace, filterLower, classesOnly, namespaces);

		return namespaces.stream()
				.sorted((n1, n2) -> n1.getName().compareToIgnoreCase(n2.getName()))
				.collect(Collectors.toList());
	}

	private void collectNamespaces(Program program, Namespace currentNamespace, String filterLower, boolean classesOnly,
			List<NamespaceInfo> collectedNamespaces) {
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator children = symbolTable.getChildren(currentNamespace.getSymbol());
		while (children.hasNext()) {
			Symbol childSymbol = children.next();
			if (childSymbol.getSymbolType() == SymbolType.NAMESPACE || childSymbol.getSymbolType() == SymbolType.CLASS) {
				Object symbolObject = null;
				try {
					symbolObject = childSymbol.getObject();
				} catch (Exception e) {
					System.err.println("Could not get object for symbol: " + childSymbol.getName() + " - " + e.getMessage());
					continue;
				}

				if (symbolObject instanceof Namespace) {
					Namespace childNamespace = (Namespace) symbolObject;
					boolean isClass = childSymbol.getSymbolType() == SymbolType.CLASS;

					if (!classesOnly || isClass) {
						if (filterLower == null || childNamespace.getName().toLowerCase().contains(filterLower)) {
							try {
								collectedNamespaces.add(new NamespaceInfo(childNamespace));
							} catch (Exception e) {
								System.err.println(
										"Error processing namespace/class: " + childNamespace.getName(true) + " - " + e.getMessage());
							}
						}
					}
				}
			}
		}
	}

	private static class NamespaceUtils {
		static Namespace getNamespace(Program program, String namespaceString) {
			SymbolTable symbolTable = program.getSymbolTable();
			SymbolIterator iter = symbolTable.getSymbols(namespaceString);
			while (iter.hasNext()) {
				Symbol sym = iter.next();
				if (sym.getSymbolType() == SymbolType.NAMESPACE || sym.getSymbolType() == SymbolType.CLASS) {
					try {
						Object obj = sym.getObject();
						if (obj instanceof Namespace) {
							return (Namespace) obj;
						}
					} catch (Exception e) {
						// Ignore
					}
				}
			}
			Namespace global = program.getGlobalNamespace();
			if (global != null) {
				Symbol sym = symbolTable.getNamespaceSymbol(namespaceString, global);
				if (sym != null && sym.getObject() instanceof Namespace) {
					return (Namespace) sym.getObject();
				}
			}
			return null;
		}
	}
}