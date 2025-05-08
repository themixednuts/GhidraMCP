package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.ArrayList;
import java.util.Arrays;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.DataTypeInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.FunctionDefinition;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List DataTypes", category = ToolCategory.DATATYPES, description = "Lists data types within a program, with optional filtering by category path, name fragment, and specific data type kind.", mcpName = "list_data_types", mcpDescription = "Lists data types, optionally filtering by category path, name fragment, and specific data type kind.")
public class GhidraListDataTypesTool implements IGhidraMcpSpecification {

	protected static final String ARG_RECURSIVE = "recursive";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."))
				.property(ARG_PATH,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional category path to search within data types (e.g., '/MyCategory'). Defaults to the root data type manager tree ('/').")
								.pattern("^/.*")
								.defaultValue("/"),
						true)
				.property(ARG_FILTER,
						JsonSchemaBuilder.string(mapper)
								.description("Optional case-insensitive substring filter to apply to data type names."))
				.property(ARG_DATA_TYPE,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional specific kind of data type to filter by (e.g., STRUCT, ENUM). If omitted, all data types matching other criteria are listed.")
								.enumValues(Arrays.stream(DataTypeKind.values())
										.filter(dk -> dk != DataTypeKind.CATEGORY) // Exclude CATEGORY from this tool's options
										.map(Enum::name)
										.collect(Collectors.toList())))
				.description(
						"Lists data types under an optional category path, optionally filtered by name and type.");

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					Optional<CategoryPath> pathOpt = getOptionalStringArgument(args, ARG_PATH).map(CategoryPath::new);
					Optional<String> filterOpt = getOptionalStringArgument(args, ARG_FILTER).map(String::toLowerCase);
					Optional<DataTypeKind> dataTypeKind = getOptionalStringArgument(args, ARG_DATA_TYPE)
							.map(DataTypeKind::valueOf);
					Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

					return Mono.fromCallable(
							() -> listDataTypesInternal(program, pathOpt, filterOpt, dataTypeKind, cursorOpt));
				});
	}

	private PaginatedResult<DataTypeInfo> listDataTypesInternal(Program program, Optional<CategoryPath> pathOpt,
			Optional<String> filterOpt, Optional<DataTypeKind> dataTypeKind, Optional<String> cursorOpt) {

		DataTypeManager dtm = program.getDataTypeManager();
		List<DataType> candidateDataTypes = new ArrayList<>();

		if (filterOpt.isPresent()) {
			dtm.findDataTypes(filterOpt.get(), candidateDataTypes);
		} else if (pathOpt.isPresent() && dtm.containsCategory(pathOpt.get())) {
			Arrays.stream(dtm.getCategory(pathOpt.get()).getDataTypes()).forEach(candidateDataTypes::add);
		} else {
			dtm.getAllDataTypes(candidateDataTypes);
		}

		// Apply data type kind filter (if any)
		if (dataTypeKind.isPresent()) {
			DataTypeKind typeFilter = dataTypeKind.get();
			candidateDataTypes.removeIf(dt -> {
				boolean matches;
				switch (typeFilter) {
					case STRUCT:
						matches = dt instanceof Structure;
						break;
					case UNION:
						matches = dt instanceof Union;
						break;
					case ENUM:
						matches = dt instanceof ghidra.program.model.data.Enum;
						break;
					case TYPEDEF:
						matches = dt instanceof TypeDef;
						break;
					case FUNCTION_DEFINITION:
						matches = dt instanceof FunctionDefinition;
						break;
					case OTHER:
						matches = !(dt instanceof Structure || dt instanceof Union ||
								dt instanceof ghidra.program.model.data.Enum || dt instanceof TypeDef ||
								dt instanceof FunctionDefinition || dt.isNotYetDefined());
						break;
					default:
						matches = false; // Should not be reached
				}
				return !matches; // removeIf removes if true (i.e., if it !matches)
			});
		}

		List<DataTypeInfo> dataTypes = candidateDataTypes.stream()
				.sorted((d1, d2) -> d1.getPathName().compareToIgnoreCase(d2.getPathName()))
				.dropWhile(dt -> !cursorOpt.map(c -> c.equals(dt.getPathName())).orElse(false))
				.limit(DEFAULT_PAGE_LIMIT + 1)
				.map(DataTypeInfo::new)
				.collect(Collectors.toList());

		boolean hasMore = dataTypes.size() > DEFAULT_PAGE_LIMIT;
		if (hasMore) {
			dataTypes = dataTypes.subList(0, Math.min(dataTypes.size(), DEFAULT_PAGE_LIMIT));
		}

		String nextCursor = null;
		if (hasMore && !dataTypes.isEmpty()) {
			nextCursor = dataTypes.get(dataTypes.size() - 1).getPathName();
		}

		return new PaginatedResult<>(dataTypes, nextCursor);

	}
}