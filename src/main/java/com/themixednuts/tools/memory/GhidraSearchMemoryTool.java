package com.themixednuts.tools.memory;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;

import ghidra.features.base.memsearch.bytesource.ProgramByteSource;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.ListAccumulator;
import io.modelcontextprotocol.server.McpAsyncServerExchange;

import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Search Memory", category = ToolCategory.MEMORY, description = "Search program memory for various data types and patterns using Ghidra's search mechanisms", mcpName = "search_memory", mcpDescription = """
		<use_case>
		Search program memory for various data types and patterns using Ghidra's native search algorithms.
		Supports string search, byte patterns, regular expressions, and numeric values.
		Use this when you need to find specific patterns, values, or strings in the program's memory.
		</use_case>

		<ghidra_specific_notes>
		- Uses Ghidra's Memory.findBytes and StringSearcher for efficient pattern matching
		- Supports string, regex, hex byte, binary, and numeric searches
		- Searches only in initialized memory regions by default
		- Results are paginated to handle large search results efficiently
		- Requires an active program to search through its memory
		</ghidra_specific_notes>

		<parameters_summary>
		- 'searchType': Type of search (string, hex, binary, decimal, float, double, regex)
		- 'searchValue': The pattern/value to search for (format depends on search type)
		- 'caseSensitive': Whether string/regex searches are case sensitive (default false)
		- 'maxResults': Maximum number of results to return (default 100, max 1000)
		</parameters_summary>

		<agent_response_guidance>
		Present search results in a clear, structured format showing addresses and found content.
		Include the search type and value in your response. If many results are found, mention
		the total count and suggest refining the search criteria if needed.
		</agent_response_guidance>
		""")
public class GhidraSearchMemoryTool implements IGhidraMcpSpecification {

	public enum SearchType {
		STRING("string", "Text string search"),
		HEX("hex", "Hexadecimal byte pattern search"),
		BINARY("binary", "Binary pattern search"),
		DECIMAL("decimal", "Decimal number search"),
		FLOAT("float", "32-bit floating point search"),
		DOUBLE("double", "64-bit floating point search"),
		REGEX("regex", "Regular expression pattern search");

		private final String value;
		private final String description;

		SearchType(String value, String description) {
			this.value = value;
			this.description = description;
		}

		public String getValue() {
			return value;
		}

		public String getDescription() {
			return description;
		}

		public static SearchType fromValue(String value) {
			for (SearchType type : values()) {
				if (type.value.equalsIgnoreCase(value)) {
					return type;
				}
			}
			throw new IllegalArgumentException("Invalid search type: " + value);
		}

		public static String[] getValidValues() {
			return java.util.Arrays.stream(values())
					.map(SearchType::getValue)
					.toArray(String[]::new);
		}

		public SearchFormat getSearchFormat() {
			switch (this) {
				case STRING:
					return SearchFormat.STRING;
				case BINARY:
					return SearchFormat.BINARY;
				case DECIMAL:
					return SearchFormat.DECIMAL;
				case FLOAT:
					return SearchFormat.FLOAT;
				case DOUBLE:
					return SearchFormat.DOUBLE;
				case REGEX:
					return SearchFormat.REG_EX;
				default:
					return SearchFormat.HEX;
			}
		}
	}

	public static final String ARG_SEARCH_TYPE = "searchType";
	public static final String ARG_SEARCH_VALUE = "searchValue";
	public static final String ARG_CASE_SENSITIVE = "caseSensitive";
	public static final String ARG_MAX_RESULTS = "maxResults";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));

		schemaRoot.property(ARG_SEARCH_TYPE,
				JsonSchemaBuilder.string(mapper)
						.description("Type of search to perform")
						.enumValues(SearchType.getValidValues()));

		schemaRoot.property(ARG_SEARCH_VALUE,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Value to search for. Format depends on search type:\n" +
										"- string: text to find (e.g., 'hello')\n" +
										"- hex: hexadecimal bytes (e.g., '48656c6c6f' or '48 65 6c 6c 6f')\n" +
										"- binary: binary string (e.g., '0100100001100101')\n" +
										"- decimal: decimal number (e.g., '12345')\n" +
										"- float: floating point number (e.g., '3.14159')\n" +
										"- double: double precision number (e.g., '2.718281828')\n" +
										"- regex: regular expression pattern"));

		schemaRoot.property(ARG_CASE_SENSITIVE,
				JsonSchemaBuilder.bool(mapper)
						.description("Whether string/regex searches are case sensitive (default false)"));

		schemaRoot.property(ARG_MAX_RESULTS,
				JsonSchemaBuilder.integer(mapper)
						.description("Maximum number of results to return (default/max: " + DEFAULT_PAGE_LIMIT + ")")
						.minimum(1)
						.maximum(DEFAULT_PAGE_LIMIT));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_SEARCH_TYPE);
		schemaRoot.requiredProperty(ARG_SEARCH_VALUE);

		return schemaRoot.build();
	}

	public static class SearchResult {
		private final String address;
		private final byte[] bytes;
		private final int length;
		private final String searchType;

		public SearchResult(String address, byte[] bytes, int length, String searchType) {
			this.address = address;
			this.bytes = bytes;
			this.length = length;
			this.searchType = searchType;
		}

		public String getAddress() {
			return address;
		}

		public byte[] getBytes() {
			return bytes;
		}

		public int getLength() {
			return length;
		}

		public String getSearchType() {
			return searchType;
		}
	}

	private static record SearchContext(
			Program program,
			SearchType searchType,
			String searchValue,
			boolean caseSensitive,
			int maxResults) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String searchTypeStr = getRequiredStringArgument(args, ARG_SEARCH_TYPE);
					SearchType searchType = SearchType.fromValue(searchTypeStr);

					String searchValue = getRequiredStringArgument(args, ARG_SEARCH_VALUE);
					boolean caseSensitive = getOptionalBooleanArgument(args, ARG_CASE_SENSITIVE).orElse(false);
					int maxResults = getOptionalIntArgument(args, ARG_MAX_RESULTS).orElse(DEFAULT_PAGE_LIMIT);

					// Validate search value is not empty
					if (searchValue.trim().isEmpty()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Search value cannot be empty")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"search value validation",
										args,
										Map.of(ARG_SEARCH_VALUE, searchValue),
										Map.of("valueLength", searchValue.length())))
								.build();
						throw new GhidraMcpException(error);
					}

					return new SearchContext(program, searchType, searchValue, caseSensitive, maxResults);
				})
				.map(context -> {
					GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex,
							"Searching memory for: " + context.searchValue());

					// You will implement this method.
					// For now, it returns an empty list and no next cursor.
					List<SearchResult> results = search(context, monitor);

					// The result is wrapped in PaginatedResult to support pagination if you
					// implement it.
					return new PaginatedResult<>(results, null);
				});
	}

	/**
	 * Performs the memory search based on the provided context.
	 * You should implement the search logic here using Ghidra's APIs like
	 * MemorySearcher and ByteMatcher.
	 *
	 * @param context The search parameters and program context.
	 * @param monitor A task monitor to report progress and check for cancellation.
	 * @return A list of SearchResult objects. To support pagination, this method
	 *         could be
	 *         modified to return a structure containing both the results for the
	 *         current page
	 *         and a cursor for the next page.
	 */
	private List<SearchResult> search(SearchContext context, GhidraMcpTaskMonitor monitor) {
		Program program = context.program();
		SearchType searchType = context.searchType();
		String searchValue = context.searchValue();
		boolean caseSensitive = context.caseSensitive();
		int maxResults = context.maxResults();

		SearchSettings settings = new SearchSettings();
		SearchFormat searchFormat = searchType.getSearchFormat();
		settings.withSearchFormat(searchFormat);
		settings.withBigEndian(program.getMemory().isBigEndian());
		settings.withCaseSensitive(caseSensitive);

		ByteMatcher matcher = searchFormat.parse(searchValue, settings);

		if (!matcher.isValidSearch()) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
					.message("Invalid search value for the given search type: " + matcher.getDescription())
					.build();
			throw new GhidraMcpException(error);
		}

		ProgramByteSource byteSource = new ProgramByteSource(program);
		AddressSetView addressSet = program.getMemory().getLoadedAndInitializedAddressSet();

		MemorySearcher searcher = new MemorySearcher(byteSource, matcher, addressSet, maxResults);

		ListAccumulator<MemoryMatch> accumulator = new ListAccumulator<>();
		searcher.findAll(accumulator, monitor);

		return accumulator.stream()
				.map(match -> new SearchResult(match.getAddress().toString(), match.getBytes(), match.getLength(),
						searchType.getValue()))
				.collect(Collectors.toList());
	}

}