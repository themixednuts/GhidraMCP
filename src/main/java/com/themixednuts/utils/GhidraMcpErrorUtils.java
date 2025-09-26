package com.themixednuts.utils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.models.DataTypeSuggestionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.GhidraMcpError.ErrorCode;
import com.themixednuts.models.GhidraMcpError.ErrorContext;
import com.themixednuts.models.GhidraMcpError.ErrorDebugInfo;
import com.themixednuts.models.GhidraMcpError.ErrorSuggestion;
import com.themixednuts.models.GhidraMcpError.ErrorSuggestion.SuggestionType;

import ghidra.framework.Application;
import ghidra.program.model.data.DataTypeManager;

/**
 * Utility class for creating structured, helpful error messages for Ghidra MCP
 * tools.
 * Provides factory methods for common error scenarios with appropriate
 * suggestions and context.
 */
public class GhidraMcpErrorUtils {

	/**
	 * Creates a validation error for missing required arguments.
	 */
	public static GhidraMcpError missingRequiredArgument(String argumentName, String toolOperation,
			Map<String, Object> providedArgs) {

		ErrorContext context = new ErrorContext(
				toolOperation,
				"argument: " + argumentName,
				providedArgs,
				Map.of("missingArgument", argumentName),
				Map.of("required", true, "provided", false));

		ErrorSuggestion suggestion = new ErrorSuggestion(
				SuggestionType.FIX_REQUEST,
				"Add the required '" + argumentName + "' argument to your request",
				"Include the '" + argumentName + "' field with a valid value",
				List.of("\"" + argumentName + "\": \"example_value\""),
				null);

		return GhidraMcpError.validation()
				.errorCode(ErrorCode.MISSING_REQUIRED_ARGUMENT)
				.message("Missing required argument: '" + argumentName + "'")
				.context(context)
				.suggestions(List.of(suggestion))
				.build();
	}

	/**
	 * Creates a validation error for invalid argument types.
	 */
	public static GhidraMcpError invalidArgumentType(String argumentName, Class<?> expectedType,
			Object actualValue, String toolOperation, Map<String, Object> providedArgs) {

		String actualType = actualValue != null ? actualValue.getClass().getSimpleName() : "null";

		ErrorContext context = new ErrorContext(
				toolOperation,
				"argument: " + argumentName,
				providedArgs,
				Map.of("providedValue", actualValue, "providedType", actualType),
				Map.of("expectedType", expectedType.getSimpleName(), "actualType", actualType));

		List<String> examples = getTypeExamples(expectedType);

		ErrorSuggestion suggestion = new ErrorSuggestion(
				SuggestionType.FIX_REQUEST,
				"Provide a " + expectedType.getSimpleName() + " value for '" + argumentName + "'",
				"Change the argument type to " + expectedType.getSimpleName(),
				examples,
				null);

		return GhidraMcpError.validation()
				.errorCode(ErrorCode.INVALID_ARGUMENT_TYPE)
				.message("Invalid type for argument '" + argumentName + "'. Expected " +
						expectedType.getSimpleName() + ", got " + actualType)
				.context(context)
				.suggestions(List.of(suggestion))
				.build();
	}

	/**
	 * Creates a resource not found error for functions.
	 */
	public static GhidraMcpError functionNotFound(Map<String, Object> searchCriteria,
			String toolOperation, List<String> availableFunctions) {

		ErrorContext context = new ErrorContext(
				toolOperation,
				"function",
				searchCriteria,
				searchCriteria,
				Map.of("searchedBy", searchCriteria.keySet(), "totalAvailable", availableFunctions.size()));

		List<ErrorSuggestion> suggestions = new ArrayList<>();

		// Suggest checking available functions
		suggestions.add(new ErrorSuggestion(
				SuggestionType.CHECK_RESOURCES,
				"Check available functions in the program",
				"Use the 'list_function_names' tool to see all available functions",
				null,
				List.of("analyze_functions")));

		// Suggest similar function names if available
		if (!availableFunctions.isEmpty()) {
			String searchName = (String) searchCriteria.get("functionName");
			if (searchName != null) {
				List<String> similarNames = findSimilarNames(searchName, availableFunctions, 5);
				if (!similarNames.isEmpty()) {
					suggestions.add(new ErrorSuggestion(
							SuggestionType.SIMILAR_VALUES,
							"Similar function names found",
							"Try one of these similar function names",
							similarNames,
							null));
				}
			}
		}

		return GhidraMcpError.resourceNotFound()
				.errorCode(ErrorCode.FUNCTION_NOT_FOUND)
				.message("Function not found using provided criteria")
				.context(context)
				.suggestions(suggestions)
				.relatedResources(availableFunctions.stream().limit(10).collect(Collectors.toList()))
				.build();
	}

	/**
	 * Creates a data type not found error with suggestions.
	 */
	public static GhidraMcpError dataTypeNotFound(String dataTypePath, String toolOperation,
			DataTypeManager dtm, List<DataTypeSuggestionInfo> suggestions) {

		ErrorContext context = new ErrorContext(
				toolOperation,
				"data type: " + dataTypePath,
				Map.of("dataTypePath", dataTypePath),
				Map.of("requestedPath", dataTypePath),
				Map.of("pathExists", false, "isValidPath", isValidDataTypePath(dataTypePath)));

		List<ErrorSuggestion> errorSuggestions = new ArrayList<>();

		// Suggest checking available data types
		errorSuggestions.add(new ErrorSuggestion(
				SuggestionType.CHECK_RESOURCES,
				"Check available data types in the program",
				"Use the 'list_data_types' tool to see available data types",
				null,
				List.of("manage_data_types")));

		// Add similar data type suggestions
		if (suggestions != null && !suggestions.isEmpty()) {
			List<String> similarPaths = suggestions.stream()
					.map(DataTypeSuggestionInfo::getPath)
					.limit(5)
					.collect(Collectors.toList());

			errorSuggestions.add(new ErrorSuggestion(
					SuggestionType.SIMILAR_VALUES,
					"Similar data types found",
					"Try one of these similar data type paths",
					similarPaths,
					null));
		}

		// Suggest data type syntax if path looks malformed
		if (!isValidDataTypePath(dataTypePath)) {
			errorSuggestions.add(new ErrorSuggestion(
					SuggestionType.FIX_REQUEST,
					"Data type path format appears invalid",
					"Use proper data type path format",
					List.of("/CategoryName/TypeName", "int", "char *", "MyStruct[10]"),
					null));
		}

		return GhidraMcpError.resourceNotFound()
				.errorCode(ErrorCode.DATA_TYPE_NOT_FOUND)
				.message("Data type not found: " + dataTypePath)
				.context(context)
				.suggestions(errorSuggestions)
				.build();
	}

	/**
	 * Creates a data type parsing error with syntax help.
	 */
	public static GhidraMcpError dataTypeParsingError(String dataTypePath, String parseError,
			String toolOperation) {

		ErrorContext context = new ErrorContext(
				toolOperation,
				"data type parsing: " + dataTypePath,
				Map.of("dataTypePath", dataTypePath),
				Map.of("inputPath", dataTypePath, "parseError", parseError),
				Map.of("syntaxValid", false, "errorType", "parsing"));

		List<ErrorSuggestion> suggestions = new ArrayList<>();

		// Suggest correct pointer syntax
		if (dataTypePath.contains("*")) {
			suggestions.add(new ErrorSuggestion(
					SuggestionType.FIX_REQUEST,
					"Check pointer syntax",
					"Ensure proper spacing and format for pointer declarations",
					List.of("char *", "int *", "/MyStruct *", "void *"),
					null));
		}

		// Suggest correct array syntax
		if (dataTypePath.contains("[") || dataTypePath.contains("]")) {
			suggestions.add(new ErrorSuggestion(
					SuggestionType.FIX_REQUEST,
					"Check array syntax",
					"Ensure proper array declaration format",
					List.of("int[10]", "char[256]", "/MyStruct[5]"),
					null));
		}

		// General syntax help
		suggestions.add(new ErrorSuggestion(
				SuggestionType.FIX_REQUEST,
				"Use valid data type syntax",
				"Follow proper data type path format",
				List.of("int", "char *", "MyStruct", "/Category/TypeName", "byte[16]"),
				null));

		ErrorCode errorCode = dataTypePath.contains("*") ? ErrorCode.INVALID_POINTER_SYNTAX
				: dataTypePath.contains("[") ? ErrorCode.INVALID_ARRAY_SYNTAX
						: ErrorCode.INVALID_TYPE_PATH;

		return GhidraMcpError.dataTypeParsing()
				.errorCode(errorCode)
				.message("Failed to parse data type: " + dataTypePath + ". " + parseError)
				.context(context)
				.suggestions(suggestions)
				.build();
	}

	/**
	 * Creates an address parsing error.
	 */
	public static GhidraMcpError addressParseError(String addressString, String toolOperation,
			Throwable cause) {

		ErrorContext context = new ErrorContext(
			toolOperation,
			"address: " + addressString,
			Map.of("address", addressString),
			Map.of("inputAddress", addressString),
			Map.of("formatValid", false, "parseError", cause != null ? cause.getMessage() : "unknown"));

		ErrorSuggestion suggestion = new ErrorSuggestion(
				SuggestionType.FIX_REQUEST,
				"Use valid address format",
				"Provide a properly formatted hexadecimal address",
				List.of("0x401000", "0x10040a0", "401000", "ram:00401000"),
				null);

		return GhidraMcpError.execution()
				.errorCode(ErrorCode.ADDRESS_PARSE_FAILED)
				.message("Invalid address format: " + addressString)
				.context(context)
				.suggestions(List.of(suggestion))
				.build();
	}

	/**
	 * Creates a search no results error with suggestions.
	 */
	public static GhidraMcpError searchNoResults(Map<String, Object> searchCriteria,
			String toolOperation, List<String> suggestions) {

		ErrorContext context = new ErrorContext(
				toolOperation,
				"search operation",
				searchCriteria,
				searchCriteria,
				Map.of("resultsFound", 0, "searchType", "exact_match"));

		List<ErrorSuggestion> errorSuggestions = new ArrayList<>();

		errorSuggestions.add(new ErrorSuggestion(
				SuggestionType.ALTERNATIVE_APPROACH,
				"Broaden your search criteria",
				"Try using partial matches or wildcards",
				List.of("Use broader filter terms", "Remove specific constraints", "Try case-insensitive search"),
				null));

		if (suggestions != null && !suggestions.isEmpty()) {
			errorSuggestions.add(new ErrorSuggestion(
					SuggestionType.SIMILAR_VALUES,
					"Related items found",
					"Try searching for these related items",
					suggestions.stream().limit(5).collect(Collectors.toList()),
					null));
		}

		return GhidraMcpError.searchNoResults()
				.errorCode(ErrorCode.NO_SEARCH_RESULTS)
				.message("Search returned no results")
				.context(context)
				.suggestions(errorSuggestions)
				.build();
	}

	/**
	 * Creates a file not found error.
	 */
	public static GhidraMcpError fileNotFound(String fileName, List<String> availableFiles,
			String toolOperation) {

		ErrorContext context = new ErrorContext(
				toolOperation,
				"file: " + fileName,
				Map.of("fileName", fileName),
				Map.of("requestedFile", fileName),
				Map.of("fileExists", false, "totalAvailable", availableFiles.size()));

		List<ErrorSuggestion> suggestions = new ArrayList<>();

		suggestions.add(new ErrorSuggestion(
				SuggestionType.CHECK_RESOURCES,
				"Check available open files",
				"Use the 'list_files' tool to see currently open files",
				null,
				null));

		if (!availableFiles.isEmpty()) {
			List<String> similarNames = findSimilarNames(fileName, availableFiles, 3);
			if (!similarNames.isEmpty()) {
				suggestions.add(new ErrorSuggestion(
						SuggestionType.SIMILAR_VALUES,
						"Similar file names found",
						"Try one of these similar file names",
						similarNames,
						null));
			}
		}

		return GhidraMcpError.resourceNotFound()
				.errorCode(ErrorCode.FILE_NOT_FOUND)
				.message("File not found or not open: " + fileName)
				.context(context)
				.suggestions(suggestions)
				.relatedResources(availableFiles)
				.build();
	}

	/**
	 * Creates debug information for an error.
	 */
	public static ErrorDebugInfo createDebugInfo(Throwable throwable, String toolClass,
			Map<String, Object> additionalInfo) {

		String stackTrace = null;
		if (throwable != null) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			throwable.printStackTrace(pw);
			stackTrace = sw.toString();
		}

		String ghidraVersion = Application.getApplicationVersion();
		String timestamp = Instant.now().toString();

		return new ErrorDebugInfo(stackTrace, ghidraVersion, toolClass, timestamp, additionalInfo);
	}

	// Helper methods

	private static List<String> getTypeExamples(Class<?> type) {
		if (type == String.class) {
			return List.of("\"example_string\"", "\"my_value\"");
		} else if (type == Integer.class || type == int.class) {
			return List.of("42", "100", "0");
		} else if (type == Boolean.class || type == boolean.class) {
			return List.of("true", "false");
		} else if (type == List.class) {
			return List.of("[\"item1\", \"item2\"]", "[]");
		} else if (type == Map.class) {
			return List.of("{\"key\": \"value\"}", "{}");
		}
		return List.of("/* " + type.getSimpleName() + " value */");
	}

	private static boolean isValidDataTypePath(String path) {
		if (path == null || path.trim().isEmpty()) {
			return false;
		}

		// Basic validation - could be enhanced
		String trimmed = path.trim();

		// Check for obviously invalid characters or patterns
		if (trimmed.contains("//") || trimmed.endsWith("/")) {
			return false;
		}

		// Check bracket matching for arrays
		long openBrackets = trimmed.chars().filter(ch -> ch == '[').count();
		long closeBrackets = trimmed.chars().filter(ch -> ch == ']').count();

		return openBrackets == closeBrackets;
	}

	private static List<String> findSimilarNames(String target, List<String> candidates, int maxResults) {
		if (target == null || candidates == null || candidates.isEmpty()) {
			return List.of();
		}

		String lowerTarget = target.toLowerCase();

		return candidates.stream()
				.filter(candidate -> candidate != null)
				.filter(candidate -> {
					String lowerCandidate = candidate.toLowerCase();
					return lowerCandidate.contains(lowerTarget) ||
							lowerTarget.contains(lowerCandidate) ||
							calculateLevenshteinDistance(lowerTarget, lowerCandidate) <= 3;
				})
				.limit(maxResults)
				.collect(Collectors.toList());
	}

	private static int calculateLevenshteinDistance(String s1, String s2) {
		int len1 = s1.length();
		int len2 = s2.length();

		int[][] dp = new int[len1 + 1][len2 + 1];

		for (int i = 0; i <= len1; i++) {
			dp[i][0] = i;
		}
		for (int j = 0; j <= len2; j++) {
			dp[0][j] = j;
		}

		for (int i = 1; i <= len1; i++) {
			for (int j = 1; j <= len2; j++) {
				if (s1.charAt(i - 1) == s2.charAt(j - 1)) {
					dp[i][j] = dp[i - 1][j - 1];
				} else {
					dp[i][j] = 1 + Math.min(dp[i - 1][j], Math.min(dp[i][j - 1], dp[i - 1][j - 1]));
				}
			}
		}

		return dp[len1][len2];
	}
}