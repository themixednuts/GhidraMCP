package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.DataTypeUtils;
import com.themixednuts.utils.GhidraMcpErrorUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Data Type at Address", category = ToolCategory.DATATYPES, description = "Applies a named data type to a given memory address.", mcpName = "update_data_type_at_address", mcpDescription = "Apply a data type to a specific memory address in a Ghidra program. Supports built-in types, user-defined structures, and array/pointer notation.")
public class GhidraUpdateDataTypeAtAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address where the data type should be applied (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The full path of the data type to apply (e.g., '/MyStruct', '/integer', '/dword', 'int[10]', 'char *'). Array and pointer notations are supported."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	// Nested record for type-safe context passing
	private static record UpdateDataAtAddressContext(
			Program program,
			Address addr,
			String dataTypePath) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			String dataTypePath = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);

			Address addr = program.getAddressFactory().getAddress(addressStr);

			// Return type-safe context
			return new UpdateDataAtAddressContext(program, addr, dataTypePath);

		}).flatMap(context -> {
			return executeInTransaction(context.program(), "Apply Data Type at Address",
					() -> {
						String toolMcpName = getMcpName();

						// Parse the data type using the centralized utility
						DataType dataType = null;
						try {
							dataType = DataTypeUtils.parseDataTypeString(context.program(), context.dataTypePath(), tool);
						} catch (IllegalArgumentException e) {
							GhidraMcpError error = GhidraMcpError.resourceNotFound()
									.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
									.message("Data type not found: " + context.dataTypePath())
									.context(new GhidraMcpError.ErrorContext(
											toolMcpName,
											"data type parsing",
											Map.of(ARG_DATA_TYPE_PATH, context.dataTypePath()),
											Map.of("dataTypePath", context.dataTypePath()),
											Map.of("parseError", e.getMessage())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Check data type path format",
													"Use list_data_types to see available types",
													List.of("'/MyStruct'", "'int[10]'", "'char *'"),
													List.of(getMcpName(GhidraListDataTypesTool.class)))))
									.build();
							throw new GhidraMcpException(error);
						} catch (InvalidDataTypeException e) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Invalid data type format '" + context.dataTypePath() + "': " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											toolMcpName,
											"data type parsing",
											Map.of(ARG_DATA_TYPE_PATH, context.dataTypePath()),
											Map.of("dataTypePath", context.dataTypePath()),
											Map.of("parseError", e.getMessage(), "formatError", true)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Check data type format",
													"Ensure the data type path uses correct syntax",
													List.of("'/MyStruct'", "'int[10]'", "'char *'"),
													null)))
									.build();
							throw new GhidraMcpException(error);
						} catch (CancelledException e) {
							GhidraMcpError error = GhidraMcpError.execution()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Data type parsing cancelled for '" + context.dataTypePath() + "': " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											toolMcpName,
											"data type parsing",
											Map.of(ARG_DATA_TYPE_PATH, context.dataTypePath()),
											Map.of("dataTypePath", context.dataTypePath()),
											Map.of("cancelled", true, "cancelReason", e.getMessage())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.USE_DIFFERENT_TOOL,
													"Retry the operation",
													"The operation was cancelled, try again",
													null,
													null)))
									.build();
							throw new GhidraMcpException(error);
						} catch (RuntimeException e) {
							GhidraMcpError error = GhidraMcpError.execution()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Unexpected runtime error during data type parsing for '" + context.dataTypePath() + "': "
											+ e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											toolMcpName,
											"data type parsing",
											Map.of(ARG_DATA_TYPE_PATH, context.dataTypePath()),
											Map.of("dataTypePath", context.dataTypePath()),
											Map.of("errorType", e.getClass().getSimpleName(), "errorMessage", e.getMessage())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
													"Verify data type availability",
													"Check if the data type exists and is accessible",
													null,
													List.of(getMcpName(GhidraListDataTypesTool.class)))))
									.build();
							throw new GhidraMcpException(error);
						}

						Listing listing = context.program().getListing();
						listing.clearCodeUnits(context.addr(), context.addr(), false);
						Data createdData = listing.createData(context.addr(), dataType);

						return String.format("Applied data type '%s' at address %s",
								dataType.getName(), context.addr().toString());
					});
		});
	}

}