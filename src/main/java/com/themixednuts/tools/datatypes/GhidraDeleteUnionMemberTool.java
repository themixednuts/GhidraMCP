package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Delete Union Member", category = ToolCategory.DATATYPES, description = "Removes a member (by name) from an existing union data type.", mcpName = "delete_union_member", mcpDescription = "Remove a member from a union.")
public class GhidraDeleteUnionMemberTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));
		schemaRoot.property(ARG_UNION_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the union containing the member (e.g., /MyCategory/MyUnion)"));
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the member to delete."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_UNION_PATH)
				.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	// Nested record for type-safe context passing
	private static record DeleteUnionMemberContext(
			Program program,
			Union unionDt,
			Integer ordinalToDelete) {
	}

	/**
	 * Gets available member names for error suggestions.
	 */
	private List<String> getAvailableMemberNames(Union union) {
		return java.util.Arrays.stream(union.getComponents())
				.map(DataTypeComponent::getFieldName)
				.filter(name -> name != null && !name.trim().isEmpty())
				.limit(10) // Prevent overwhelming error messages
				.collect(Collectors.toList());
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
			String memberName = getRequiredStringArgument(args, ARG_NAME);

			DataType dt = program.getDataTypeManager().getDataType(unionPathString);

			if (dt == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Union not found at path: " + unionPathString)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"union lookup",
								args,
								Map.of(ARG_UNION_PATH, unionPathString),
								Map.of("searchedPath", unionPathString, "dataTypeExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify the union path",
										"Check if the union exists at the specified path",
										null,
										List.of(getMcpName(GhidraListDataTypesTool.class),
												getMcpName(GhidraGetDataTypeTool.class))),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Check the path format",
										"Ensure the path follows the correct format",
										List.of("/MyCategory/MyUnion", "/BuiltInTypes/SomeUnion"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			if (!(dt instanceof Union)) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Data type at path is not a Union: " + unionPathString)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"data type validation",
								args,
								Map.of(ARG_UNION_PATH, unionPathString, "actualDataType", dt.getClass().getSimpleName()),
								Map.of("expectedType", "Union", "actualType", dt.getClass().getSimpleName(), "dataTypeName",
										dt.getName())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.USE_DIFFERENT_TOOL,
										"Use the appropriate tool for this data type",
										"This data type requires a different delete operation",
										null,
										List.of(getMcpName(GhidraDeleteStructMemberTool.class),
												getMcpName(GhidraDeleteEnumEntryTool.class))),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify the data type details",
										"Check the actual type of the data type at this path",
										null,
										List.of(getMcpName(GhidraGetDataTypeTool.class)))))
						.build();
				throw new GhidraMcpException(error);
			}

			Union unionDt = (Union) dt;

			DataTypeComponent componentToDelete = null;
			for (DataTypeComponent comp : unionDt.getComponents()) {
				String fieldName = comp.getFieldName();
				if (fieldName != null && fieldName.equals(memberName)) {
					componentToDelete = comp;
					break;
				}
			}

			if (componentToDelete == null) {
				List<String> availableMembers = getAvailableMemberNames(unionDt);

				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Member '" + memberName + "' not found in union " + unionPathString)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"union member lookup",
								args,
								Map.of(ARG_UNION_PATH, unionPathString, ARG_NAME, memberName),
								Map.of("searchedMemberName", memberName, "unionSize", unionDt.getLength(),
										"memberCount", unionDt.getNumComponents(), "memberExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Check existing union members",
										"View the current members in this union",
										null,
										List.of(getMcpName(GhidraGetDataTypeTool.class))),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.SIMILAR_VALUES,
										"Use an existing member name",
										"Available member names in this union",
										availableMembers.isEmpty() ? List.of("(no named members found)") : availableMembers,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Return type-safe context
			return new DeleteUnionMemberContext(program, unionDt, componentToDelete.getOrdinal());
		}).flatMap(context -> {
			String unionPathString = context.unionDt().getPathName();

			return executeInTransaction(context.program(), "Delete Union Member (ordinal " + context.ordinalToDelete() + ")",
					() -> {
						context.unionDt().delete(context.ordinalToDelete());
						return "Union member deleted successfully from " + unionPathString + " (member ordinal was "
								+ context.ordinalToDelete()
								+ ").";
					});
		});
	}
}