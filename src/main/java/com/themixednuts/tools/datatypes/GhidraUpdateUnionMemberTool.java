package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.DataTypeUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Union Members", mcpName = "update_union_members", category = ToolCategory.DATATYPES, description = "Updates one or more fields (members) in an existing union data type.", mcpDescription = "Updates the name, data type, and/or comment of one or more existing fields (members) in a union.")
public class GhidraUpdateUnionMemberTool implements IGhidraMcpSpecification {

	// Argument for the array of member updates
	public static final String ARG_MEMBER_UPDATES = "memberUpdates";
	// Arguments for identifying the member and the updates
	public static final String ARG_MEMBER_NAME = "name"; // Identify by current name
	public static final String ARG_NEW_MEMBER_NAME = "newName";
	public static final String ARG_NEW_DATA_TYPE_PATH = "newDataTypePath";
	public static final String ARG_NEW_COMMENT = "newComment";

	private static record UnionMemberUpdateDefinition(
			String name,
			Optional<String> newName,
			Optional<String> newDataTypePath,
			Optional<String> newComment) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		// Schema for a single member update definition
		IObjectSchemaBuilder updateSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition of updates for a single union member.")
				.property(ARG_MEMBER_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Current name of the member to update."),
						true)
				// Optional Updates
				.property(ARG_NEW_MEMBER_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: New name for the member."))
				.property(ARG_NEW_DATA_TYPE_PATH,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: New data type path for the member (e.g., 'dword', '/MyOtherStruct', 'int[5]', 'char *'). Array and pointer notations are supported."))
				.property(ARG_NEW_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: New comment for the member. An empty string clears the comment."))
				.requiredProperty(ARG_MEMBER_NAME);

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));
		schemaRoot.property(ARG_UNION_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the union to modify (e.g., /MyCategory/MyUnion)"));
		// Add the array property
		schemaRoot.property(ARG_MEMBER_UPDATES,
				JsonSchemaBuilder.array(mapper)
						.description("An array of member update definitions.")
						.items(updateSchema)
						.minItems(1)); // Require at least one update

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_UNION_PATH)
				.requiredProperty(ARG_MEMBER_UPDATES);

		return schemaRoot.build();
	}

	// Context to hold details needed for the transaction
	private static record UnionMemberUpdateBatchContext(
			Program program,
			PluginTool tool,
			Union union,
			List<UnionMemberUpdateDefinition> memberUpdateDefs) {
	}

	/**
	 * Get the tool name from the annotation for error reporting
	 */

	/**
	 * Get available member names for error suggestions
	 */
	private List<String> getAvailableMemberNames(Union union) {
		return java.util.Arrays.stream(union.getDefinedComponents())
				.map(DataTypeComponent::getFieldName)
				.filter(name -> name != null && !name.isEmpty())
				.sorted()
				.collect(Collectors.toList());
	}

	private boolean processSingleUnionMemberUpdate(Union union, UnionMemberUpdateDefinition updateDef, Program program,
			PluginTool tool) {
		DataTypeComponent componentToUpdate = null;
		int componentIndex = -1;
		for (DataTypeComponent comp : union.getDefinedComponents()) {
			if (updateDef.name().equals(comp.getFieldName())) {
				componentToUpdate = comp;
				componentIndex = comp.getOrdinal();
				break;
			}
		}
		if (componentToUpdate == null) {
			List<String> availableMembers = getAvailableMemberNames(union);
			GhidraMcpError error = GhidraMcpError.resourceNotFound()
					.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
					.message("No member found with name '" + updateDef.name() + "' in union '" + union.getPathName() + "'")
					.context(new GhidraMcpError.ErrorContext(
							getMcpName(),
							"union member lookup",
							Map.of(ARG_MEMBER_NAME, updateDef.name(), ARG_UNION_PATH, union.getPathName()),
							Map.of("unionPath", union.getPathName(), "memberName", updateDef.name()),
							Map.of("memberExists", false, "availableMembers", availableMembers, "memberCount",
									availableMembers.size())))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Use an existing member name",
									"Member name must match an existing union member",
									availableMembers.isEmpty() ? List.of("<no members available>") : availableMembers,
									null)))
					.build();
			throw new GhidraMcpException(error);
		}

		String finalName = updateDef.newName().orElse(componentToUpdate.getFieldName());
		String finalComment = updateDef.newComment().orElse(componentToUpdate.getComment());
		DataType finalDataType;
		boolean dataTypeChanged = false;

		if (updateDef.newDataTypePath().isPresent()) {
			String newDataTypePathStr = updateDef.newDataTypePath().get();
			try {
				DataType newDt = DataTypeUtils.parseDataTypeString(program, newDataTypePathStr, tool);
				finalDataType = newDt;
				dataTypeChanged = !finalDataType.isEquivalent(componentToUpdate.getDataType());
			} catch (InvalidDataTypeException e) {
				GhidraMcpError error = GhidraMcpError.dataTypeParsing()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Invalid data type format for '" + newDataTypePathStr + "': " + e.getMessage())
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"member data type parsing",
								Map.of(ARG_NEW_DATA_TYPE_PATH, newDataTypePathStr, ARG_MEMBER_NAME, updateDef.name()),
								Map.of("dataTypePath", newDataTypePathStr, "memberName", updateDef.name()),
								Map.of("parseError", e.getMessage())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use correct data type format",
										"Check data type path format",
										List.of("'dword'", "'/MyOtherStruct'", "'int[5]'", "'char *'"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			} catch (CancelledException e) {
				throw new RuntimeException(
						"Parsing cancelled for new data type '" + newDataTypePathStr + "': " + e.getMessage(), e);
			}
		} else {
			finalDataType = componentToUpdate.getDataType();
		}

		int finalSize = finalDataType.getLength();
		if (finalSize <= 0) {
			if (finalDataType.isEquivalent(componentToUpdate.getDataType())) {
				finalSize = componentToUpdate.getLength();
			}
			if (finalSize <= 0) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Cannot determine positive size for data type '" + finalDataType.getPathName() + "' for member '"
								+ updateDef.name() + "'")
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"member size validation",
								Map.of(ARG_MEMBER_NAME, updateDef.name(), ARG_NEW_DATA_TYPE_PATH, finalDataType.getPathName()),
								Map.of("memberName", updateDef.name(), "dataTypePath", finalDataType.getPathName(), "calculatedSize",
										finalSize),
								Map.of("sizeInvalid", true, "expectedSizeRange", "> 0")))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use a data type with defined size",
										"Some data types may not have a determinable size",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}
		}

		boolean nameChanged = updateDef.newName().isPresent() && !finalName.equals(componentToUpdate.getFieldName());
		boolean commentChanged = updateDef.newComment().isPresent() && !finalComment.equals(componentToUpdate.getComment());

		if (!nameChanged && !dataTypeChanged && !commentChanged) {
			return false;
		}

		union.delete(componentIndex);
		union.insert(componentIndex, finalDataType, finalSize, finalName, finalComment);
		return true;
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
					List<Map<String, Object>> rawMemberUpdates = getOptionalListArgument(args, ARG_MEMBER_UPDATES)
							.orElseThrow(() -> {
								GhidraMcpError error = GhidraMcpError.validation()
										.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
										.message("Missing required argument: '" + ARG_MEMBER_UPDATES + "'")
										.context(new GhidraMcpError.ErrorContext(
												getMcpName(),
												"argument validation",
												Map.of(),
												Map.of("missingArgument", ARG_MEMBER_UPDATES),
												Map.of("argumentRequired", true)))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
														"Provide member updates array",
														"Include the memberUpdates array with at least one update definition",
														null,
														null)))
										.build();
								return new GhidraMcpException(error);
							});

					if (rawMemberUpdates.isEmpty()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Argument '" + ARG_MEMBER_UPDATES + "' cannot be empty")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"member updates validation",
										Map.of(ARG_MEMBER_UPDATES, rawMemberUpdates),
										Map.of("memberUpdatesLength", rawMemberUpdates.size()),
										Map.of("arrayEmpty", true)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Provide at least one member update",
												"Add at least one member update definition to the array",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					List<UnionMemberUpdateDefinition> memberUpdateDefs = rawMemberUpdates.stream()
							.map(rawDef -> new UnionMemberUpdateDefinition(
									getRequiredStringArgument(rawDef, ARG_MEMBER_NAME),
									getOptionalStringArgument(rawDef, ARG_NEW_MEMBER_NAME),
									getOptionalStringArgument(rawDef, ARG_NEW_DATA_TYPE_PATH),
									getOptionalStringArgument(rawDef, ARG_NEW_COMMENT)))
							.collect(Collectors.toList());

					DataType dt = program.getDataTypeManager().getDataType(unionPathString);
					if (dt == null) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Union not found at path: " + unionPathString)
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"union lookup",
										Map.of(ARG_UNION_PATH, unionPathString),
										Map.of("unionPath", unionPathString),
										Map.of("unionExists", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"List available data types",
												"Check what unions exist",
												null,
												List.of(getMcpName(GhidraListDataTypesTool.class)))))
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
										Map.of(ARG_UNION_PATH, unionPathString),
										Map.of("unionPath", unionPathString, "actualDataType", dt.getDisplayName()),
										Map.of("isUnion", false, "actualTypeName", dt.getClass().getSimpleName())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use a union data type",
												"Ensure the path points to a union, not " + dt.getClass().getSimpleName(),
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
					Union union = (Union) dt;

					for (UnionMemberUpdateDefinition def : memberUpdateDefs) {
						if (def.name().isBlank()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Member name to identify for update cannot be blank")
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"member name validation",
											Map.of(ARG_MEMBER_NAME, def.name()),
											Map.of("memberName", def.name()),
											Map.of("nameBlank", true)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Provide a valid member name",
													"Member names must not be blank",
													null,
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
						if (def.newName().isEmpty() && def.newDataTypePath().isEmpty() && def.newComment().isEmpty()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("No updates specified for member '" + def.name()
											+ "'. Provide at least one of 'newName', 'newDataTypePath', or 'newComment'")
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"member update validation",
											Map.of(ARG_MEMBER_NAME, def.name()),
											Map.of("memberName", def.name()),
											Map.of("noUpdatesProvided", true, "availableUpdateFields",
													List.of("newName", "newDataTypePath", "newComment"))))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Specify at least one update",
													"Provide at least one field to update",
													List.of("newName", "newDataTypePath", "newComment"),
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
					}

					return new UnionMemberUpdateBatchContext(program, tool, union, memberUpdateDefs);
				})
				.flatMap(context -> {
					String transactionName = "Update Union Members in " + context.union().getName();
					String unionPathName = context.union().getPathName();

					return executeInTransaction(context.program(), transactionName, () -> {
						int localMembersUpdatedCount = 0;
						try {
							for (UnionMemberUpdateDefinition updateDef : context.memberUpdateDefs()) {
								if (processSingleUnionMemberUpdate(context.union(), updateDef, context.program(), context.tool())) {
									localMembersUpdatedCount++;
								}
							}
							return localMembersUpdatedCount;
						} catch (GhidraMcpException e) {
							// Re-throw GhidraMcpException as-is to preserve structured error
							throw e;
						} catch (IllegalArgumentException e) {
							GhidraMcpError error = GhidraMcpError.execution()
									.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
									.message("Error updating union member: " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"union member update operation",
											Map.of(ARG_UNION_PATH, unionPathName),
											Map.of("unionPath", unionPathName, "errorMessage", e.getMessage()),
											Map.of("updatesFailed", true, "operationType", "union member update")))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
													"Verify union and member information",
													"Check that the union and members exist",
													null,
													List.of(getMcpName(GhidraListDataTypesTool.class)))))
									.build();
							throw new GhidraMcpException(error);
						} catch (Exception e) {
							throw new RuntimeException("Unexpected error updating a union member: " + e.getMessage(), e);
						}
					})
							.map(count -> {
								int updatedCount = (Integer) count;
								if (updatedCount > 0) {
									return "Updated " + updatedCount + " member(s) in union '" + unionPathName + "'.";
								} else {
									return "No effective changes applied to union '" + unionPathName + "'.";
								}
							});
				});
	}
}