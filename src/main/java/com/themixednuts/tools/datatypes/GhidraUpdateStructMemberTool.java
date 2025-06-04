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
import com.themixednuts.utils.DataTypeUtils;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Struct Members", mcpName = "update_struct_members", category = ToolCategory.DATATYPES, description = "Updates one or more fields (members) in an existing struct data type.", mcpDescription = "Updates the name, data type, and/or comment of one or more existing fields (members) in a struct.")
public class GhidraUpdateStructMemberTool implements IGhidraMcpSpecification {

	// Arguments
	public static final String ARG_MEMBER_UPDATES = "memberUpdates";
	// Member updates sub-arguments
	public static final String ARG_MEMBER_OFFSET = "offset"; // Identify by offset
	public static final String ARG_NEW_DATA_TYPE_PATH = "newDataTypePath";
	public static final String ARG_NEW_COMMENT = "newComment";

	private static record StructMemberUpdateDefinition(
			Optional<Integer> offset,
			Optional<String> name,
			Optional<String> newName,
			Optional<String> newDataTypePath,
			Optional<String> newComment) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		// Define the schema for a single member update
		IObjectSchemaBuilder updateSchema = JsonSchemaBuilder.object(mapper)
				// Identifiers: Must provide either offset or name
				.property(ARG_MEMBER_OFFSET,
						JsonSchemaBuilder.integer(mapper)
								.description("Offset of the member to update. Required if 'name' is not provided.")
								.minimum(0))
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Current name of the member to update. Required if 'offset' is not provided."))
				// Updates: Must provide at least one
				.property(ARG_NEW_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: New name for the member."))
				.property(ARG_NEW_DATA_TYPE_PATH,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: New data type path for the member (e.g., 'dword', '/MyOtherStruct', 'int[5]', 'char *'). Array and pointer notations are supported."))
				.property(ARG_NEW_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: New comment for the member. An empty string clears the comment."));

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));
		schemaRoot.property(ARG_STRUCT_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the structure to modify (e.g., /MyCategory/MyStruct)"));
		// Add the array property
		schemaRoot.property(ARG_MEMBER_UPDATES,
				JsonSchemaBuilder.array(mapper)
						.description("An array of member update definitions.")
						.items(updateSchema)
						.minItems(1)); // Require at least one update

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_STRUCT_PATH)
				.requiredProperty(ARG_MEMBER_UPDATES);

		return schemaRoot.build();
	}

	// Context to hold details needed for the transaction
	private static record StructMemberUpdateBatchContext(
			Program program,
			PluginTool tool,
			Structure struct,
			List<StructMemberUpdateDefinition> memberUpdateDefs) {
	}

	private boolean processSingleStructMemberUpdate(Structure struct, StructMemberUpdateDefinition updateDef,
			Program program, PluginTool tool) {
		DataTypeComponent componentToUpdate = null;
		String identifierForError;

		if (updateDef.offset().isPresent()) {
			int offset = updateDef.offset().get();
			identifierForError = "offset " + offset;
			componentToUpdate = struct.getComponentAt(offset);
			if (componentToUpdate == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("No component found starting exactly at " + identifierForError)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"struct member lookup by offset",
								Map.of(ARG_STRUCT_PATH, struct.getPathName(), ARG_MEMBER_OFFSET, offset),
								Map.of("searchedOffset", offset),
								Map.of("structSize", struct.getLength(), "memberExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Check existing struct members",
										"View the current members and their offsets in this structure",
										null,
										List.of(getMcpName(GhidraGetDataTypeTool.class)))))
						.build();
				throw new GhidraMcpException(error);
			}
			if (updateDef.name().isPresent() && !updateDef.name().get().equals(componentToUpdate.getFieldName())) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
						.message("Member name '" + updateDef.name().get() + "' does not match component at " + identifierForError
								+ " (found: '" + componentToUpdate.getFieldName() + "')")
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"member name validation",
								Map.of(ARG_MEMBER_OFFSET, offset, ARG_NAME, updateDef.name().get()),
								Map.of("providedName", updateDef.name().get(), "actualName", componentToUpdate.getFieldName()),
								Map.of("offset", offset, "nameMatch", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use correct member name",
										"Provide the actual name of the member at this offset",
										List.of("\"" + ARG_NAME + "\": \"" + componentToUpdate.getFieldName() + "\""),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}
		} else if (updateDef.name().isPresent()) {
			String name = updateDef.name().get();
			identifierForError = "name '" + name + "'";
			for (DataTypeComponent comp : struct.getDefinedComponents()) {
				if (name.equals(comp.getFieldName())) {
					componentToUpdate = comp;
					break;
				}
			}
			if (componentToUpdate == null) {
				List<String> availableNames = java.util.Arrays.stream(struct.getDefinedComponents())
						.map(DataTypeComponent::getFieldName)
						.filter(n -> n != null && !n.trim().isEmpty())
						.limit(10)
						.collect(Collectors.toList());

				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("No component found with " + identifierForError)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"struct member lookup by name",
								Map.of(ARG_STRUCT_PATH, struct.getPathName(), ARG_NAME, name),
								Map.of("searchedName", name),
								Map.of("structSize", struct.getLength(), "memberCount", struct.getNumDefinedComponents(),
										"memberExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Check existing struct members",
										"View the current members in this structure",
										null,
										List.of(getMcpName(GhidraGetDataTypeTool.class))),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.SIMILAR_VALUES,
										"Use an existing member name",
										"Available member names in this structure",
										availableNames.isEmpty() ? List.of("(no named members found)") : availableNames,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}
		} else {
			throw new IllegalStateException("Missing identifier (offset or name) for a struct member update.");
		}

		int targetOffset = componentToUpdate.getOffset();
		String finalName = updateDef.newName().orElse(componentToUpdate.getFieldName());
		String finalComment = updateDef.newComment().orElse(componentToUpdate.getComment());
		DataType finalDataType;
		int finalSize;
		boolean dataTypeChanged = false;

		if (updateDef.newDataTypePath().isPresent()) {
			String newDataTypePathStr = updateDef.newDataTypePath().get();
			try {
				DataType newDt = DataTypeUtils.parseDataTypeString(program, newDataTypePathStr, tool);
				finalDataType = newDt;
				dataTypeChanged = !finalDataType.isEquivalent(componentToUpdate.getDataType());
			} catch (IllegalArgumentException e) {
				GhidraMcpError error = GhidraMcpError.dataTypeParsing()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
						.message("Error parsing new data type path '" + newDataTypePathStr + "': " + e.getMessage())
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"data type parsing",
								Map.of(ARG_NEW_DATA_TYPE_PATH, newDataTypePathStr),
								Map.of("providedPath", newDataTypePathStr),
								Map.of("parseError", e.getMessage())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Check data type path format",
										"Ensure the data type path follows the correct syntax",
										List.of("\"int\"", "\"/MyCategory/MyStruct\"", "\"int[5]\"", "\"char *\""),
										null)))
						.build();
				throw new GhidraMcpException(error);
			} catch (InvalidDataTypeException e) {
				GhidraMcpError error = GhidraMcpError.dataTypeParsing()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
						.message("Invalid new data type format for '" + newDataTypePathStr + "': " + e.getMessage())
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"data type validation",
								Map.of(ARG_NEW_DATA_TYPE_PATH, newDataTypePathStr),
								Map.of("providedPath", newDataTypePathStr),
								Map.of("validationError", e.getMessage())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify data type exists",
										"Check if the data type exists in the program",
										null,
										List.of(getMcpName(GhidraListDataTypesTool.class),
												getMcpName(GhidraGetDataTypeTool.class)))))
						.build();
				throw new GhidraMcpException(error);
			} catch (CancelledException e) {
				throw new RuntimeException(
						"Parsing cancelled for new data type path '" + newDataTypePathStr + "': " + e.getMessage(), e);
			} catch (RuntimeException e) {
				throw new RuntimeException(
						"Unexpected runtime error parsing new data type path '" + newDataTypePathStr + "': " + e.getMessage(), e);
			}
		} else {
			finalDataType = componentToUpdate.getDataType();
		}

		finalSize = finalDataType.getLength();
		if (finalSize <= 0) {
			if (finalDataType.isEquivalent(componentToUpdate.getDataType())) {
				finalSize = componentToUpdate.getLength();
			}
			if (finalSize <= 0) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.TYPE_SIZE_MISMATCH)
						.message("Cannot determine positive size for final data type '"
								+ finalDataType.getPathName() + "' for member identified by " + identifierForError)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"data type size validation",
								Map.of("memberIdentifier", identifierForError, "dataTypePath", finalDataType.getPathName()),
								Map.of("calculatedSize", finalSize),
								Map.of("dataTypeName", finalDataType.getName(), "sizeValid", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use a data type with known size",
										"Choose a data type that has a defined size",
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

		struct.replaceAtOffset(targetOffset, finalDataType, finalSize, finalName, finalComment);
		return true;
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String structPathString = getRequiredStringArgument(args, ARG_STRUCT_PATH);
					List<Map<String, Object>> rawMemberUpdates = getOptionalListArgument(args, ARG_MEMBER_UPDATES)
							.orElse(null);

					if (rawMemberUpdates == null) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
								.message("Missing required argument: '" + ARG_MEMBER_UPDATES + "'")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"argument validation",
										args,
										Map.of(),
										Map.of("requiredArgument", ARG_MEMBER_UPDATES, "provided", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Provide member updates",
												"Include the memberUpdates array with at least one update definition",
												List.of("\"" + ARG_MEMBER_UPDATES + "\": [{\"" + ARG_MEMBER_OFFSET + "\": 0, \"" + ARG_NEW_NAME
														+ "\": \"newName\"}]"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					if (rawMemberUpdates.isEmpty()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Argument '" + ARG_MEMBER_UPDATES + "' cannot be empty")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"argument validation",
										args,
										Map.of(ARG_MEMBER_UPDATES, rawMemberUpdates),
										Map.of("arraySize", 0, "minimumRequired", 1)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Add member update definitions",
												"Provide at least one member update in the array",
												List.of("\"" + ARG_MEMBER_UPDATES + "\": [{\"" + ARG_MEMBER_OFFSET + "\": 0, \"" + ARG_NEW_NAME
														+ "\": \"newName\"}]"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					List<StructMemberUpdateDefinition> memberUpdateDefs = rawMemberUpdates.stream()
							.map(rawDef -> new StructMemberUpdateDefinition(
									getOptionalIntArgument(rawDef, ARG_MEMBER_OFFSET),
									getOptionalStringArgument(rawDef, ARG_NAME),
									getOptionalStringArgument(rawDef, ARG_NEW_NAME),
									getOptionalStringArgument(rawDef, ARG_NEW_DATA_TYPE_PATH),
									getOptionalStringArgument(rawDef, ARG_NEW_COMMENT)))
							.collect(Collectors.toList());

					DataType dt = program.getDataTypeManager().getDataType(structPathString);
					if (dt == null) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Structure not found at path: " + structPathString)
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"structure lookup",
										args,
										Map.of(ARG_STRUCT_PATH, structPathString),
										Map.of("searchedPath", structPathString, "dataTypeExists", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify the structure path",
												"Check if the structure exists at the specified path",
												null,
												List.of(getMcpName(GhidraListDataTypesTool.class),
														getMcpName(GhidraGetDataTypeTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}
					if (!(dt instanceof Structure)) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Data type at path is not a Structure: " + structPathString)
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"data type validation",
										args,
										Map.of(ARG_STRUCT_PATH, structPathString, "actualDataType", dt.getClass().getSimpleName()),
										Map.of("expectedType", "Structure", "actualType", dt.getClass().getSimpleName(), "dataTypeName",
												dt.getName())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.USE_DIFFERENT_TOOL,
												"Use the appropriate tool for this data type",
												"This data type requires a different update operation",
												null,
												List.of(getMcpName(GhidraUpdateUnionMemberTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}
					Structure struct = (Structure) dt;

					for (StructMemberUpdateDefinition def : memberUpdateDefs) {
						if (def.offset().isEmpty() && def.name().isEmpty()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
									.message("Must provide either '" + ARG_MEMBER_OFFSET + "' or '" + ARG_NAME + "' to identify a member")
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"member identifier validation",
											args,
											Map.of(),
											Map.of("offsetProvided", false, "nameProvided", false, "identifierRequired", true)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Provide a member identifier",
													"Include either offset or name to identify the member to update",
													List.of("\"" + ARG_MEMBER_OFFSET + "\": 0", "\"" + ARG_NAME + "\": \"memberName\""),
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
						if (def.newName().isEmpty() && def.newDataTypePath().isEmpty() && def.newComment().isEmpty()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
									.message(
											"No updates specified for a member. Provide at least one of 'newName', 'newDataTypePath', or 'newComment'")
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"update specification validation",
											args,
											Map.of(),
											Map.of("newNameProvided", false, "newDataTypeProvided", false, "newCommentProvided", false,
													"updateRequired", true)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Specify what to update",
													"Include at least one field to update",
													List.of("\"" + ARG_NEW_NAME + "\": \"newName\"",
															"\"" + ARG_NEW_DATA_TYPE_PATH + "\": \"int\"",
															"\"" + ARG_NEW_COMMENT + "\": \"new comment\""),
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
					}

					return new StructMemberUpdateBatchContext(program, tool, struct, memberUpdateDefs);
				})
				.flatMap(context -> {
					String transactionName = "Update Struct Members in " + context.struct().getName();
					String structPathName = context.struct().getPathName();

					return executeInTransaction(context.program(), transactionName, () -> {
						int localMembersUpdatedCount = 0;
						try {
							for (StructMemberUpdateDefinition updateDef : context.memberUpdateDefs()) {
								if (processSingleStructMemberUpdate(context.struct(), updateDef, context.program(),
										context.tool())) {
									localMembersUpdatedCount++;
								}
							}
							return localMembersUpdatedCount;
						} catch (GhidraMcpException e) {
							throw e; // Re-throw structured errors as-is
						} catch (Exception e) {
							throw new RuntimeException("Unexpected error updating a struct member: " + e.getMessage(), e);
						}
					})
							.map(count -> {
								int updatedCount = (Integer) count;
								if (updatedCount > 0) {
									return "Updated " + updatedCount + " member(s) in structure '" + structPathName + "'.";
								} else {
									return "No effective changes applied to structure '" + structPathName + "'.";
								}
							});
				});
	}
}