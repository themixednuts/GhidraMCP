package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Struct Members", mcpName = "update_struct_members", category = ToolCategory.DATATYPES, description = "Updates one or more fields (members) in an existing struct data type.", mcpDescription = "Updates the name, data type, and/or comment of one or more existing fields (members) in a struct.")
public class GhidraUpdateStructMemberTool implements IGhidraMcpSpecification {

	// Argument for the array of member updates
	public static final String ARG_MEMBER_UPDATES = "memberUpdates";
	// Arguments for identifying the member and the updates
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

		// Schema for a single member update definition
		IObjectSchemaBuilder updateSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition of updates for a single structure member.")
				// Identification (choose one)
				.property(ARG_MEMBER_OFFSET,
						JsonSchemaBuilder.integer(mapper)
								.description("Offset of the member to update. Required if 'name' is not provided."))
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Current name of the member to update. Required if 'offset' is not provided."))
				// Optional Updates
				.property(ARG_NEW_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: New name for the member."))
				.property(ARG_NEW_DATA_TYPE_PATH,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: New data type path for the member (e.g., 'dword', '/MyOtherStruct')."))
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
			Structure struct,
			List<StructMemberUpdateDefinition> memberUpdateDefs) {
	}

	private boolean processSingleStructMemberUpdate(Structure struct, StructMemberUpdateDefinition updateDef,
			Program program) {
		DataTypeComponent componentToUpdate = null;
		String identifierForError;

		if (updateDef.offset().isPresent()) {
			int offset = updateDef.offset().get();
			identifierForError = "offset " + offset;
			componentToUpdate = struct.getComponentAt(offset);
			if (componentToUpdate == null) {
				throw new IllegalArgumentException("No component found starting exactly at " + identifierForError);
			}
			if (updateDef.name().isPresent() && !updateDef.name().get().equals(componentToUpdate.getFieldName())) {
				throw new IllegalArgumentException(
						"Member name '" + updateDef.name().get() + "' does not match component at " + identifierForError
								+ " (found: '" + componentToUpdate.getFieldName() + "')");
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
				throw new IllegalArgumentException("No component found with " + identifierForError);
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
			DataType newDt = program.getDataTypeManager().getDataType(updateDef.newDataTypePath().get());
			if (newDt == null) {
				throw new IllegalArgumentException("New data type not found: " + updateDef.newDataTypePath().get());
			}
			finalDataType = newDt;
			dataTypeChanged = !finalDataType.isEquivalent(componentToUpdate.getDataType());
		} else {
			finalDataType = componentToUpdate.getDataType();
		}

		finalSize = finalDataType.getLength();
		if (finalSize <= 0) {
			if (finalDataType.isEquivalent(componentToUpdate.getDataType())) {
				finalSize = componentToUpdate.getLength();
			}
			if (finalSize <= 0) {
				throw new IllegalArgumentException("Cannot determine positive size for final data type '"
						+ finalDataType.getPathName() + "' for member identified by " + identifierForError);
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
							.orElseThrow(
									() -> new IllegalArgumentException("Missing required argument: '" + ARG_MEMBER_UPDATES + "'"));

					if (rawMemberUpdates.isEmpty()) {
						throw new IllegalArgumentException("Argument '" + ARG_MEMBER_UPDATES + "' cannot be empty.");
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
						throw new IllegalArgumentException("Structure not found at path: " + structPathString);
					}
					if (!(dt instanceof Structure)) {
						throw new IllegalArgumentException("Data type at path is not a Structure: " + structPathString);
					}
					Structure struct = (Structure) dt;

					for (StructMemberUpdateDefinition def : memberUpdateDefs) {
						if (def.offset().isEmpty() && def.name().isEmpty()) {
							throw new IllegalArgumentException(
									"Must provide either '" + ARG_MEMBER_OFFSET + "' or '" + ARG_NAME + "' to identify a member.");
						}
						if (def.newName().isEmpty() && def.newDataTypePath().isEmpty() && def.newComment().isEmpty()) {
							throw new IllegalArgumentException(
									"No updates specified for a member. Provide at least one of 'newName', 'newDataTypePath', or 'newComment'.");
						}
					}

					return new StructMemberUpdateBatchContext(program, struct, memberUpdateDefs);
				})
				.flatMap(context -> {
					String transactionName = "Update Struct Members in " + context.struct().getName();
					String structPathName = context.struct().getPathName();

					return executeInTransaction(context.program(), transactionName, () -> {
						int localMembersUpdatedCount = 0;
						try {
							for (StructMemberUpdateDefinition updateDef : context.memberUpdateDefs()) {
								if (processSingleStructMemberUpdate(context.struct(), updateDef, context.program())) {
									localMembersUpdatedCount++;
								}
							}
							return localMembersUpdatedCount;
						} catch (IllegalArgumentException e) {
							throw new IllegalArgumentException("Error updating a struct member: " + e.getMessage(), e);
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