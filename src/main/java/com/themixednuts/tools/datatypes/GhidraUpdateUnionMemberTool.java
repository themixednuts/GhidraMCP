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
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
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
								.description("Optional: New data type path for the member (e.g., 'dword', '/MyOtherStruct')."))
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
			Union union,
			List<UnionMemberUpdateDefinition> memberUpdateDefs) {
	}

	private boolean processSingleUnionMemberUpdate(Union union, UnionMemberUpdateDefinition updateDef, Program program) {
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
			throw new IllegalArgumentException(
					"No component found with name '" + updateDef.name() + "' in union '" + union.getPathName() + "'.");
		}

		String finalName = updateDef.newName().orElse(componentToUpdate.getFieldName());
		String finalComment = updateDef.newComment().orElse(componentToUpdate.getComment());
		DataType finalDataType;
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

		int finalSize = finalDataType.getLength();
		if (finalSize <= 0) {
			if (finalDataType.isEquivalent(componentToUpdate.getDataType())) {
				finalSize = componentToUpdate.getLength();
			}
			if (finalSize <= 0) {
				throw new IllegalArgumentException("Cannot determine positive size for final data type '"
						+ finalDataType.getPathName() + "' for member '" + updateDef.name() + "'.");
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
							.orElseThrow(
									() -> new IllegalArgumentException("Missing required argument: '" + ARG_MEMBER_UPDATES + "'"));

					if (rawMemberUpdates.isEmpty()) {
						throw new IllegalArgumentException("Argument '" + ARG_MEMBER_UPDATES + "' cannot be empty.");
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
						throw new IllegalArgumentException("Union not found at path: " + unionPathString);
					}
					if (!(dt instanceof Union)) {
						throw new IllegalArgumentException("Data type at path is not a Union: " + unionPathString);
					}
					Union union = (Union) dt;

					for (UnionMemberUpdateDefinition def : memberUpdateDefs) {
						if (def.name().isBlank()) {
							throw new IllegalArgumentException("Member name to identify for update cannot be blank.");
						}
						if (def.newName().isEmpty() && def.newDataTypePath().isEmpty() && def.newComment().isEmpty()) {
							throw new IllegalArgumentException(
									"No updates specified for member '" + def.name()
											+ "'. Provide at least one of 'newName', 'newDataTypePath', or 'newComment'.");
						}
					}

					return new UnionMemberUpdateBatchContext(program, union, memberUpdateDefs);
				})
				.flatMap(context -> {
					String transactionName = "Update Union Members in " + context.union().getName();
					String unionPathName = context.union().getPathName();

					return executeInTransaction(context.program(), transactionName, () -> {
						int localMembersUpdatedCount = 0;
						try {
							for (UnionMemberUpdateDefinition updateDef : context.memberUpdateDefs()) {
								if (processSingleUnionMemberUpdate(context.union(), updateDef, context.program())) {
									localMembersUpdatedCount++;
								}
							}
							return localMembersUpdatedCount;
						} catch (IllegalArgumentException e) {
							throw new IllegalArgumentException("Error updating a union member: " + e.getMessage(), e);
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