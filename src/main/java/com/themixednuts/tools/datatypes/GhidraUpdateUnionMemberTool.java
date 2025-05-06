package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

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

@GhidraMcpTool(name = "Update Union Member", category = ToolCategory.DATATYPES, description = "Modifies the name, data type, or comment of an existing member in a union.", mcpName = "update_union_member", mcpDescription = "Modify an existing member within a union (name, type, comment).")
public class GhidraUpdateUnionMemberTool implements IGhidraMcpSpecification {

	private static record UnionUpdateContext(
			Program program,
			Union unionDt,
			int ordinalToDelete,
			String oldMemberName,
			DataType finalDataType,
			String finalName,
			String finalComment) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));
		schemaRoot.property(ARG_UNION_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the union containing the member (e.g., /MyCategory/MyUnion)"));
		// Use standard ARG_NAME for current member name
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The current name of the member to edit."));

		// Optional properties for updates using standard args
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new name for the member."));
		schemaRoot.property(ARG_DATA_TYPE_PATH, // Use standard ARG_DATA_TYPE_PATH for the new type
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new data type path (e.g., 'dword', '/MyStruct')."));
		schemaRoot.property(ARG_COMMENT, // Use standard ARG_COMMENT for the new comment
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new comment. Use empty string \"\" to clear."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_UNION_PATH)
				.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup
					String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
					String memberName = getRequiredStringArgument(args, ARG_NAME); // Current name
					Optional<String> newNameOpt = getOptionalStringArgument(args, ARG_NEW_NAME);
					// Use ARG_DATA_TYPE_PATH for the new type path
					Optional<String> newTypePathOpt = getOptionalStringArgument(args, ARG_DATA_TYPE_PATH);
					// Use ARG_COMMENT for the new comment
					Optional<String> newCommentOpt = getOptionalStringArgument(args, ARG_COMMENT);

					// Validate: At least one change specified
					if (newNameOpt.isEmpty() && newTypePathOpt.isEmpty() && newCommentOpt.isEmpty()) {
						throw new IllegalArgumentException(
								"No changes specified. Provide at least one 'newName', 'dataTypePath', or 'comment' argument.");
					}

					DataType dt = program.getDataTypeManager().getDataType(unionPathString);

					if (dt == null) {
						throw new IllegalArgumentException("Union not found at path: " + unionPathString);
					}
					if (!(dt instanceof Union)) {
						throw new IllegalArgumentException("Data type at path is not a Union: " + unionPathString);
					}
					Union unionDt = (Union) dt;

					// Find the component to update
					DataTypeComponent componentToUpdate = null;
					for (DataTypeComponent comp : unionDt.getComponents()) {
						// Use getFieldName() as name can technically be null, though unlikely for user
						// types
						String currentFieldName = comp.getFieldName();
						if (currentFieldName != null && currentFieldName.equals(memberName)) {
							componentToUpdate = comp;
							break;
						}
					}

					if (componentToUpdate == null) {
						throw new IllegalArgumentException("Member '" + memberName + "' not found in union: " + unionPathString);
					}

					// --- Determine final values ---
					String finalName = newNameOpt.orElse(componentToUpdate.getFieldName());
					String finalComment = newCommentOpt.orElse(componentToUpdate.getComment());
					DataType finalDataType;

					if (newTypePathOpt.isPresent()) {
						// Use getDataType, non-deprecated
						DataType newDt = program.getDataTypeManager().getDataType(newTypePathOpt.get());
						if (newDt == null) {
							throw new IllegalArgumentException("New data type not found: " + newTypePathOpt.get());
						}
						finalDataType = newDt;
					} else {
						finalDataType = componentToUpdate.getDataType();
					}

					return new UnionUpdateContext(program, unionDt, componentToUpdate.getOrdinal(), memberName,
							finalDataType, finalName, finalComment);
				})
				.flatMap(context -> { // .flatMap for transaction
					return executeInTransaction(context.program(), "Update Union Member " + context.oldMemberName(), () -> {

						// Delete the old component by ordinal
						context.unionDt().delete(context.ordinalToDelete());
						// Add the new/updated component
						DataTypeComponent addedComp = context.unionDt().add(context.finalDataType(), context.finalName(),
								context.finalComment());

						if (addedComp == null) {
							// This could happen if the new name conflicts after deleting the old one, etc.
							throw new RuntimeException("Failed to add updated member '" + context.finalName()
									+ "' back to union after deleting original.");
						}

						return "Union member '" + context.oldMemberName() + "' updated successfully (New name: '"
								+ context.finalName() + "').";
					});
				});
	}
}