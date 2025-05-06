package com.themixednuts.tools.datatypes;

import java.util.Map;

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

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) { // Ensure
																																																								// signature
		return getProgram(args, tool).map(program -> { // .map for sync setup
			String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
			String memberName = getRequiredStringArgument(args, ARG_NAME);

			DataType dt = program.getDataTypeManager().getDataType(unionPathString);

			if (dt == null) {
				throw new IllegalArgumentException("Union not found at path: " + unionPathString);
			}
			if (!(dt instanceof Union)) {
				throw new IllegalArgumentException("Data type at path is not a Union: " + unionPathString);
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
				throw new IllegalArgumentException(
						"Member '" + memberName + "' not found in union " + unionPathString + " (already deleted?).");
			}

			// Return type-safe context
			return new DeleteUnionMemberContext(program, unionDt, componentToDelete.getOrdinal());
		}).flatMap(context -> { // .flatMap for transaction
			String unionPathString = context.unionDt().getPathName(); // Get path before transaction for message

			return executeInTransaction(context.program(), "Delete Union Member (ordinal " + context.ordinalToDelete() + ")",
					() -> {
						// Use context fields
						context.unionDt().delete(context.ordinalToDelete());
						return "Union member deleted successfully from " + unionPathString + " (member ordinal was "
								+ context.ordinalToDelete()
								+ ").";
					});
		});
	}
}