package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(name = "Delete Struct Member", category = ToolCategory.DATATYPES, description = "Deletes a member from an existing structure.", mcpName = "delete_struct_member", mcpDescription = "Removes a field (member) from an existing struct data type by its offset.")
public class GhidraDeleteStructMemberTool implements IGhidraMcpSpecification {
	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_STRUCT_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the struct containing the member (e.g., /MyCategory/MyStruct)"));

		schemaRoot.property(ARG_OFFSET,
				JsonSchemaBuilder.integer(mapper)
						.description("The offset (in bytes) of the member to delete.")
						.minimum(0));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_STRUCT_PATH)
				.requiredProperty(ARG_OFFSET);

		return schemaRoot.build();
	}

	// Nested record for type-safe context passing
	private static record DeleteStructMemberContext(
			Program program,
			Structure structDt,
			Integer memberOffset) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) { // Ensure
																																																								// signature
		return getProgram(args, tool).map(program -> { // .map for sync setup
			String structPathString = getRequiredStringArgument(args, ARG_STRUCT_PATH);
			Integer memberOffset = getRequiredIntArgument(args, ARG_OFFSET);

			if (memberOffset < 0) {
				throw new IllegalArgumentException("Invalid memberOffset: Cannot be negative.");
			}

			DataType dt = program.getDataTypeManager().getDataType(structPathString);

			if (dt == null) {
				throw new IllegalArgumentException("Struct not found at path: " + structPathString);
			}
			if (!(dt instanceof Structure)) {
				throw new IllegalArgumentException("Data type at path is not a Structure: " + structPathString);
			}
			Structure structDt = (Structure) dt;

			// Check if component exists at offset BEFORE transaction
			DataTypeComponent component = structDt.getComponentAt(memberOffset);
			if (component == null) {
				throw new IllegalArgumentException("No struct member found starting exactly at offset: " + memberOffset);
			}

			// Return type-safe context
			return new DeleteStructMemberContext(program, structDt, memberOffset);

		}).flatMap(context -> { // .flatMap for transaction
			String structPathName = context.structDt().getPathName(); // Get path before transaction for message

			return executeInTransaction(context.program(), "MCP - Delete Struct Member at offset " + context.memberOffset(),
					() -> {
						// Use context fields
						context.structDt().deleteAtOffset(context.memberOffset());
						return "Struct member at offset " + context.memberOffset() + " deleted successfully from " + structPathName
								+ ".";
					});
		});
	}

}