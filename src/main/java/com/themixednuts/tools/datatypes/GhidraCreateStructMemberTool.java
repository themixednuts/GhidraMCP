package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Struct Member", mcpName = "create_struct_member", category = ToolCategory.DATATYPES, description = "Adds a new field (member) to an existing struct data type at a specified offset.", mcpDescription = "Adds a new field (member) to an existing struct data type at a specified offset.")
public class GhidraCreateStructMemberTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));
		schemaRoot.property(ARG_STRUCT_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the structure to modify (e.g., /MyCategory/MyStruct)"));
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Name for the new member."));
		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the member's data type (e.g., 'dword', '/MyOtherStruct')."));
		schemaRoot.property(ARG_OFFSET,
				JsonSchemaBuilder.integer(mapper)
						.description("Optional offset for the new member within the struct. If omitted, the member is appended."));
		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new member."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_STRUCT_PATH)
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	private static record StructMemberContext(
			Program program,
			Structure struct,
			String memberName,
			DataType memberDataType,
			Optional<Integer> offsetOpt,
			Optional<String> commentOpt) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup
					String structPathString = getRequiredStringArgument(args, ARG_STRUCT_PATH);
					String memberName = getRequiredStringArgument(args, ARG_NAME);
					String memberTypePath = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
					Optional<Integer> offsetOpt = getOptionalIntArgument(args, ARG_OFFSET);
					Optional<String> commentOpt = getOptionalStringArgument(args, ARG_COMMENT);

					DataType dt = program.getDataTypeManager().getDataType(structPathString);

					if (dt == null) {
						throw new IllegalArgumentException("Structure not found at path: " + structPathString);
					}
					if (!(dt instanceof Structure)) {
						throw new IllegalArgumentException("Data type at path is not a Structure: " + structPathString);
					}
					Structure struct = (Structure) dt;

					DataType memberDataType = program.getDataTypeManager().getDataType(memberTypePath);
					if (memberDataType == null) {
						throw new IllegalArgumentException("Data type not found for member: " + memberTypePath);
					}

					return new StructMemberContext(program, struct, memberName, memberDataType, offsetOpt, commentOpt);
				})
				.flatMap(context -> { // .flatMap for transaction
					String transactionName = "Add Struct Member " + context.memberName();
					String structPathName = context.struct().getPathName(); // Get path name before transaction

					return executeInTransaction(context.program(), transactionName, () -> {
						if (context.offsetOpt().isPresent()) {
							int offset = context.offsetOpt().get();
							int length = context.memberDataType().getLength();
							if (length <= 0) { // Handle dynamically sized types like strings
								length = 1; // Default size, might need refinement
							}
							context.struct().insert(offset, context.memberDataType(), length, context.memberName(),
									context.commentOpt().orElse(null));
						} else {
							context.struct().add(context.memberDataType(), context.memberName(), context.commentOpt().orElse(null));
						}
						return "Member '" + context.memberName() + "' added to structure '" + structPathName + "'.";
					});
				});
	}
}