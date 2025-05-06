package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(name = "Create Union Member", mcpName = "create_union_member", category = ToolCategory.DATATYPES, description = "Adds a new member to an existing union data type.", mcpDescription = "Adds a new field (member) to an existing union data type.")
public class GhidraCreateUnionMemberTool implements IGhidraMcpSpecification {

	private static record UnionMemberContext(
			Program program,
			Union union,
			String memberName,
			DataType memberDataType,
			Optional<String> commentOpt) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_UNION_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the union to add the member to (e.g., /MyCategory/MyUnion)"));

		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name for the new member."));

		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the member's data type (e.g., 'dword', '/MyStruct')."));

		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new member."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_UNION_PATH)
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup
					String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
					String memberName = getRequiredStringArgument(args, ARG_NAME);
					String memberTypePath = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
					Optional<String> commentOpt = getOptionalStringArgument(args, ARG_COMMENT);

					DataType dt = program.getDataTypeManager().getDataType(unionPathString);

					if (dt == null) {
						throw new IllegalArgumentException("Union not found at path: " + unionPathString);
					}
					if (!(dt instanceof Union)) {
						throw new IllegalArgumentException("Data type at path is not a Union: " + unionPathString);
					}
					Union unionDt = (Union) dt;

					DataType memberDataType = program.getDataTypeManager().getDataType(memberTypePath);
					if (memberDataType == null) {
						throw new IllegalArgumentException("Member data type not found: " + memberTypePath);
					}

					return new UnionMemberContext(program, unionDt, memberName, memberDataType, commentOpt);
				})
				.flatMap(context -> { // .flatMap for transaction
					String unionPath = context.union().getPathName(); // Get before transaction
					return executeInTransaction(context.program(), "Add Union Member " + context.memberName(), () -> {
						DataTypeComponent addedComponent = context.union().add(context.memberDataType(), context.memberName(),
								context.commentOpt().orElse(null));

						if (addedComponent != null) {
							return "Member '" + context.memberName() + "' added successfully to union " + unionPath + ".";
						} else {
							throw new RuntimeException("Failed to add member '" + context.memberName() + "' to union " + unionPath
									+ ". Name/type conflict or other issue?");
						}
					});
				});
	}
}