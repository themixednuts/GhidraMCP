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
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Union Members", mcpName = "create_union_members", category = ToolCategory.DATATYPES, description = "Adds one or more new fields (members) to an existing union data type.", mcpDescription = "Adds one or more new fields (members) to an existing union data type.")
public class GhidraCreateUnionMemberTool implements IGhidraMcpSpecification {

	// Argument for the array of members
	public static final String ARG_MEMBERS = "members";

	private static record UnionMemberDefinition(
			String name,
			String dataTypePath,
			Optional<String> comment) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		// Schema for a single member definition
		IObjectSchemaBuilder memberSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition of a single union member to add.")
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Name for the new member."),
						true)
				.property(ARG_DATA_TYPE_PATH,
						JsonSchemaBuilder.string(mapper)
								.description("Full path or name of the member\'s data type (e.g., 'dword', '/MyOtherStruct')."),
						true)
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional comment for the new member."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));
		schemaRoot.property(ARG_UNION_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the union to modify (e.g., /MyCategory/MyUnion)"));
		// Add the array property
		schemaRoot.property(ARG_MEMBERS,
				JsonSchemaBuilder.array(mapper)
						.description("An array of member definitions to add to the union.")
						.items(memberSchema)
						.minItems(1)); // Require at least one member

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_UNION_PATH)
				.requiredProperty(ARG_MEMBERS);

		return schemaRoot.build();
	}

	private static record UnionMemberBatchContext(
			Program program,
			Union union,
			List<UnionMemberDefinition> memberDefs) {
	}

	private void processSingleUnionMemberCreation(Union union, UnionMemberDefinition memberDef, Program program) {
		DataType memberDataType = program.getDataTypeManager().getDataType(memberDef.dataTypePath());
		if (memberDataType == null) {
			throw new IllegalArgumentException(
					"Data type not found for member '" + memberDef.name() + "': " + memberDef.dataTypePath());
		}
		union.add(memberDataType, memberDef.name(), memberDef.comment().orElse(null));
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
					List<Map<String, Object>> rawMemberDefs = getOptionalListArgument(args, ARG_MEMBERS)
							.orElseThrow(() -> new IllegalArgumentException("Missing required argument: '" + ARG_MEMBERS + "'"));

					if (rawMemberDefs.isEmpty()) {
						throw new IllegalArgumentException("Argument '" + ARG_MEMBERS + "' cannot be empty.");
					}

					List<UnionMemberDefinition> memberDefs = rawMemberDefs.stream()
							.map(rawDef -> new UnionMemberDefinition(
									getRequiredStringArgument(rawDef, ARG_NAME),
									getRequiredStringArgument(rawDef, ARG_DATA_TYPE_PATH),
									getOptionalStringArgument(rawDef, ARG_COMMENT)))
							.collect(Collectors.toList());

					DataType dt = program.getDataTypeManager().getDataType(unionPathString);

					if (dt == null) {
						throw new IllegalArgumentException("Union not found at path: " + unionPathString);
					}
					if (!(dt instanceof Union)) {
						throw new IllegalArgumentException("Data type at path is not a Union: " + unionPathString);
					}
					Union union = (Union) dt;

					for (UnionMemberDefinition def : memberDefs) {
						if (def.name().isBlank()) {
							throw new IllegalArgumentException("Union member name cannot be blank.");
						}
						if (def.dataTypePath().isBlank()) {
							throw new IllegalArgumentException(
									"Union member data type path cannot be blank for member '" + def.name() + "'.");
						}
					}

					return new UnionMemberBatchContext(program, union, memberDefs);
				})
				.flatMap(context -> {
					String transactionName = "Add Union Members to " + context.union().getName();
					String unionPathName = context.union().getPathName();

					return executeInTransaction(context.program(), transactionName, () -> {
						int localMembersAddedCount = 0;
						try {
							for (UnionMemberDefinition memberDef : context.memberDefs()) {
								processSingleUnionMemberCreation(context.union(), memberDef, context.program());
								localMembersAddedCount++;
							}
							return localMembersAddedCount;
						} catch (IllegalArgumentException e) {
							throw new IllegalArgumentException("Error processing a union member: " + e.getMessage(), e);
						} catch (Exception e) {
							throw new RuntimeException("Unexpected error processing a union member: " + e.getMessage(), e);
						}
					})
							.map(count -> {
								int addedCount = (Integer) count;
								return "Added " + addedCount + " member(s) to union '" + unionPathName + "'.";
							});
				});
	}
}