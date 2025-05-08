package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;
import java.util.List;
import java.util.stream.Collectors;

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

@GhidraMcpTool(name = "Create Struct Members", mcpName = "create_struct_members", category = ToolCategory.DATATYPES, description = "Adds one or more new fields (members) to an existing struct data type.", mcpDescription = "Adds one or more new fields (members) to an existing struct data type.")
public class GhidraCreateStructMemberTool implements IGhidraMcpSpecification {

	// Argument for the array of members
	public static final String ARG_MEMBERS = "members";

	private static record StructMemberDefinition(
			String name,
			String dataTypePath,
			Optional<Integer> offset,
			Optional<String> comment) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		// Schema for a single member definition
		IObjectSchemaBuilder memberSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition of a single structure member to add.")
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Name for the new member."),
						true) // Required within member object
				.property(ARG_DATA_TYPE_PATH,
						JsonSchemaBuilder.string(mapper)
								.description("Full path or name of the member's data type (e.g., 'dword', '/MyOtherStruct')."),
						true) // Required within member object
				.property(ARG_OFFSET,
						JsonSchemaBuilder.integer(mapper)
								.description(
										"Optional offset for the new member within the struct. If omitted or -1, the member is appended."))
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional comment for the new member."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));
		schemaRoot.property(ARG_STRUCT_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the structure to modify (e.g., /MyCategory/MyStruct)"));
		// Add the array property
		schemaRoot.property(ARG_MEMBERS,
				JsonSchemaBuilder.array(mapper)
						.description("An array of member definitions to add to the structure.")
						.items(memberSchema)
						.minItems(1)); // Require at least one member

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_STRUCT_PATH)
				.requiredProperty(ARG_MEMBERS); // Make the array required

		return schemaRoot.build();
	}

	private static record StructMemberBatchContext(
			Program program,
			Structure struct,
			List<StructMemberDefinition> memberDefs) {
	}

	private void processSingleStructMemberCreation(Structure struct, StructMemberDefinition memberDef, Program program) {
		DataType memberDataType = program.getDataTypeManager().getDataType(memberDef.dataTypePath());
		if (memberDataType == null) {
			throw new IllegalArgumentException(
					"Data type not found for member '" + memberDef.name() + "': " + memberDef.dataTypePath());
		}

		if (memberDef.offset().isPresent()) {
			int offset = memberDef.offset().get();
			if (offset == -1) {
				struct.add(memberDataType, memberDef.name(), memberDef.comment().orElse(null));
			} else {
				int length = memberDataType.getLength();
				if (length <= 0) {
					length = 1;
				}
				struct.insert(offset, memberDataType, length, memberDef.name(), memberDef.comment().orElse(null));
			}
		} else {
			struct.add(memberDataType, memberDef.name(), memberDef.comment().orElse(null));
		}
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String structPathString = getRequiredStringArgument(args, ARG_STRUCT_PATH);
					List<Map<String, Object>> rawMemberDefs = getOptionalListArgument(args, ARG_MEMBERS)
							.orElseThrow(() -> new IllegalArgumentException("Missing required argument: '" + ARG_MEMBERS + "'"));

					if (rawMemberDefs.isEmpty()) {
						throw new IllegalArgumentException("Argument '" + ARG_MEMBERS + "' cannot be empty.");
					}

					List<StructMemberDefinition> memberDefs = rawMemberDefs.stream()
							.map(rawDef -> new StructMemberDefinition(
									getRequiredStringArgument(rawDef, ARG_NAME),
									getRequiredStringArgument(rawDef, ARG_DATA_TYPE_PATH),
									getOptionalIntArgument(rawDef, ARG_OFFSET),
									getOptionalStringArgument(rawDef, ARG_COMMENT)))
							.collect(Collectors.toList());

					DataType dt = program.getDataTypeManager().getDataType(structPathString);

					if (dt == null) {
						throw new IllegalArgumentException("Structure not found at path: " + structPathString);
					}
					if (!(dt instanceof Structure)) {
						throw new IllegalArgumentException("Data type at path is not a Structure: " + structPathString);
					}
					Structure struct = (Structure) dt;

					for (StructMemberDefinition def : memberDefs) {
						if (def.name().isBlank()) {
							throw new IllegalArgumentException("Member name cannot be blank.");
						}
						if (def.dataTypePath().isBlank()) {
							throw new IllegalArgumentException(
									"Member data type path cannot be blank for member '" + def.name() + "'.");
						}
					}

					return new StructMemberBatchContext(program, struct, memberDefs);
				})
				.flatMap(context -> {
					String transactionName = "Add Struct Members to " + context.struct().getName();
					String structPathName = context.struct().getPathName();

					return executeInTransaction(context.program(), transactionName, () -> {
						int localMembersAddedCount = 0;
						try {
							for (StructMemberDefinition memberDef : context.memberDefs()) {
								processSingleStructMemberCreation(context.struct(), memberDef, context.program());
								localMembersAddedCount++;
							}
							return localMembersAddedCount;
						} catch (IndexOutOfBoundsException e) {
							String currentMemberNameForError = "<unknown_member_causing_error>";
							throw new IllegalArgumentException(
									"Failed adding member (likely '" + currentMemberNameForError + "') to structure '" + structPathName
											+ "'. Offset is out of bounds.",
									e);
						} catch (IllegalArgumentException e) {
							throw new IllegalArgumentException("Error processing a member: " + e.getMessage(), e);
						} catch (Exception e) {
							throw new RuntimeException("Unexpected error processing a member: " + e.getMessage(), e);
						}
					}).map(count -> {
						int addedCount = (Integer) count;
						return "Added " + addedCount + " member(s) to structure '" + structPathName + "'.";
					});
				});
	}
}