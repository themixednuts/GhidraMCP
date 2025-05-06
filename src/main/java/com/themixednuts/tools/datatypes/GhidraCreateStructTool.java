package com.themixednuts.tools.datatypes;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(name = "Create Struct", category = ToolCategory.DATATYPES, description = "Creates a new struct data type.", mcpName = "create_struct", mcpDescription = "Defines a new struct data type, optionally pre-populated with members.")
public class GhidraCreateStructTool implements IGhidraMcpSpecification {

	public static final String ARG_MEMBERS = "members";

	private record MemberDefinition(
			String name,
			DataType dataType,
			Optional<Integer> sizeOpt, // Keep optional size if provided
			Optional<Integer> offsetOpt,
			Optional<String> commentOpt) {
	}

	private record StructContext(
			Program program,
			CategoryPath categoryPath,
			String structName,
			String originalPath,
			List<MemberDefinition> resolvedMembers) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_STRUCT_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path for the new struct (e.g., /MyCategory/MyStruct)"));

		// Schema for a single member definition
		IObjectSchemaBuilder memberSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition for a single struct member.")
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Name for the new member."))
				.property(ARG_DATA_TYPE_PATH,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Full path or name of the member's data type (e.g., /Category/TypeName, or built-in like 'int', 'char*')."))
				.property(ARG_SIZE,
						JsonSchemaBuilder.integer(mapper)
								.description(
										"Optional explicit size for the member in bytes. If omitted, the default size of the member type is used.")
								.minimum(1))
				.property(ARG_OFFSET,
						JsonSchemaBuilder.integer(mapper)
								.description(
										"Optional offset within the struct to insert the member. If omitted, adds to the end.")
								.minimum(0))
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional comment for the new member."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		// Optional members array property using ARG_MEMBERS
		schemaRoot.property(ARG_MEMBERS,
				JsonSchemaBuilder.array(mapper)
						.items(memberSchema)
						.description("Optional list of members to add to the new struct."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_STRUCT_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // Synchronous setup and resolution
					String structPathString = getRequiredStringArgument(args, ARG_STRUCT_PATH);
					Optional<List<Map<String, Object>>> membersListOpt = getOptionalListArgument(args, ARG_MEMBERS);

					// Parse path
					CategoryPath fullPath = new CategoryPath(structPathString);
					CategoryPath categoryPath = fullPath.getParent(); // Can be null if root
					String structName = fullPath.getName();
					if (structName.isBlank()) {
						throw new IllegalArgumentException("Invalid struct path: Name cannot be blank.");
					}
					// Ensure categoryPath is ROOT if parent was null
					if (categoryPath == null) {
						categoryPath = CategoryPath.ROOT;
					}

					DataTypeManager dtm = program.getDataTypeManager();

					// Resolve members BEFORE transaction
					List<MemberDefinition> resolvedMembers = new ArrayList<>();
					if (membersListOpt.isPresent()) {
						for (Map<String, Object> memberMap : membersListOpt.get()) {
							String memberName = getRequiredStringArgument(memberMap, ARG_NAME);
							String memberTypePath = getRequiredStringArgument(memberMap, ARG_DATA_TYPE_PATH);
							Optional<Integer> memberSizeOpt = getOptionalIntArgument(memberMap, ARG_SIZE);
							Optional<Integer> offsetOpt = getOptionalIntArgument(memberMap, ARG_OFFSET);
							Optional<String> commentOpt = getOptionalStringArgument(memberMap, ARG_COMMENT);

							// Use getDataType (non-deprecated)
							DataType memberDataType = dtm.getDataType(memberTypePath);
							if (memberDataType == null) {
								throw new IllegalArgumentException(
										"Data type not found for member '" + memberName + "': " + memberTypePath);
							}

							resolvedMembers
									.add(new MemberDefinition(memberName, memberDataType, memberSizeOpt, offsetOpt, commentOpt));
						}
					}

					// Return context for the transaction
					return new StructContext(program, categoryPath, structName, structPathString, resolvedMembers);

				})
				.flatMap(context -> { // Transactional part
					return executeInTransaction(context.program(), "Create Struct " + context.structName(), () -> {
						DataTypeManager dtm = context.program().getDataTypeManager();

						// Check existence *inside* transaction
						if (dtm.getDataType(context.categoryPath(), context.structName()) != null) {
							throw new IllegalArgumentException(
									"Struct already exists (checked in transaction): " + context.originalPath());
						}

						// Ensure category exists *inside* transaction
						Category category = dtm.createCategory(context.categoryPath());
						if (category == null) {
							// This should ideally not happen if path was valid, but handle defensively
							category = dtm.getCategory(context.categoryPath());
							if (category == null) {
								throw new RuntimeException(
										"Failed to create or find category in transaction: " + context.categoryPath());
							}
						}

						// Create the new empty structure in the correct category
						StructureDataType newStruct = new StructureDataType(category.getCategoryPath(), context.structName(), 0,
								dtm);

						// Add resolved members
						for (MemberDefinition member : context.resolvedMembers()) {
							try {
								// Determine size: Use explicit if valid, else default, else error
								int size = member.sizeOpt().orElse(member.dataType().getLength());
								if (size <= 0) {
									// Default size didn't work, throw error
									throw new IllegalArgumentException("Cannot determine valid size for member '" + member.name()
											+ "' with type " + member.dataType().getPathName() + ". Provide explicit size.");
								}

								if (member.offsetOpt().isPresent()) {
									newStruct.insertAtOffset(member.offsetOpt().get(), member.dataType(), size, member.name(),
											member.commentOpt().orElse(null));
								} else {
									newStruct.add(member.dataType(), size, member.name(), member.commentOpt().orElse(null));
								}
							} catch (IllegalArgumentException e) {
								// Re-throw with more context
								throw new IllegalArgumentException(
										"Failed to add member '" + member.name() + "' to struct: " + e.getMessage(), e);
							}
						}

						// Add the new structure to the manager
						DataType addedType = dtm.addDataType(newStruct, DataTypeConflictHandler.DEFAULT_HANDLER);

						if (addedType instanceof Structure) {
							return "Struct '" + context.originalPath() + "' created successfully.";
						} else {
							throw new RuntimeException(
									"Failed to add struct '" + context.originalPath() + "' after creation (unexpected conflict?).");
						}
					}); // End executeInTransaction
				}); // End flatMap
	}
}