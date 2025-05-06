package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

// import java.util.stream.Collectors; // Unused

// import com.fasterxml.jackson.annotation.JsonProperty; // Unused
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IArraySchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
// Specific Imports
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Union", mcpName = "create_union", category = ToolCategory.DATATYPES, description = "Defines a new union data type, optionally pre-populated with members.", mcpDescription = "Defines a new union data type, optionally pre-populated with members.")
public class GhidraCreateUnionTool implements IGhidraMcpSpecification {

	// Keep ARG_MEMBERS as it's specific to the list of definitions
	public static final String ARG_MEMBERS = "members";

	// Simplified record for pre-resolved member details
	private record ResolvedUnionMember(
			String name,
			DataType dataType,
			Optional<String> commentOpt) {
	}

	// Context for passing data between stages
	private record UnionContext(
			Program program,
			CategoryPath categoryPath,
			String unionName,
			String originalPath,
			List<ResolvedUnionMember> resolvedMembers) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));
		schemaRoot.property(ARG_UNION_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path for the new union (e.g., /MyCategory/MyUnion)")
						.pattern("^/.+"));

		// Define schema for individual members using standard ARG constants
		IObjectSchemaBuilder memberSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition for a single union member.")
				.property(ARG_DATA_TYPE_PATH, JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the member's data type (e.g., 'dword', '/MyStruct')."))
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
						.description("Name for the new member."))
				.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new member."))
				.requiredProperty(ARG_DATA_TYPE_PATH)
				.requiredProperty(ARG_NAME);

		// Define the optional array of members using ARG_MEMBERS
		IArraySchemaBuilder membersArraySchema = JsonSchemaBuilder.array(mapper)
				.description("Optional list of members to add to the new union.")
				.items(memberSchema);

		schemaRoot.property(ARG_MEMBERS, membersArraySchema);

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_UNION_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup
					String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
					Optional<List<Map<String, Object>>> rawMemberDefsOpt = getOptionalListArgument(args, ARG_MEMBERS);

					// Parse Path
					CategoryPath fullPath = new CategoryPath(unionPathString);
					CategoryPath categoryPath = fullPath.getParent();
					String unionName = fullPath.getName();
					if (unionName.isBlank()) {
						throw new IllegalArgumentException("Union name cannot be blank in path: " + unionPathString);
					}
					if (categoryPath == null) {
						categoryPath = CategoryPath.ROOT;
					}

					// Resolve member data types beforehand
					List<ResolvedUnionMember> resolvedMembers = new ArrayList<>();
					if (rawMemberDefsOpt.isPresent()) {
						for (Map<String, Object> memberMap : rawMemberDefsOpt.get()) {
							String memberName = getRequiredStringArgument(memberMap, ARG_NAME);
							String memberTypePath = getRequiredStringArgument(memberMap, ARG_DATA_TYPE_PATH);
							Optional<String> commentOpt = getOptionalStringArgument(memberMap, ARG_COMMENT);

							// Use getDataType
							DataType memberDt = program.getDataTypeManager().getDataType(memberTypePath);
							if (memberDt == null) {
								throw new IllegalArgumentException(
										"Member data type not found: " + memberTypePath);
							}
							resolvedMembers.add(new ResolvedUnionMember(memberName, memberDt, commentOpt));
						}
					}

					// Return context
					return new UnionContext(program, categoryPath, unionName, unionPathString, resolvedMembers);

				})
				.flatMap(context -> { // .flatMap for transaction
					return executeInTransaction(context.program(), "Create Union " + context.unionName(), () -> {
						DataTypeManager dtm = context.program().getDataTypeManager();

						// Check existence *inside* transaction
						if (dtm.getDataType(context.categoryPath(), context.unionName()) != null) {
							throw new IllegalArgumentException(
									"Union already exists (checked in transaction): " + context.originalPath());
						}

						// Ensure category exists *inside* transaction
						Category category = dtm.createCategory(context.categoryPath());
						if (category == null) {
							category = dtm.getCategory(context.categoryPath());
							if (category == null) {
								throw new RuntimeException(
										"Failed to create or find category in transaction: " + context.categoryPath());
							}
						}

						// Create Union
						UnionDataType newUnion = new UnionDataType(category.getCategoryPath(), context.unionName(), dtm);

						// Add members
						for (ResolvedUnionMember member : context.resolvedMembers()) {
							newUnion.add(member.dataType(), member.name(), member.commentOpt().orElse(null));
						}

						// Add the new union to the manager using addDataType
						DataType resolvedUnion = dtm.addDataType(newUnion, DataTypeConflictHandler.DEFAULT_HANDLER);

						if (resolvedUnion instanceof Union) {
							return "Union created successfully at: " + resolvedUnion.getPathName();
						} else {
							throw new RuntimeException(
									"Failed to add union '" + context.originalPath() + "' after creation (unexpected conflict?).");
						}
					}); // End executeInTransaction
				}); // End flatMap
	}
}