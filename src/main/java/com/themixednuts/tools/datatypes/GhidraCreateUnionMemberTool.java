package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.DataTypeUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
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
								.description(
										"Full path or name of the member's data type (e.g., 'dword', '/MyOtherStruct', 'int[5]', 'char *'). Array and pointer notations are supported."),
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
			List<UnionMemberDefinition> memberDefs,
			PluginTool tool) {
	}

	private void processSingleUnionMemberCreation(Union union, UnionMemberDefinition memberDef, Program program,
			PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		DataType memberDataType = null;

		try {
			memberDataType = DataTypeUtils.parseDataTypeString(program, memberDef.dataTypePath(), tool);
		} catch (IllegalArgumentException e) {
			throw e;
		} catch (InvalidDataTypeException e) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
					.message("Invalid data type format for '" + memberDef.dataTypePath() + "': " + e.getMessage())
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"member data type format validation",
							Map.of(ARG_DATA_TYPE_PATH, memberDef.dataTypePath(), ARG_NAME, memberDef.name()),
							Map.of("memberDataTypePath", memberDef.dataTypePath(), "memberName", memberDef.name()),
							Map.of("formatError", e.getMessage())))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Check member data type format",
									"Use correct data type path format",
									List.of("'dword'", "'/MyOtherStruct'", "'int[5]'", "'char *'"),
									null)))
					.build();
			throw new GhidraMcpException(error);
		} catch (CancelledException e) {
			throw new RuntimeException(
					"Data type parsing cancelled for '" + memberDef.dataTypePath() + "': " + e.getMessage(), e);
		} catch (RuntimeException e) {
			throw new RuntimeException(
					"Unexpected runtime error during data type parsing for '" + memberDef.dataTypePath() + "': " + e.getMessage(),
					e);
		}

		union.add(memberDataType, memberDef.name(), memberDef.comment().orElse(null));
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
					String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
					List<Map<String, Object>> rawMemberDefs = getOptionalListArgument(args, ARG_MEMBERS)
							.orElseThrow(() -> {
								GhidraMcpError error = GhidraMcpError.validation()
										.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
										.message("Missing required argument: '" + ARG_MEMBERS + "'")
										.context(new GhidraMcpError.ErrorContext(
												annotation.mcpName(),
												"argument validation",
												Map.of(),
												Map.of("missingArgument", ARG_MEMBERS),
												Map.of("argumentRequired", true)))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
														"Provide members array",
														"Include the members array with at least one member definition",
														null,
														null)))
										.build();
								return new GhidraMcpException(error);
							});

					if (rawMemberDefs.isEmpty()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Argument '" + ARG_MEMBERS + "' cannot be empty.")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"members array validation",
										Map.of(ARG_MEMBERS, rawMemberDefs),
										Map.of("membersArrayLength", rawMemberDefs.size()),
										Map.of("arrayEmpty", true)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Provide at least one member",
												"Add at least one member definition to the array",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					List<UnionMemberDefinition> memberDefs = rawMemberDefs.stream()
							.map(rawDef -> new UnionMemberDefinition(
									getRequiredStringArgument(rawDef, ARG_NAME),
									getRequiredStringArgument(rawDef, ARG_DATA_TYPE_PATH),
									getOptionalStringArgument(rawDef, ARG_COMMENT)))
							.collect(Collectors.toList());

					DataType dt = program.getDataTypeManager().getDataType(unionPathString);

					if (dt == null) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Union not found at path: " + unionPathString)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"union lookup",
										Map.of(ARG_UNION_PATH, unionPathString),
										Map.of("unionPath", unionPathString),
										Map.of("unionExists", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"List available data types",
												"Check what unions exist",
												null,
												List.of(getMcpName(GhidraListDataTypesTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}
					if (!(dt instanceof Union)) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Data type at path is not a Union: " + unionPathString)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"data type validation",
										Map.of(ARG_UNION_PATH, unionPathString),
										Map.of("unionPath", unionPathString, "actualDataType", dt.getDisplayName()),
										Map.of("isUnion", false, "actualTypeName", dt.getClass().getSimpleName())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use a union data type",
												"Ensure the path points to a union, not " + dt.getClass().getSimpleName(),
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
					Union union = (Union) dt;

					for (UnionMemberDefinition def : memberDefs) {
						if (def.name().isBlank()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Union member name cannot be blank.")
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"member name validation",
											Map.of(ARG_NAME, def.name()),
											Map.of("memberName", def.name()),
											Map.of("nameBlank", true)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Provide a valid member name",
													"Member names must not be blank",
													null,
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
						if (def.dataTypePath().isBlank()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Union member data type path cannot be blank for member '" + def.name() + "'.")
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"member data type validation",
											Map.of(ARG_NAME, def.name(), ARG_DATA_TYPE_PATH, def.dataTypePath()),
											Map.of("memberName", def.name(), "dataTypePath", def.dataTypePath()),
											Map.of("dataTypePathBlank", true)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Provide a valid data type path",
													"Data type paths must not be blank",
													List.of("'dword'", "'/MyOtherStruct'", "'int[5]'"),
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
					}

					return new UnionMemberBatchContext(program, union, memberDefs, tool);
				})
				.flatMap(context -> {
					String transactionName = "Add Union Members to " + context.union().getName();
					String unionPathName = context.union().getPathName();

					return executeInTransaction(context.program(), transactionName, () -> {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						int localMembersAddedCount = 0;
						try {
							for (UnionMemberDefinition memberDef : context.memberDefs()) {
								processSingleUnionMemberCreation(context.union(), memberDef, context.program(), context.tool());
								localMembersAddedCount++;
							}
							return localMembersAddedCount;
						} catch (IllegalArgumentException e) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Error processing a union member: " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"member processing",
											Map.of("unionPath", unionPathName),
											Map.of("unionPathName", unionPathName),
											Map.of("processingError", e.getMessage())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Check member definition",
													"Verify all member properties are valid",
													null,
													null)))
									.build();
							throw new GhidraMcpException(error);
						} catch (Exception e) {
							throw new RuntimeException("Unexpected error processing a union member: " + e.getMessage(), e);
						}
					}).map(count -> {
						int addedCount = (Integer) count;
						return "Added " + addedCount + " member(s) to union '" + unionPathName + "'.";
					});
				});
	}
}