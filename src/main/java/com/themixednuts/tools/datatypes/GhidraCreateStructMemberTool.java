package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;
import java.util.List;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.DataTypeUtils;

import com.themixednuts.tools.datatypes.GhidraListDataTypesTool;

import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Struct Members", mcpName = "create_struct_members", category = ToolCategory.DATATYPES, description = "Adds one or more new fields (members) to an existing struct data type.", mcpDescription = """
		<use_case>
		Add one or more members to an existing structure data type with precise control over field placement and types. Essential for building complex data structures during reverse engineering.
		</use_case>

		<important_notes>
		- Members can be inserted at specific offsets or appended to the end
		- Offset behavior: 0 = insert at beginning, positive values = insert at that offset, -1 or omitted = append to end
		- Supports all data types including arrays, pointers, and user-defined structures
		- Member names must be unique within the structure
		- Array and pointer notation supported in data type paths
		</important_notes>

		<example>
		Add members to struct:
		{
		  "fileName": "program.exe",
		  "structPath": "/MyStructs/Configuration",
		  "members": [
		    {"name": "header", "dataTypePath": "dword", "offset": 0, "comment": "Insert at beginning"},
		    {"name": "version", "dataTypePath": "dword", "comment": "Append to end (no offset)"},
		    {"name": "buffer", "dataTypePath": "char[256]", "offset": 8, "comment": "Insert at offset 8"},
		    {"name": "callback", "dataTypePath": "FunctionPtr *", "offset": -1, "comment": "Append to end"}
		  ]
		}
		</example>

		<workflow>
		1. Validate structure exists at specified path
		2. Parse all member data types and validate availability
		3. Check for name conflicts with existing members
		4. Add or insert members at specified offsets (0=beginning, positive=specific offset, -1/omitted=end)
		5. Update structure layout and size calculations
		</workflow>
		""")
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
								.description(
										"Full path or name of the member's data type (e.g., 'dword', '/MyOtherStruct', 'int[5]', 'char *'). Array and pointer notations are supported."),
						true) // Required within member object
				.property(ARG_OFFSET,
						JsonSchemaBuilder.integer(mapper)
								.description(
										"Optional offset for the new member within the struct. Use 0 to insert at the beginning, positive values for specific offsets, -1 or omit to append to the end."))
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
			PluginTool tool,
			Structure struct,
			List<StructMemberDefinition> memberDefs) {
	}

	private void processSingleStructMemberCreation(Structure struct, StructMemberDefinition memberDef, Program program,
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
					GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
					String structPathString = getRequiredStringArgument(args, ARG_STRUCT_PATH);
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

					List<StructMemberDefinition> memberDefs = rawMemberDefs.stream()
							.map(rawDef -> new StructMemberDefinition(
									getRequiredStringArgument(rawDef, ARG_NAME),
									getRequiredStringArgument(rawDef, ARG_DATA_TYPE_PATH),
									getOptionalIntArgument(rawDef, ARG_OFFSET),
									getOptionalStringArgument(rawDef, ARG_COMMENT)))
							.collect(Collectors.toList());

					DataType dt = program.getDataTypeManager().getDataType(structPathString);

					if (dt == null) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Structure not found at path: " + structPathString)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"structure lookup",
										Map.of(ARG_STRUCT_PATH, structPathString),
										Map.of("structPath", structPathString),
										Map.of("structExists", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"List available data types",
												"Check what structures exist",
												null,
												List.of(getMcpName(GhidraListDataTypesTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}
					if (!(dt instanceof Structure)) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Data type at path is not a Structure: " + structPathString)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"data type validation",
										Map.of(ARG_STRUCT_PATH, structPathString),
										Map.of("structPath", structPathString, "actualDataType", dt.getDisplayName()),
										Map.of("isStructure", false, "actualTypeName", dt.getClass().getSimpleName())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use a structure data type",
												"Ensure the path points to a structure, not " + dt.getClass().getSimpleName(),
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
					Structure struct = (Structure) dt;

					for (StructMemberDefinition def : memberDefs) {
						if (def.name().isBlank()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Member name cannot be blank.")
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
									.message("Member data type path cannot be blank for member '" + def.name() + "'.")
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

					return new StructMemberBatchContext(program, tool, struct, memberDefs);
				})
				.flatMap(context -> {
					String transactionName = "Add Struct Members to " + context.struct().getName();
					String structPathName = context.struct().getPathName();

					return executeInTransaction(context.program(), transactionName, () -> {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						int localMembersAddedCount = 0;
						try {
							for (StructMemberDefinition memberDef : context.memberDefs()) {
								processSingleStructMemberCreation(context.struct(), memberDef, context.program(), context.tool());
								localMembersAddedCount++;
							}
							return localMembersAddedCount;
						} catch (IndexOutOfBoundsException e) {
							String currentMemberNameForError = "<unknown_member_causing_error>";
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Failed adding member (likely '" + currentMemberNameForError + "') to structure '"
											+ structPathName + "'. Offset is out of bounds.")
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"member insertion",
											Map.of("structPath", structPathName),
											Map.of("structPathName", structPathName, "memberName", currentMemberNameForError),
											Map.of("offsetOutOfBounds", true, "exceptionType", "IndexOutOfBoundsException")))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Check member offset",
													"Ensure the offset is valid for the structure",
													null,
													null)))
									.build();
							throw new GhidraMcpException(error);
						} catch (IllegalArgumentException e) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Error processing a member: " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"member processing",
											Map.of("structPath", structPathName),
											Map.of("structPathName", structPathName),
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
							throw new RuntimeException("Unexpected error processing a member: " + e.getMessage(), e);
						}
					}).map(count -> {
						int addedCount = (Integer) count;
						return "Added " + addedCount + " member(s) to structure '" + structPathName + "'.";
					});
				});
	}
}