package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
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
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String structPathString = getRequiredStringArgument(args, ARG_STRUCT_PATH);
			Integer memberOffset = getRequiredIntArgument(args, ARG_OFFSET);

			if (memberOffset < 0) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Invalid member offset: Cannot be negative")
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"offset validation",
								args,
								Map.of(ARG_OFFSET, memberOffset),
								Map.of("validOffsetRange", "0 or greater", "providedOffset", memberOffset)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Provide a valid offset",
										"Specify a non-negative offset value (0 or greater)",
										List.of("\"" + ARG_OFFSET + "\": 0", "\"" + ARG_OFFSET + "\": 4", "\"" + ARG_OFFSET + "\": 8"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			DataType dt = program.getDataTypeManager().getDataType(structPathString);

			if (dt == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Structure not found at path: " + structPathString)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"structure lookup",
								args,
								Map.of(ARG_STRUCT_PATH, structPathString),
								Map.of("searchedPath", structPathString, "dataTypeExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify the structure path",
										"Check if the structure exists at the specified path",
										null,
										List.of(getMcpName(GhidraListDataTypesTool.class),
												getMcpName(GhidraGetDataTypeTool.class))),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Check the path format",
										"Ensure the path follows the correct format",
										List.of("/MyCategory/MyStruct", "/BuiltInTypes/int"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			if (!(dt instanceof Structure)) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Data type at path is not a Structure: " + structPathString)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"data type validation",
								args,
								Map.of(ARG_STRUCT_PATH, structPathString, "actualDataType", dt.getClass().getSimpleName()),
								Map.of("expectedType", "Structure", "actualType", dt.getClass().getSimpleName(), "dataTypeName",
										dt.getName())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.USE_DIFFERENT_TOOL,
										"Use the appropriate tool for this data type",
										"This data type requires a different delete operation",
										null,
										List.of(getMcpName(GhidraDeleteUnionMemberTool.class),
												getMcpName(GhidraDeleteEnumEntryTool.class))),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify the data type details",
										"Check the actual type of the data type at this path",
										null,
										List.of(getMcpName(GhidraGetDataTypeTool.class)))))
						.build();
				throw new GhidraMcpException(error);
			}

			Structure structDt = (Structure) dt;

			// Check if component exists at offset BEFORE transaction
			DataTypeComponent component = structDt.getComponentAt(memberOffset);
			if (component == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("No struct member found starting exactly at offset: " + memberOffset)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"struct member lookup",
								args,
								Map.of(ARG_STRUCT_PATH, structPathString, ARG_OFFSET, memberOffset),
								Map.of("searchedOffset", memberOffset, "structSize", structDt.getLength(), "memberExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Check existing struct members",
										"View the current members and their offsets in this structure",
										null,
										List.of(getMcpName(GhidraGetDataTypeTool.class))),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use a valid member offset",
										"Specify an offset where a member actually starts",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Return type-safe context
			return new DeleteStructMemberContext(program, structDt, memberOffset);

		}).flatMap(context -> {
			String structPathName = context.structDt().getPathName();

			return executeInTransaction(context.program(), "MCP - Delete Struct Member at offset " + context.memberOffset(),
					() -> {
						context.structDt().deleteAtOffset(context.memberOffset());
						return "Struct member at offset " + context.memberOffset() + " deleted successfully from " + structPathName
								+ ".";
					});
		});
	}
}