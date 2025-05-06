package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

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

@GhidraMcpTool(name = "Update Struct Member", mcpName = "update_struct_member", category = ToolCategory.DATATYPES, description = "Modifies the name, data type, size, or comment of an existing field (member) in a struct.", mcpDescription = "Modifies the name, data type, size, or comment of an existing field (member) in a struct.")
public class GhidraUpdateStructMemberTool implements IGhidraMcpSpecification {

	private static record StructUpdateContext(
			Program program,
			Structure structDt,
			int memberOffset,
			String finalName,
			DataType finalDataType,
			int finalSize,
			String finalComment) {
	}

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
						.description("The current offset (in bytes) of the member to edit.")
						.minimum(0)); // Offset cannot be negative

		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new name for the member."));

		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new data type path (e.g., 'dword', '/MyStruct')."));

		schemaRoot.property(ARG_SIZE,
				JsonSchemaBuilder.integer(mapper)
						.description(
								"Optional: The new explicit size in bytes. Often inferred from type, but needed for arrays or flexible types.")
						.minimum(1)); // Size must be positive

		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new comment. Use empty string \"\" to clear."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_STRUCT_PATH)
				.requiredProperty(ARG_OFFSET);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup and validation
					String structPathString = getRequiredStringArgument(args, ARG_STRUCT_PATH);
					int memberOffset = getRequiredIntArgument(args, ARG_OFFSET);
					Optional<String> newNameOpt = getOptionalStringArgument(args, ARG_NEW_NAME);
					Optional<String> newTypePathOpt = getOptionalStringArgument(args, ARG_DATA_TYPE_PATH);
					Optional<Integer> newSizeOpt = getOptionalIntArgument(args, ARG_SIZE);
					Optional<String> newCommentOpt = getOptionalStringArgument(args, ARG_COMMENT);

					// Validate: At least one change requested
					if (newNameOpt.isEmpty() && newTypePathOpt.isEmpty() && newSizeOpt.isEmpty() && newCommentOpt.isEmpty()) {
						throw new IllegalArgumentException("No changes specified. Provide at least one 'new*' argument.");
					}
					// Validate offset
					if (memberOffset < 0) {
						throw new IllegalArgumentException("Invalid memberOffset: Cannot be negative.");
					}
					// Validate size if provided
					if (newSizeOpt.isPresent() && newSizeOpt.get() <= 0) {
						throw new IllegalArgumentException("Invalid newMemberSize: Must be positive.");
					}

					DataType dt = program.getDataTypeManager().getDataType(structPathString);

					if (dt == null) {
						throw new IllegalArgumentException("Struct not found at path: " + structPathString);
					}
					if (!(dt instanceof Structure)) {
						throw new IllegalArgumentException("Data type at path is not a Structure: " + structPathString);
					}
					Structure structDt = (Structure) dt;

					// Get component at offset
					DataTypeComponent component = structDt.getComponentAt(memberOffset);
					if (component == null) {
						throw new IllegalArgumentException("No struct member found starting exactly at offset: " + memberOffset);
					}

					// --- Determine final values ---
					String finalName = newNameOpt.orElse(component.getFieldName());
					String finalComment = newCommentOpt.orElse(component.getComment());
					DataType finalDataType;
					int finalSize;

					if (newTypePathOpt.isPresent()) {
						DataType newDt = program.getDataTypeManager().getDataType(newTypePathOpt.get());
						if (newDt == null) {
							throw new IllegalArgumentException("New data type not found: " + newTypePathOpt.get());
						}
						finalDataType = newDt;
					} else {
						finalDataType = component.getDataType();
					}

					if (newSizeOpt.isPresent()) {
						finalSize = newSizeOpt.get(); // Already validated > 0
					} else {
						// Use the length of the *final* data type if size wasn't specified
						finalSize = finalDataType.getLength();
						if (finalSize <= 0) { // Handle dynamic types where size MUST be specified
							throw new IllegalArgumentException("Cannot determine valid size for type '" + finalDataType.getPathName()
									+ "'. Provide explicit size.");
						}
					}

					return new StructUpdateContext(program, structDt, memberOffset, finalName, finalDataType, finalSize,
							finalComment);
				})
				.flatMap(context -> { // .flatMap for transaction
					return executeInTransaction(context.program(),
							"Update Struct Member at offset " + context.memberOffset(), () -> {
								// Always use replaceAtOffset for simplicity
								context.structDt().replaceAtOffset(context.memberOffset(), context.finalDataType(),
										context.finalSize(), context.finalName(), context.finalComment());

								return "Struct member at offset " + context.memberOffset() + " updated successfully.";
							});
				});
	}
}