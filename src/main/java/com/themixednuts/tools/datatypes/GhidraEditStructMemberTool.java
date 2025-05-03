package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.*;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Edit Struct Member", category = "Data Types", description = "Enable the MCP tool to edit an existing struct member.", mcpName = "edit_struct_member", mcpDescription = "Edits the name, type, size, and/or comment of an existing member within a struct, identified by its offset.")
public class GhidraEditStructMemberTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schema),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public ObjectNode schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property("structPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the struct containing the member (e.g., /MyCategory/MyStruct)"));

		schemaRoot.property("memberOffset",
				JsonSchemaBuilder.integer(mapper)
						.description("The current offset (in bytes) of the member to edit.")
						.minimum(0)); // Offset cannot be negative

		schemaRoot.property("newMemberName",
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new name for the member."));

		schemaRoot.property("newMemberTypePath",
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new data type path (e.g., 'dword', '/MyStruct')."));

		schemaRoot.property("newMemberSize",
				JsonSchemaBuilder.integer(mapper)
						.description(
								"Optional: The new explicit size in bytes. Often inferred from type, but needed for arrays or flexible types.")
						.minimum(1)); // Size must be positive

		schemaRoot.property("newMemberComment",
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new comment. Use empty string \"\" to clear."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("structPath")
				.requiredProperty("memberOffset");

		// Note: The logic for requiring at least one 'new*' property is handled
		// in the execute method.

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, validate, find struct/component, resolve new type/size
			// Argument parsing errors caught by onErrorResume
			String structPathString = getRequiredStringArgument(args, "structPath");
			final Integer memberOffset = getRequiredIntArgument(args, "memberOffset"); // Final for lambda
			Optional<String> newNameOpt = getOptionalStringArgument(args, "newMemberName");
			Optional<String> newTypePathOpt = getOptionalStringArgument(args, "newMemberTypePath");
			Optional<Integer> newSizeOpt = getOptionalIntArgument(args, "newMemberSize");
			Optional<String> newCommentOpt = getOptionalStringArgument(args, "newMemberComment");

			// Validate: At least one change requested
			if (newNameOpt.isEmpty() && newTypePathOpt.isEmpty() && newSizeOpt.isEmpty() && newCommentOpt.isEmpty()) {
				return createErrorResult("No changes specified. Provide at least one 'new*' argument.");
			}
			// Validate offset
			if (memberOffset < 0) {
				return createErrorResult("Invalid memberOffset: Cannot be negative.");
			}
			// Validate size if provided
			if (newSizeOpt.isPresent() && newSizeOpt.get() <= 0) {
				return createErrorResult("Invalid newMemberSize: Must be positive.");
			}

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(structPathString);

			if (dt == null) {
				return createErrorResult("Struct not found at path: " + structPathString);
			}
			if (!(dt instanceof Structure)) {
				return createErrorResult("Data type at path is not a Structure: " + structPathString);
			}
			final Structure structDt = (Structure) dt; // Make final for lambda

			// Get component at offset
			final DataTypeComponent component = structDt.getComponentAt(memberOffset); // Make final for lambda
			if (component == null) {
				return createErrorResult("No struct member found starting exactly at offset: " + memberOffset);
			}

			// --- Determine final values (outside transaction) ---
			final String finalName = newNameOpt.orElse(component.getFieldName());
			final String finalComment = newCommentOpt.orElse(component.getComment());
			final DataType finalDataType;
			final int finalSize;
			final boolean typeOrSizeChanged = newTypePathOpt.isPresent() || newSizeOpt.isPresent(); // Final for lambda

			if (newTypePathOpt.isPresent()) {
				DataType newDt = dtm.getDataType(newTypePathOpt.get());
				if (newDt == null) {
					return createErrorResult("New data type not found: " + newTypePathOpt.get());
				}
				finalDataType = newDt;
			} else {
				finalDataType = component.getDataType();
			}

			if (newSizeOpt.isPresent()) {
				finalSize = newSizeOpt.get(); // Already validated > 0
			} else {
				finalSize = typeOrSizeChanged ? finalDataType.getLength() : component.getLength();
				if (finalSize <= 0) { // Handle dynamic types where size MUST be specified
					return createErrorResult("Cannot determine valid size for type '" + finalDataType.getPathName()
							+ "'. Provide explicit newMemberSize.");
				}
			}

			// --- Execute modification in transaction ---
			return executeInTransaction(program, "MCP - Edit Struct Member", () -> {
				// Inner Callable logic (just the modification):
				// If only name/comment changed, use setters
				if (!typeOrSizeChanged) {
					DataTypeComponent compToUpdate = structDt.getComponentAt(memberOffset); // Re-get component inside tx?
					if (compToUpdate != null) {
						compToUpdate.setFieldName(finalName);
						compToUpdate.setComment(finalComment);
					}
				} else {
					// If type or size changed, replace the component
					structDt.replaceAtOffset(memberOffset, finalDataType, finalSize, finalName, finalComment);
				}
				// Return success
				return createSuccessResult("Struct member at offset " + memberOffset + " updated successfully.");
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			// Catch errors from getProgram or unexpected setup errors (incl. arg parsing)
			// Logging handled by createErrorResult
			return createErrorResult(e);
		});
	}
}