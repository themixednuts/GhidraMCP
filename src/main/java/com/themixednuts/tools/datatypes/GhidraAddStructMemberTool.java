package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Add Struct Member", category = "Data Types", description = "Enable the MCP tool to add a member to a struct data type.", mcpName = "add_struct_member", mcpDescription = "Adds a new member field to an existing structure (struct) data type.")
public class GhidraAddStructMemberTool implements IGhidraMcpSpecification {

	public GhidraAddStructMemberTool() {
	}

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
						.description("The full path of the structure to modify (e.g., /MyCategory/MyStruct)"));
		schemaRoot.property("memberName",
				JsonSchemaBuilder.string(mapper)
						.description("Name for the new member."));
		schemaRoot.property("memberTypePath",
				JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the member's data type (e.g., 'dword', '/MyOtherStruct')."));
		schemaRoot.property("offset",
				JsonSchemaBuilder.integer(mapper)
						.description("Optional offset for the new member within the struct. If omitted, the member is appended."));
		schemaRoot.property("comment",
				JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new member."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("structPath")
				.requiredProperty("memberName")
				.requiredProperty("memberTypePath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String structPathString = getRequiredStringArgument(args, "structPath");
			final String memberName = getRequiredStringArgument(args, "memberName"); // Final for lambda
			String memberTypePath = getRequiredStringArgument(args, "memberTypePath");
			final Optional<Integer> offsetOpt = getOptionalIntArgument(args, "offset"); // Final for lambda
			final Optional<String> commentOpt = getOptionalStringArgument(args, "comment"); // Final for lambda

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(structPathString);

			if (dt == null) {
				return createErrorResult("Structure not found at path: " + structPathString);
			}
			if (!(dt instanceof Structure)) {
				return createErrorResult("Data type at path is not a Structure: " + structPathString);
			}
			final Structure struct = (Structure) dt; // Final for lambda

			final DataType memberDataType = dtm.getDataType(memberTypePath); // Final for lambda
			if (memberDataType == null) {
				return createErrorResult("Data type not found for member: " + memberTypePath);
			}

			// Determine size (outside transaction)
			final int memberSize = memberDataType.getLength(); // Final for lambda
			if (memberSize <= 0) {
				// Cannot add dynamically sized types without explicit size (which isn't an arg
				// here)
				return createErrorResult("Cannot add member with dynamically sized type: " + memberTypePath);
			}

			// --- Execute modification in transaction ---
			final String finalStructPathString = structPathString; // Capture for message
			return executeInTransaction(program, "MCP - Add Struct Member", () -> {
				// Inner Callable logic (just the modification):
				if (offsetOpt.isPresent()) {
					int offset = offsetOpt.get(); // Explicit unboxing
					// Pass memberSize to insert
					struct.insert(offset, memberDataType, memberSize, memberName, commentOpt.orElse(null));
				} else {
					// Add method doesn't need explicit size
					struct.add(memberDataType, memberName, commentOpt.orElse(null));
				}
				// Return success
				return createSuccessResult(
						"Member '" + memberName + "' added to structure '" + finalStructPathString + "'.");
			});
		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}