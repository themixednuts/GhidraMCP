package com.themixednuts.tools.datatypes;

import java.util.Map;

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

@GhidraMcpTool(key = "Add Union Member", category = "Data Types", description = "Enable the MCP tool to add a member to an existing union.", mcpName = "add_union_member", mcpDescription = "Adds a new member to an existing union. Note: In unions, members typically overlap at offset 0.")
public class GhidraAddUnionMemberTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
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

		schemaRoot.property("unionPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the union to add the member to (e.g., /MyCategory/MyUnion)"));

		schemaRoot.property("memberName",
				JsonSchemaBuilder.string(mapper)
						.description("The name for the new member."));

		schemaRoot.property("memberTypePath",
				JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the member's data type (e.g., 'dword', '/MyStruct')."));

		schemaRoot.property("comment",
				JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new member."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("unionPath")
				.requiredProperty("memberName")
				.requiredProperty("memberTypePath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, find union, find member data type
			// Argument parsing errors caught by onErrorResume
			String unionPathString = getRequiredStringArgument(args, "unionPath");
			final String memberName = getRequiredStringArgument(args, "memberName"); // Final for lambda
			String memberTypePath = getRequiredStringArgument(args, "memberTypePath");
			final String comment = getOptionalStringArgument(args, "comment").orElse(null); // Final for lambda

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(unionPathString);

			if (dt == null) {
				return createErrorResult("Union not found at path: " + unionPathString);
			}
			if (!(dt instanceof Union)) {
				return createErrorResult("Data type at path is not a Union: " + unionPathString);
			}
			final Union unionDt = (Union) dt; // Final for lambda

			final DataType memberDataType = dtm.getDataType(memberTypePath); // Final for lambda
			if (memberDataType == null) {
				return createErrorResult("Member data type not found: " + memberTypePath);
			}

			// --- Execute modification in transaction ---
			final String finalUnionPathString = unionPathString; // Capture for message
			return executeInTransaction(program, "MCP - Add Union Member", () -> {
				// Inner Callable logic (just the modification):
				DataTypeComponent addedComponent = unionDt.add(memberDataType, memberName, comment);

				if (addedComponent != null) {
					// Return success
					return createSuccessResult(
							"Member '" + memberName + "' added successfully to union " + finalUnionPathString + ".");
				} else {
					// Return specific error if add fails (e.g., name conflict)
					return createErrorResult("Failed to add member '" + memberName + "' to union " + finalUnionPathString
							+ ". Name/type conflict or other issue?");
				}
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup (incl. arg parsing), or transaction
			// execution
			// Logging handled by createErrorResult
			return createErrorResult(e);
		});
	}
}