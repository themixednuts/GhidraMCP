package com.themixednuts.tools.datatypes;

import java.util.Map;

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

@GhidraMcpTool(key = "Remove Struct Member", category = "Data Types", description = "Enable the MCP tool to remove a member from a struct data type.", mcpName = "remove_struct_member", mcpDescription = "Removes a member from an existing structure (struct) data type by name.")
public class GhidraRemoveStructMemberTool implements IGhidraMcpSpecification {

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
		schemaRoot.property("structPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the structure to modify (e.g., /MyCategory/MyStruct)"));
		schemaRoot.property("memberName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the member to remove."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("structPath")
				.requiredProperty("memberName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String structPathString = getRequiredStringArgument(args, "structPath");
			String memberName = getRequiredStringArgument(args, "memberName");

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(structPathString);

			if (dt == null) {
				return createErrorResult("Structure not found at path: " + structPathString);
			}
			if (!(dt instanceof Structure)) {
				return createErrorResult("Data type at path is not a Structure: " + structPathString);
			}
			final Structure struct = (Structure) dt;

			int memberIndex = -1;
			for (int i = 0; i < struct.getNumComponents(); i++) {
				if (struct.getComponent(i).getFieldName().equals(memberName)) {
					memberIndex = i;
					break;
				}
			}

			if (memberIndex == -1) {
				return createSuccessResult(
						"Member '" + memberName + "' not found in structure '" + structPathString + "'. No changes made.");
			}

			final int finalMemberIndex = memberIndex;
			final String finalMemberName = memberName;
			final String finalStructPathString = structPathString;

			return executeInTransaction(program, "MCP - Remove Struct Member", () -> {
				struct.delete(finalMemberIndex);
				return createSuccessResult(
						"Member '" + finalMemberName + "' removed from structure '" + finalStructPathString + "'.");
			});

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}