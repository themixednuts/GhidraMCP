package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Remove Struct Member", category = "Data Types", description = "Remove a member (field) from a structure data type.", mcpName = "remove_struct_member", mcpDescription = "Removes a specific member field from a structure data type by its ordinal index.")
public class GhidraRemoveStructMemberTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = schemaObject.toJsonString(mapper);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to serialize schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("structName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the structure data type (e.g., '/MyStruct', '/windows/POINTL')."));
		schemaRoot.property("memberOrdinal",
				JsonSchemaBuilder.integer(mapper)
						.description("The zero-based index (ordinal) of the member to remove.")
						.minimum(0));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("structName")
				.requiredProperty("memberOrdinal");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String structName = getRequiredStringArgument(args, "structName");
			int memberOrdinal = getRequiredIntArgument(args, "memberOrdinal");
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(structName);

			if (dt == null) {
				return createErrorResult("Structure data type not found: " + structName);
			}
			if (!(dt instanceof Structure)) {
				return createErrorResult("Data type '".concat(structName).concat("' is not a Structure."));
			}
			final Structure structure = (Structure) dt;

			if (memberOrdinal < 0 || memberOrdinal >= structure.getNumComponents()) {
				return createErrorResult("Invalid member ordinal: " + memberOrdinal + ". Must be between 0 and "
						+ (structure.getNumComponents() - 1));
			}

			DataTypeComponent componentToRemove = structure.getComponent(memberOrdinal);
			String removedMemberName = componentToRemove != null ? componentToRemove.getFieldName() : "(unknown)";

			return executeInTransaction(program, "Remove Struct Member: " + structName + "[" + memberOrdinal + "]",
					() -> {
						structure.delete(memberOrdinal);
						return createSuccessResult("Member at ordinal " + memberOrdinal + " (name: '" + removedMemberName
								+ "') removed from structure '" + structName + "' successfully.");
					});

		}).onErrorResume(e -> createErrorResult(e));
	}
}