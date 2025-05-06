package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.DataTypeInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Enum Definition", category = ToolCategory.DATATYPES, description = "Gets the definition of an existing enum.", mcpName = "get_enum_definition", mcpDescription = "Retrieves the definition (name, entries, etc.) of an enum data type.")
public class GhidraGetEnumDefinitionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(IGhidraMcpSpecification.ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(IGhidraMcpSpecification.ARG_ENUM_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The name or path of the enum data type (e.g., 'ColorEnum', '/windows/WINBOOL')."));

		schemaRoot.requiredProperty(IGhidraMcpSpecification.ARG_FILE_NAME)
				.requiredProperty(IGhidraMcpSpecification.ARG_ENUM_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String enumPath = getRequiredStringArgument(args, IGhidraMcpSpecification.ARG_ENUM_PATH);
			DataType dt = program.getDataTypeManager().getDataType(enumPath);

			if (dt == null) {
				throw new IllegalArgumentException("Enum data type not found: " + enumPath);
			}

			if (!(dt instanceof Enum)) {
				throw new IllegalArgumentException("Data type '" + enumPath + "' is not an Enum. Found: "
						+ dt.getClass().getSimpleName());
			}

			DataTypeInfo enumInfo = new DataTypeInfo(dt);
			return enumInfo;
		});
	}
}