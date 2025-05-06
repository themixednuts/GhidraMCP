package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.DataTypeInfo;
// UnionMemberInfo import removed as it's used internally by DataTypeInfo
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
// DataTypeManager import removed as it's unused
import ghidra.program.model.data.Union;
// Program import removed as it's unused
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Union Definition", category = ToolCategory.DATATYPES, description = "Retrieves the definition (name, members, etc.) of a union data type.", mcpName = "get_union_definition", mcpDescription = "Retrieve details of a defined union type.")
public class GhidraGetUnionDefinitionTool implements IGhidraMcpSpecification {

	// REMOVED Constant ARG_UNION_PATH as it exists in IGhidraMcpSpecification

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_UNION_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The name or path of the union data type (e.g., 'MyUnion', '/unions/MyUnion')."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_UNION_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) { // Ensure
																																																								// signature
		return getProgram(args, tool)
				.map(program -> {
					String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
					// DataTypeManager dtm = program.getDataTypeManager(); // Not needed explicitly

					DataType dt = program.getDataTypeManager().getDataType(unionPathString);

					if (dt == null) {
						throw new IllegalArgumentException("Union not found at path: " + unionPathString);
					}
					if (!(dt instanceof Union)) {
						throw new IllegalArgumentException("Data type at path is not a Union: " + unionPathString
								+ " (Type: " + dt.getClass().getSimpleName() + ")");
					}

					DataTypeInfo unionInfo = new DataTypeInfo(dt);

					return unionInfo;
				});
	}
}