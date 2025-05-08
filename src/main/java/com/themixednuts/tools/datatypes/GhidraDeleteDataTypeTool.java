package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.ArchiveType;

@GhidraMcpTool(name = "Delete Data Type", category = ToolCategory.DATATYPES, description = "Deletes an existing data type.", mcpName = "delete_data_type", mcpDescription = "Removes a user-defined data type (struct, enum, etc.).")
public class GhidraDeleteDataTypeTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."),
				true);

		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description("The full path of the data type to delete (e.g., /MyCategory/MyType)."),
				true);

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String pathString = getRequiredStringArgument(args, ARG_PATH);
					GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex,
							this.getClass().getAnnotation(GhidraMcpTool.class).mcpName());

					String transactionName = "Delete Data Type: " + pathString;

					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						return deleteDataTypeAtPath(dtm, pathString, monitor);
					});
				});
	}

	private String deleteDataTypeAtPath(DataTypeManager dtm, String pathString, GhidraMcpTaskMonitor monitor) {
		DataType dt = dtm.getDataType(pathString);
		if (dt == null) {
			throw new IllegalArgumentException("Data type not found at path: " + pathString);
		}

		// Check if it's deletable (not built-in, etc.)
		SourceArchive sourceArchive = dt.getSourceArchive();
		SourceArchive programArchive = dtm.getLocalSourceArchive();
		if (sourceArchive != null && !sourceArchive.equals(programArchive)
				&& sourceArchive.getArchiveType() != ArchiveType.PROJECT) {
			throw new IllegalArgumentException(
					"Cannot delete built-in or external archive data type: " + pathString + " from archive "
							+ sourceArchive.getName());
		}

		boolean removed = dtm.remove(dt, monitor);
		if (removed) {
			return "Data Type '" + pathString + "' deleted successfully.";
		} else {
			throw new RuntimeException("Failed to delete Data Type '" + pathString
					+ ". It might be in use, was already deleted, or another issue occurred.");
		}
	}
}