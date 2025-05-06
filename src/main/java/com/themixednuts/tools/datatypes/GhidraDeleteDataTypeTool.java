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
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.ArchiveType;

@GhidraMcpTool(name = "Delete Data Type", category = ToolCategory.DATATYPES, description = "Deletes an existing data type.", mcpName = "delete_data_type", mcpDescription = "Removes a user-defined data type (struct, enum, etc.).")
public class GhidraDeleteDataTypeTool implements IGhidraMcpSpecification {

	private static record DeleteContext(
			Program program,
			DataType dataTypeToDelete,
			GhidraMcpTaskMonitor monitor,
			String originalPath) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		// Use ARG_DATA_TYPE_PATH for consistency
		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the data type to delete (e.g., /MyCategory/MyType)"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup and validation
					// Use ARG_DATA_TYPE_PATH
					String pathString = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
					DataType dt = program.getDataTypeManager().getDataType(pathString);

					if (dt == null) {
						// Throw if not found - tool is for deletion
						throw new IllegalArgumentException("Data type not found at path: " + pathString);
					}

					// Check source archive
					SourceArchive sourceArchive = dt.getSourceArchive();
					SourceArchive programArchive = program.getDataTypeManager().getLocalSourceArchive(); // Get from correct DTM
					// Check if not local or project archive
					if (sourceArchive != null && !sourceArchive.equals(programArchive)
							&& sourceArchive.getArchiveType() != ArchiveType.PROJECT) {
						throw new IllegalArgumentException(
								"Cannot delete built-in or external archive data type: " + pathString + " from archive "
										+ sourceArchive.getName());
					}

					GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex,
							this.getClass().getAnnotation(GhidraMcpTool.class).mcpName());

					return new DeleteContext(program, dt, monitor, pathString);
				})
				.flatMap(context -> { // .flatMap for transaction
					return executeInTransaction(context.program(), "Delete Data Type: " + context.originalPath(), () -> {
						DataTypeManager dtmInTx = context.program().getDataTypeManager();
						// Re-fetch inside transaction to ensure it still exists and we have the TX
						// version
						DataType dtInTx = dtmInTx.getDataType(context.originalPath());
						if (dtInTx == null) {
							// It was deleted between the map phase and now
							throw new IllegalStateException(
									"Data type '" + context.originalPath() + "' was deleted concurrently.");
						}

						boolean removed = dtmInTx.remove(dtInTx, context.monitor());

						if (removed) {
							return "Data type '" + context.originalPath() + "' deleted successfully.";
						} else {
							// remove() returns false if the type is not removable (e.g., in use)
							throw new RuntimeException(
									"Failed to delete data type '" + context.originalPath() + "'. It might be in use.");
						}
					});
				});
	}
}