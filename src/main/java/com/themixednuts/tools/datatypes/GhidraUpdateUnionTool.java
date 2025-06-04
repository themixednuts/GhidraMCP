package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Union", category = ToolCategory.DATATYPES, description = "Updates properties of an existing Union.", mcpName = "update_union", mcpDescription = "Updates the name or description of an existing Union data type.")
public class GhidraUpdateUnionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."),
				true);
		schemaRoot.property(ARG_UNION_PATH, // Using ARG_UNION_PATH from IGhidraMcpSpecification
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the union to update (e.g., /MyCategory/MyUnion)."),
				true);
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional new name for the union."));
		schemaRoot.property(ARG_COMMENT, // Using ARG_COMMENT from IGhidraMcpSpecification
				JsonSchemaBuilder.string(mapper)
						.description("Optional new description text. An empty string clears the description."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_UNION_PATH);

		return schemaRoot.build();
	}

	private static record UnionUpdateContext(
			Program program,
			Union oldUnion,
			Optional<String> newNameOpt,
			Optional<String> newDescriptionOpt,
			String originalPath,
			List<String> updatedFields) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			final String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
			Optional<String> newNameOpt = getOptionalStringArgument(args, ARG_NEW_NAME);
			Optional<String> newDescriptionOpt = getOptionalStringArgument(args, ARG_COMMENT);

			if (newNameOpt.isEmpty() && newDescriptionOpt.isEmpty()) {
				GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("No changes specified. Provide at least newName or newDescription")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"update parameters validation",
								Map.of(ARG_UNION_PATH, unionPathString),
								Map.of("unionPath", unionPathString),
								Map.of("noUpdatesProvided", true, "availableUpdateFields", List.of("newName", "newDescription"))))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Specify at least one update",
										"Provide at least one field to update",
										List.of("newName", "newDescription"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			DataType dt = program.getDataTypeManager().getDataType(unionPathString);

			if (dt == null) {
				GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Union not found at path: " + unionPathString)
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"union lookup",
								Map.of(ARG_UNION_PATH, unionPathString),
								Map.of("unionPath", unionPathString),
								Map.of("unionExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"List available data types",
										"Check what unions exist",
										null,
										List.of(getMcpName(GhidraListDataTypesTool.class)))))
						.build();
				throw new GhidraMcpException(error);
			}
			if (!(dt instanceof Union)) {
				GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Data type at path is not a Union: " + unionPathString)
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"data type validation",
								Map.of(ARG_UNION_PATH, unionPathString),
								Map.of("unionPath", unionPathString, "actualDataType", dt.getDisplayName()),
								Map.of("isUnion", false, "actualTypeName", dt.getClass().getSimpleName())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use a union data type",
										"Ensure the path points to a union, not " + dt.getClass().getSimpleName(),
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}
			final Union oldUnion = (Union) dt;
			final List<String> updatedFields = new ArrayList<>();

			newNameOpt.ifPresent(s -> updatedFields.add("name"));
			newDescriptionOpt.ifPresent(s -> updatedFields.add("description"));

			return new UnionUpdateContext(program, oldUnion, newNameOpt, newDescriptionOpt, unionPathString, updatedFields);

		}).flatMap(context -> {
			return executeInTransaction(context.program(), "MCP - Update Union: " + context.originalPath(), () -> {
				DataTypeManager dtm = context.program().getDataTypeManager();
				Union unionToUpdate = (Union) dtm.getDataType(context.originalPath()); // Re-fetch in transaction
				if (unionToUpdate == null) {
					throw new IllegalStateException("Union disappeared before transaction: " + context.originalPath());
				}

				if (context.newNameOpt().isPresent()) {
					String newName = context.newNameOpt().get();
					try {
						unionToUpdate.setName(newName);
					} catch (InvalidNameException | ghidra.util.exception.DuplicateNameException e) {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Failed to set new name for union: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"union name update",
										Map.of(ARG_NEW_NAME, newName, ARG_UNION_PATH, context.originalPath()),
										Map.of("newName", newName, "unionPath", context.originalPath()),
										Map.of("nameUpdateFailed", true, "nameError", e.getMessage())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use a valid unique name",
												"Union names must be valid and not duplicate existing names",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
				}

				if (context.newDescriptionOpt().isPresent()) {
					unionToUpdate.setDescription(context.newDescriptionOpt().get());
				}

				return "Union '" + context.originalPath() + "' updated successfully. Modified fields: "
						+ String.join(", ", context.updatedFields());
			});
		});
	}
}