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
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Enum", category = ToolCategory.DATATYPES, description = "Updates properties of an existing Enum.", mcpName = "update_enum", mcpDescription = "Updates the name, description, or size of an existing Enum data type.")
public class GhidraUpdateEnumTool implements IGhidraMcpSpecification {

	public static final String ARG_NEW_SIZE = "newSize";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."),
				true);
		schemaRoot.property(ARG_ENUM_PATH, // Using ARG_ENUM_PATH from IGhidraMcpSpecification
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the enum to update (e.g., /MyCategory/MyEnum)."),
				true);
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional new name for the enum."));
		schemaRoot.property(ARG_COMMENT, // Using ARG_COMMENT from IGhidraMcpSpecification
				JsonSchemaBuilder.string(mapper)
						.description("Optional new description text. An empty string clears the description."));
		schemaRoot.property(ARG_NEW_SIZE,
				JsonSchemaBuilder.integer(mapper)
						.description("Optional new size (in bytes) for the enum (e.g., 1, 2, 4, 8)."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_ENUM_PATH);

		return schemaRoot.build();
	}

	private static record EnumUpdateContext(
			Program program,
			Enum oldEnum,
			Optional<String> newNameOpt,
			Optional<String> newDescriptionOpt,
			Optional<Integer> newSizeOpt,
			String originalPath,
			List<String> updatedFields) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			final String enumPathString = getRequiredStringArgument(args, ARG_ENUM_PATH);
			Optional<String> newNameOpt = getOptionalStringArgument(args, ARG_NEW_NAME);
			Optional<String> newDescriptionOpt = getOptionalStringArgument(args, ARG_COMMENT);
			Optional<Integer> newSizeOpt = getOptionalIntArgument(args, ARG_NEW_SIZE);

			if (newNameOpt.isEmpty() && newDescriptionOpt.isEmpty() && newSizeOpt.isEmpty()) {
				GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("No changes specified. Provide at least newName, newDescription, or newSize")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"update parameters validation",
								Map.of(ARG_ENUM_PATH, enumPathString),
								Map.of("enumPath", enumPathString),
								Map.of("noUpdatesProvided", true, "availableUpdateFields",
										List.of("newName", "newDescription", "newSize"))))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Specify at least one update",
										"Provide at least one field to update",
										List.of("newName", "newDescription", "newSize"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			DataType dt = program.getDataTypeManager().getDataType(enumPathString);

			if (dt == null) {
				GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Enum not found at path: " + enumPathString)
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"enum lookup",
								Map.of(ARG_ENUM_PATH, enumPathString),
								Map.of("enumPath", enumPathString),
								Map.of("enumExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"List available data types",
										"Check what enums exist",
										null,
										List.of(getMcpName(GhidraListDataTypesTool.class)))))
						.build();
				throw new GhidraMcpException(error);
			}
			if (!(dt instanceof Enum)) {
				GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Data type at path is not an Enum: " + enumPathString)
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"data type validation",
								Map.of(ARG_ENUM_PATH, enumPathString),
								Map.of("enumPath", enumPathString, "actualDataType", dt.getDisplayName()),
								Map.of("isEnum", false, "actualTypeName", dt.getClass().getSimpleName())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use an enum data type",
										"Ensure the path points to an enum, not " + dt.getClass().getSimpleName(),
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}
			final Enum oldEnum = (Enum) dt;
			final List<String> updatedFields = new ArrayList<>();

			newNameOpt.ifPresent(s -> updatedFields.add("name"));
			newDescriptionOpt.ifPresent(s -> updatedFields.add("description"));
			newSizeOpt.ifPresent(s -> updatedFields.add("size"));

			return new EnumUpdateContext(program, oldEnum, newNameOpt, newDescriptionOpt, newSizeOpt, enumPathString,
					updatedFields);

		}).flatMap(context -> {
			return executeInTransaction(context.program(), "MCP - Update Enum: " + context.originalPath(), () -> {
				DataTypeManager dtm = context.program().getDataTypeManager();
				Enum enumToUpdate = (Enum) dtm.getDataType(context.originalPath()); // Re-fetch in transaction
				if (enumToUpdate == null) {
					throw new IllegalStateException("Enum disappeared before transaction: " + context.originalPath());
				}

				if (context.newNameOpt().isPresent()) {
					String newName = context.newNameOpt().get();
					try {
						enumToUpdate.setName(newName);
					} catch (InvalidNameException | ghidra.util.exception.DuplicateNameException e) {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Failed to set new name for enum: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"enum name update",
										Map.of(ARG_NEW_NAME, newName, ARG_ENUM_PATH, context.originalPath()),
										Map.of("newName", newName, "enumPath", context.originalPath()),
										Map.of("nameUpdateFailed", true, "nameError", e.getMessage())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use a valid unique name",
												"Enum names must be valid and not duplicate existing names",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
				}

				if (context.newDescriptionOpt().isPresent()) {
					enumToUpdate.setDescription(context.newDescriptionOpt().get());
				}

				if (context.newSizeOpt().isPresent()) {
					int newSize = context.newSizeOpt().get();
					if (newSize != 1 && newSize != 2 && newSize != 4 && newSize != 8) {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid enum size: " + newSize + ". Must be 1, 2, 4, or 8")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"enum size validation",
										Map.of(ARG_NEW_SIZE, newSize, ARG_ENUM_PATH, context.originalPath()),
										Map.of("providedSize", newSize, "enumPath", context.originalPath()),
										Map.of("validSizes", List.of(1, 2, 4, 8), "receivedSize", newSize)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use a valid enum size",
												"Provide one of the valid size values",
												List.of("1", "2", "4", "8"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
					// Cast to EnumDataType to access setLength
					if (enumToUpdate instanceof EnumDataType) {
						((EnumDataType) enumToUpdate).setLength(newSize);
					} else {
						// This case should ideally not happen if the initial check was for Enum and it
						// was resolved correctly.
						throw new IllegalStateException(
								"Enum is not an instance of EnumDataType, cannot set length: " + enumToUpdate.getPathName());
					}
				}

				return "Enum '" + context.originalPath() + "' updated successfully. Modified fields: "
						+ String.join(", ", context.updatedFields());
			});
		});
	}
}