package com.themixednuts.utils;

import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.CancelledException;

public class DataTypeUtils {

	/**
	 * Parses a data type string using a multi-step approach:
	 * <ol>
	 * <li>Direct lookup using the program's
	 * {@link DataTypeManager#getDataType(String)}.</li>
	 * <li>If not found and {@link DataTypeManagerService} is available, attempts to
	 * parse using
	 * {@link DataTypeParser#parse(String)} with the original path.</li>
	 * <li>If still not found and the path was modified (leading '/' removed,
	 * internal '/' replaced with '::'),
	 * attempts to parse the modified path using {@link DataTypeParser}.</li>
	 * </ol>
	 *
	 * @param program      The current program, used to get the DataTypeManager.
	 * @param dataTypePath The string representation of the data type to parse
	 *                     (e.g., "int", "char *", "/MyCategory/MyStruct",
	 *                     "MyCat::MyStruct").
	 * @param tool         The PluginTool instance, used to get the
	 *                     {@link DataTypeManagerService} for advanced parsing.
	 * @return The resolved {@link DataType}, or {@code null} if the data type
	 *         string is syntactically valid
	 *         but the type is not found after all attempts, or if the
	 *         {@code DataTypeManagerService}
	 *         is unavailable and the direct lookup fails.
	 * @throws IllegalArgumentException if the {@code dataTypePath} is null or
	 *                                  blank.
	 * @throws InvalidDataTypeException if a syntax error occurs during parsing with
	 *                                  {@code DataTypeParser}
	 *                                  (only when {@code DataTypeManagerService} is
	 *                                  available and used).
	 * @throws CancelledException       if parsing is cancelled.
	 */
	public static DataType parseDataTypeString(Program program, String dataTypePath, PluginTool tool)
			throws IllegalArgumentException, CancelledException, InvalidDataTypeException {
		if (dataTypePath == null || dataTypePath.isBlank()) {
			throw new IllegalArgumentException("Data type path cannot be null or blank.");
		}

		DataType dt = program.getDataTypeManager().getDataType(dataTypePath);
		if (dt != null) {
			return dt;
		}

		DataTypeManager programDtm = program.getDataTypeManager();
		DataTypeManagerService dtmService = tool.getService(DataTypeManagerService.class);

		DataTypeParser parser = new DataTypeParser(programDtm, programDtm, dtmService, DataTypeParser.AllowedDataTypes.ALL);
		InvalidDataTypeException firstParseException = null;

		try {
			dt = parser.parse(dataTypePath);
			if (dt != null) {
				return dt;
			}
		} catch (InvalidDataTypeException e) {
			firstParseException = e;
		}

		String originalPathForComparison = dataTypePath;
		String pathForThirdAttempt = dataTypePath;

		if (pathForThirdAttempt.startsWith("/")) {
			pathForThirdAttempt = pathForThirdAttempt.substring(1);
		}
		if (pathForThirdAttempt.contains("/")) {
			pathForThirdAttempt = pathForThirdAttempt.replace("/", "::");
		}

		boolean actuallyModified = !pathForThirdAttempt.equals(originalPathForComparison);

		if (!actuallyModified) {
			return null;
		}

		try {
			dt = parser.parse(pathForThirdAttempt);
			if (dt != null) {
				return dt;
			}
		} catch (InvalidDataTypeException e) {
			if (firstParseException != null) {
				throw firstParseException;
			}
			throw e;
		}

		if (firstParseException != null) {
			throw firstParseException;
		}

		return null;
	}
}