package com.themixednuts.utils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

import java.util.Iterator;

/**
 * Utility class for working with Ghidra data types.
 * Provides methods to parse, resolve, and work with data types in Ghidra programs.
 */
public class DataTypeUtils {

    /**
     * Parses a data type string and returns the corresponding DataType.
     * This method is used by existing tools and expects data type paths in various formats.
     *
     * @param program the Program context
     * @param dataTypePath the data type path string (e.g., "/int", "dword", "MyStruct", "/MyCategory/MyStruct")
     * @param tool the PluginTool context
     * @return the resolved DataType
     * @throws IllegalArgumentException if the data type cannot be parsed or found
     * @throws CancelledException if the operation was cancelled
     * @throws InvalidDataTypeException if the data type is invalid
     */
    public static DataType parseDataTypeString(Program program, String dataTypePath, PluginTool tool)
            throws IllegalArgumentException, CancelledException, InvalidDataTypeException {
        if (program == null || dataTypePath == null || dataTypePath.trim().isEmpty()) {
            throw new IllegalArgumentException("Program and dataTypePath cannot be null or empty");
        }

        DataTypeManager programDtm = program.getDataTypeManager();
        String trimmedPath = dataTypePath.trim();

        // Note: DataTypeParser is not available in public API, so we use manual resolution

        // Fall back to manual resolution methods
        DataType result = null;

        // First try direct lookup if it starts with /
        if (trimmedPath.startsWith("/")) {
            try {
                result = programDtm.getDataType(trimmedPath);
            } catch (Exception e) {
                // Continue with other methods
            }
        }

        // Try built-in types by name
        if (result == null) {
            result = resolveBuiltInDataType(programDtm, trimmedPath);
        }

        // Try finding by name in program data types
        if (result == null) {
            result = resolveDataTypeByName(programDtm, trimmedPath);
        }

        // Try parsing as category path + name
        if (result == null && trimmedPath.contains("/")) {
            result = resolveDataTypeByPath(programDtm, trimmedPath);
        }

        // Handle pointer types (ending with *)
        if (result == null && trimmedPath.endsWith("*")) {
            String baseTypeName = trimmedPath.substring(0, trimmedPath.length() - 1).trim();
            DataType baseType = parseDataTypeString(program, baseTypeName, tool);
            result = programDtm.getPointer(baseType);
        }

        if (result == null) {
            throw new IllegalArgumentException("Could not resolve data type: " + dataTypePath);
        }

        return result;
    }

    /**
     * Resolves a data type by name from built-in types.
     */
    private static DataType resolveBuiltInDataType(DataTypeManager dtm, String typeName) {
        // Try common built-in types directly
        switch (typeName.toLowerCase()) {
            case "byte": case "char": case "uchar": return SignedByteDataType.dataType;
            case "short": case "word": return SignedWordDataType.dataType;
            case "int": case "dword": return SignedDWordDataType.dataType;
            case "long": case "qword": return SignedQWordDataType.dataType;
            case "float": return FloatDataType.dataType;
            case "double": return DoubleDataType.dataType;
            case "void": return VoidDataType.dataType;
            case "pointer": return PointerDataType.dataType;
            case "string": return StringDataType.dataType;
            default: return null;
        }
    }

    /**
     * Resolves a data type by searching all program data types by name.
     */
    private static DataType resolveDataTypeByName(DataTypeManager dtm, String typeName) {
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType type = allTypes.next();
            if (type.getName().equals(typeName)) {
                return type;
            }
        }
        return null;
    }

    /**
     * Resolves a data type by parsing a full category path.
     */
    private static DataType resolveDataTypeByPath(DataTypeManager dtm, String fullPath) {
        try {
            int lastSlash = fullPath.lastIndexOf('/');
            if (lastSlash > 0) {
                String categoryPathStr = fullPath.substring(0, lastSlash);
                String typeName = fullPath.substring(lastSlash + 1);
                CategoryPath categoryPath = new CategoryPath(categoryPathStr);
                return dtm.getDataType(categoryPath, typeName);
            }
        } catch (Exception e) {
            // Fall through to return null
        }
        return null;
    }

    /**
     * Simple version of resolveDataType for tool compatibility.
     *
     * @param dtm the DataTypeManager to search in
     * @param typeName the name of the data type to find
     * @return the DataType if found, null otherwise
     */
    public static DataType resolveDataType(DataTypeManager dtm, String typeName) {
        if (dtm == null || typeName == null || typeName.trim().isEmpty()) {
            return null;
        }

        String trimmedName = typeName.trim();

        // Try built-in types first
        DataType result = resolveBuiltInDataType(dtm, trimmedName);

        // Try finding in program data type manager
        if (result == null) {
            result = resolveDataTypeByName(dtm, trimmedName);
        }

        // Try common variations for pointer types
        if (result == null && trimmedName.endsWith("*")) {
            String baseTypeName = trimmedName.substring(0, trimmedName.length() - 1).trim();
            DataType baseType = resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                result = dtm.getPointer(baseType);
            }
        }

        return result;
    }

    /**
     * Gets a human-readable description of the data type kind.
     *
     * @param dataType the DataType to describe
     * @return a string describing the kind of data type
     */
    public static String getDataTypeKind(DataType dataType) {
        if (dataType == null) {
            return "unknown";
        }

        if (dataType instanceof Structure) return "struct";
        if (dataType instanceof ghidra.program.model.data.Enum) return "enum";
        if (dataType instanceof Union) return "union";
        if (dataType instanceof TypeDef) return "typedef";
        if (dataType instanceof Pointer) return "pointer";
        if (dataType instanceof FunctionDefinitionDataType) return "function_definition";
        if (dataType instanceof Array) return "array";

        String className = dataType.getClass().getSimpleName();
        return className.toLowerCase().replace("datatype", "");
    }
}