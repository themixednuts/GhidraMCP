package com.themixednuts.models;

/**
 * Enumeration of data type kinds for Ghidra data types. Used to categorize different types of data
 * structures.
 */
public enum DataTypeKind {
  PRIMITIVE,
  STRUCTURE,
  UNION,
  ENUM,
  ARRAY,
  POINTER,
  FUNCTION_DEFINITION,
  TYPEDEF,
  OTHER
}
