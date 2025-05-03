package com.themixednuts.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

/**
 * Utility class to hold relevant information about a Ghidra Variable for JSON
 * serialization.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GhidraVariableInfo {

	@JsonProperty("name")
	private final String name;

	@JsonProperty("comment")
	private final String comment;

	@JsonProperty("data_type")
	private final String dataTypeName; // Store name, avoid complex object

	@JsonProperty("length")
	private final int length;

	@JsonProperty("first_use_offset")
	private final long firstUseOffset;

	@JsonProperty("source_type")
	private final String sourceType;

	@JsonProperty("storage")
	private final String storageString;

	@JsonProperty("is_stack_variable")
	private final boolean isStackVariable;

	@JsonProperty("is_register_variable")
	private final boolean isRegisterVariable;

	@JsonProperty("is_parameter")
	private final boolean isParameter;

	@JsonProperty("is_compound_variable")
	private final boolean isCompoundVariable;

	@JsonProperty("has_stack_storage")
	private final boolean hasStackStorage;

	@JsonProperty("function_name")
	private final String functionName; // Optional: Name of the containing function

	@JsonProperty("function_address")
	private final String functionAddress; // Optional: Address of the containing function

	public GhidraVariableInfo(Variable variable) {
		this.name = variable.getName();
		this.comment = variable.getComment();

		DataType dt = variable.getDataType();
		this.dataTypeName = (dt != null) ? dt.getDisplayName() : null;

		this.length = variable.getLength();
		this.firstUseOffset = variable.getFirstUseOffset();

		SourceType srcType = variable.getSource();
		this.sourceType = (srcType != null) ? srcType.toString() : null;

		VariableStorage storage = variable.getVariableStorage();
		this.storageString = (storage != null) ? storage.toString() : null;

		this.isStackVariable = variable.isStackVariable();
		this.isRegisterVariable = variable.isRegisterVariable();
		this.isParameter = variable instanceof ghidra.program.model.listing.Parameter;
		this.isCompoundVariable = variable.isCompoundVariable();
		this.hasStackStorage = variable.hasStackStorage();

		Function func = variable.getFunction();
		if (func != null) {
			this.functionName = func.getName();
			this.functionAddress = func.getEntryPoint().toString();
		} else {
			this.functionName = null;
			this.functionAddress = null;
		}
	}

	// Getters
	public String getName() {
		return name;
	}

	public String getComment() {
		return comment;
	}

	public String getDataTypeName() {
		return dataTypeName;
	}

	public int getLength() {
		return length;
	}

	public long getFirstUseOffset() {
		return firstUseOffset;
	}

	public String getSourceType() {
		return sourceType;
	}

	public String getStorageString() {
		return storageString;
	}

	public boolean isStackVariable() {
		return isStackVariable;
	}

	public boolean isRegisterVariable() {
		return isRegisterVariable;
	}

	public boolean isParameter() {
		return isParameter;
	}

	public boolean isCompoundVariable() {
		return isCompoundVariable;
	}

	public boolean isHasStackStorage() {
		return hasStackStorage;
	}

	public String getFunctionName() {
		return functionName;
	}

	public String getFunctionAddress() {
		return functionAddress;
	}
}