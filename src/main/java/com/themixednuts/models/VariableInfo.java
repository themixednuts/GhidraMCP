package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class VariableInfo {

	private final String name;
	private final String comment;
	private final String dataTypeName;
	private final int length;
	private final long firstUseOffset;
	private final String sourceType;
	private final String storageString;
	private final boolean isStackVariable;
	private final boolean isRegisterVariable;
	private final boolean isParameter;
	private final boolean isCompoundVariable;
	private final boolean hasStackStorage;
	private final String functionName;
	private final String functionAddress;

	public VariableInfo(Variable variable) {
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

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("comment")
	public String getComment() {
		return comment;
	}

	@JsonProperty("data_type")
	public String getDataTypeName() {
		return dataTypeName;
	}

	@JsonProperty("length")
	public int getLength() {
		return length;
	}

	@JsonProperty("first_use_offset")
	public long getFirstUseOffset() {
		return firstUseOffset;
	}

	@JsonProperty("source_type")
	public String getSourceType() {
		return sourceType;
	}

	@JsonProperty("storage")
	public String getStorageString() {
		return storageString;
	}

	@JsonProperty("is_stack_variable")
	public boolean isStackVariable() {
		return isStackVariable;
	}

	@JsonProperty("is_register_variable")
	public boolean isRegisterVariable() {
		return isRegisterVariable;
	}

	@JsonProperty("is_parameter")
	public boolean isParameter() {
		return isParameter;
	}

	@JsonProperty("is_compound_variable")
	public boolean isCompoundVariable() {
		return isCompoundVariable;
	}

	@JsonProperty("has_stack_storage")
	public boolean isHasStackStorage() {
		return hasStackStorage;
	}

	@JsonProperty("function_name")
	public String getFunctionName() {
		return functionName;
	}

	@JsonProperty("function_address")
	public String getFunctionAddress() {
		return functionAddress;
	}
}