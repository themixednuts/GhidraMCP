package com.themixednuts.models;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.tools.datatypes.DataTypeKind;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;

/**
 * Model representing the detailed definition of a FunctionDefinition data type.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionDefinitionDetails extends BaseDataTypeDetails {

	@JsonProperty("return_type_path")
	private final String returnTypePath;

	@JsonProperty("calling_convention_name")
	private final String callingConventionName;

	@JsonProperty("has_var_args")
	private final boolean hasVarArgs;

	@JsonProperty("has_no_return")
	private final boolean hasNoReturn;

	@JsonProperty("parameters")
	private final List<ParameterInfo> parameters;

	public FunctionDefinitionDetails(FunctionDefinition funcDef) {
		super(
				DataTypeKind.FUNCTION_DEFINITION,
				funcDef.getPathName(),
				funcDef.getName(),
				funcDef.getCategoryPath().getPath(),
				funcDef.getLength(),
				funcDef.getAlignment(),
				Optional.ofNullable(funcDef.getDescription()).orElse(""));
		this.returnTypePath = funcDef.getReturnType().getPathName();
		this.callingConventionName = funcDef.getCallingConventionName();
		this.hasVarArgs = funcDef.hasVarArgs();
		this.hasNoReturn = funcDef.hasNoReturn();

		List<ParameterInfo> paramInfos = new ArrayList<>();
		for (ParameterDefinition paramDef : funcDef.getArguments()) {
			paramInfos.add(new ParameterInfo(
					paramDef.getName(),
					paramDef.getDataType().getPathName(),
					Optional.ofNullable(paramDef.getComment()).orElse(""),
					paramDef.getLength()));
		}
		this.parameters = paramInfos;
	}

	// Getters
	public String getReturnTypePath() {
		return returnTypePath;
	}

	public String getCallingConventionName() {
		return callingConventionName;
	}

	public boolean hasVarArgs() {
		return hasVarArgs;
	}

	public boolean hasNoReturn() {
		return hasNoReturn;
	}

	public List<ParameterInfo> getParameters() {
		return parameters;
	}
}
