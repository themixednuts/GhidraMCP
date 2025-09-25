package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.listing.Function;

import java.util.List;
import java.util.stream.Collectors;
import java.util.Arrays;

/**
 * Comprehensive function analysis model combining basic info with advanced analysis.
 * Used by AnalyzeFunctionsTool for detailed function information.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionAnalysis {
    private final FunctionInfo basicInfo;
    private final int parameterCount;
    private final String returnType;
    private final int bodySize;
    private final List<ParameterInfo> parameters;

    // Optional analysis data
    private String decompiledCode;
    private List<String> pcodeOperations;

    public FunctionAnalysis(Function function) {
        this.basicInfo = new FunctionInfo(function);
        this.parameterCount = function.getParameterCount();
        this.returnType = function.getReturnType().getName();
        this.bodySize = (int) function.getBody().getNumAddresses();

        // Extract parameters
        this.parameters = Arrays.stream(function.getParameters())
            .map(ParameterInfo::new)
            .collect(Collectors.toList());
    }

    @JsonProperty("basic_info")
    public FunctionInfo getBasicInfo() {
        return basicInfo;
    }

    @JsonProperty("parameter_count")
    public int getParameterCount() {
        return parameterCount;
    }

    @JsonProperty("return_type")
    public String getReturnType() {
        return returnType;
    }

    @JsonProperty("body_size")
    public int getBodySize() {
        return bodySize;
    }

    @JsonProperty("parameters")
    public List<ParameterInfo> getParameters() {
        return parameters;
    }

    @JsonProperty("decompiled_code")
    public String getDecompiledCode() {
        return decompiledCode;
    }

    public void setDecompiledCode(String decompiledCode) {
        this.decompiledCode = decompiledCode;
    }

    @JsonProperty("pcode_operations")
    public List<String> getPcodeOperations() {
        return pcodeOperations;
    }

    public void setPcodeOperations(List<String> pcodeOperations) {
        this.pcodeOperations = pcodeOperations;
    }
}