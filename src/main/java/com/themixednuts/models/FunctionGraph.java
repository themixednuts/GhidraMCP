package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionGraph {

	private final String functionName;
	private final String functionAddress;
	private final List<FunctionGraphNode> nodes;
	private final List<FunctionGraphEdge> edges;

	public FunctionGraph(String functionName, String functionAddress, List<FunctionGraphNode> nodes, List<FunctionGraphEdge> edges) {
		this.functionName = functionName;
		this.functionAddress = functionAddress;
		this.nodes = nodes;
		this.edges = edges;
	}

	@JsonProperty("function_name")
	public String getFunctionName() {
		return functionName;
	}

	@JsonProperty("function_address")
	public String getFunctionAddress() {
		return functionAddress;
	}

	@JsonProperty("nodes")
	public List<FunctionGraphNode> getNodes() {
		return nodes;
	}

	@JsonProperty("edges")
	public List<FunctionGraphEdge> getEdges() {
		return edges;
	}
}



