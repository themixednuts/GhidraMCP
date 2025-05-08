package com.themixednuts.models;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.tools.datatypes.DataTypeKind;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Union;

/**
 * Model representing the detailed definition of a Union data type.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UnionDetails extends BaseDataTypeDetails {

	@JsonProperty("num_components")
	private final int numComponents;

	@JsonProperty("members")
	private final List<UnionMemberInfo> members;

	public UnionDetails(Union unionDt) {
		super(
				DataTypeKind.UNION,
				unionDt.getPathName(),
				unionDt.getName(),
				unionDt.getCategoryPath().getPath(),
				unionDt.getLength(),
				unionDt.getAlignment(),
				Optional.ofNullable(unionDt.getDescription()).orElse(""));
		this.numComponents = unionDt.getNumComponents();

		List<UnionMemberInfo> memberInfos = new ArrayList<>();
		for (DataTypeComponent component : unionDt.getComponents()) {
			memberInfos.add(new UnionMemberInfo(component));
		}
		this.members = memberInfos;
	}

	// Getters
	public int getNumComponents() {
		return numComponents;
	}

	public List<UnionMemberInfo> getMembers() {
		return members;
	}
}
