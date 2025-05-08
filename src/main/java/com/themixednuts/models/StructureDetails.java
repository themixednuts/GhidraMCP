package com.themixednuts.models;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.tools.datatypes.DataTypeKind;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;

/**
 * Model representing the detailed definition of a Structure data type.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class StructureDetails extends BaseDataTypeDetails {

	@JsonProperty("num_components")
	private final int numComponents;

	@JsonProperty("members")
	private final List<StructureMemberInfo> members;

	public StructureDetails(Structure struct) {
		super(
				DataTypeKind.STRUCT,
				struct.getPathName(),
				struct.getName(),
				struct.getCategoryPath().getPath(),
				struct.getLength(),
				struct.getAlignment(),
				Optional.ofNullable(struct.getDescription()).orElse(""));
		this.numComponents = struct.getNumComponents();

		List<StructureMemberInfo> memberInfos = new ArrayList<>();
		for (DataTypeComponent component : struct.getDefinedComponents()) {
			memberInfos.add(new StructureMemberInfo(
					component.getFieldName(),
					component.getDataType().getPathName(),
					component.getOffset(),
					component.getOrdinal(),
					component.getLength(),
					Optional.ofNullable(component.getComment()).orElse(""),
					component.isBitFieldComponent()));
		}
		this.members = memberInfos;
	}

	// Getters
	public int getNumComponents() {
		return numComponents;
	}

	public List<StructureMemberInfo> getMembers() {
		return members;
	}
}
