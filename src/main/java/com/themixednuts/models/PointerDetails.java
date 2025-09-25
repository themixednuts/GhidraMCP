package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;

public class PointerDetails extends BaseDataTypeDetails {

	private final String pointedToTypePathName;
	private final int pointerLengthSpecificToPointerDetails;

	public PointerDetails(Pointer pointer) {
		super(
				DataTypeKind.POINTER,
				pointer.getPathName(),
				pointer.getName(),
				pointer.getCategoryPath() == null ? CategoryPath.ROOT.getPath() : pointer.getCategoryPath().getPath(),
				pointer.getLength(),
				pointer.getAlignment(),
				pointer.getDescription() == null ? "" : pointer.getDescription());
		DataType pointedTo = pointer.getDataType();
		if (pointedTo != null) {
			this.pointedToTypePathName = pointedTo.getPathName();
		} else {
			this.pointedToTypePathName = "[undefined_or_void*]";
		}
		this.pointerLengthSpecificToPointerDetails = pointer.getLength();
	}

	@JsonProperty("pointed_to_type_path_name")
	public String getPointedToTypePathName() {
		return pointedToTypePathName;
	}

	@JsonProperty("pointer_length_specific_to_pointer_details")
	public int getPointerLengthSpecificToPointerDetails() {
		return pointerLengthSpecificToPointerDetails;
	}
}