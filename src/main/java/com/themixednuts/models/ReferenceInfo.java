package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.symbol.Reference;

/**
 * POJO for serializing Ghidra Reference information.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ReferenceInfo {

	private final String fromAddress;

	private final String toAddress;

	private final String type;

	private final boolean primary;

	private final boolean memoryReference;

	private final boolean offsetReference;

	private final boolean shiftedReference;

	private final boolean registerReference;

	private final boolean stackReference;

	private final boolean externalReference;

	public ReferenceInfo(Reference reference) {
		this.fromAddress = reference.getFromAddress().toString();
		this.toAddress = reference.getToAddress().toString();
		this.type = reference.getReferenceType().getName();
		this.primary = reference.isPrimary();
		this.memoryReference = reference.isMemoryReference();
		this.offsetReference = reference.isOffsetReference();
		this.shiftedReference = reference.isShiftedReference();
		this.registerReference = reference.isRegisterReference();
		this.stackReference = reference.isStackReference();
		this.externalReference = reference.isExternalReference();
	}

	@JsonProperty("from_address")
	public String getFromAddress() {
		return fromAddress;
	}

	@JsonProperty("to_address")
	public String getToAddress() {
		return toAddress;
	}

	@JsonProperty("type")
	public String getType() {
		return type;
	}

	@JsonProperty("is_primary")
	public boolean isPrimary() {
		return primary;
	}

	@JsonProperty("is_memory_reference")
	public boolean isMemoryReference() {
		return memoryReference;
	}

	@JsonProperty("is_offset_reference")
	public boolean isOffsetReference() {
		return offsetReference;
	}

	@JsonProperty("is_shift_reference")
	public boolean isShiftedReference() {
		return shiftedReference;
	}

	@JsonProperty("is_register_reference")
	public boolean isRegisterReference() {
		return registerReference;
	}

	@JsonProperty("is_stack_reference")
	public boolean isStackReference() {
		return stackReference;
	}

	@JsonProperty("is_external_reference")
	public boolean isExternalReference() {
		return externalReference;
	}
}