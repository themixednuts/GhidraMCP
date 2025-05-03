package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.symbol.Reference;

/**
 * POJO for serializing Ghidra Reference information.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ReferenceInfo {

	@JsonProperty("from_address")
	private final String fromAddress;

	@JsonProperty("to_address")
	private final String toAddress;

	@JsonProperty("type")
	private final String type;

	@JsonProperty("is_primary")
	private final boolean primary;

	@JsonProperty("is_memory_reference")
	private final boolean memoryReference;

	@JsonProperty("is_offset_reference")
	private final boolean offsetReference;

	@JsonProperty("is_shift_reference")
	private final boolean shiftedReference;

	@JsonProperty("is_register_reference")
	private final boolean registerReference;

	@JsonProperty("is_stack_reference")
	private final boolean stackReference;

	@JsonProperty("is_external_reference")
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

	// --- Getters ---

	public String getFromAddress() {
		return fromAddress;
	}

	public String getToAddress() {
		return toAddress;
	}

	public String getType() {
		return type;
	}

	public boolean isPrimary() {
		return primary;
	}

	public boolean isMemoryReference() {
		return memoryReference;
	}

	public boolean isOffsetReference() {
		return offsetReference;
	}

	public boolean isShiftedReference() {
		return shiftedReference;
	}

	public boolean isRegisterReference() {
		return registerReference;
	}

	public boolean isStackReference() {
		return stackReference;
	}

	public boolean isExternalReference() {
		return externalReference;
	}
}