package com.themixednuts.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.Namespace;

/**
 * Utility class to hold relevant information about a Ghidra Namespace for JSON
 * serialization.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GhidraNamespaceInfo {

	@JsonProperty("name")
	private final String name;

	@JsonProperty("full_name")
	private final String fullName;

	@JsonProperty("id")
	private final long id;

	@JsonProperty("body_min_address")
	private final String bodyMinAddress; // If available

	@JsonProperty("body_max_address")
	private final String bodyMaxAddress; // If available

	@JsonProperty("is_global")
	private final boolean isGlobal;

	public GhidraNamespaceInfo(Namespace namespace) {
		this.name = namespace.getName();
		this.fullName = namespace.getName(true); // Get fully qualified name
		this.id = namespace.getID();
		this.isGlobal = namespace.isGlobal();

		AddressSetView body = namespace.getBody();
		if (body != null) {
			Address minAddr = body.getMinAddress();
			this.bodyMinAddress = (minAddr != null) ? minAddr.toString() : null;
			Address maxAddr = body.getMaxAddress();
			this.bodyMaxAddress = (maxAddr != null) ? maxAddr.toString() : null;
		} else {
			this.bodyMinAddress = null;
			this.bodyMaxAddress = null;
		}
	}

	// Getters
	public String getName() {
		return name;
	}

	public String getFullName() {
		return fullName;
	}

	public long getId() {
		return id;
	}

	public String getBodyMinAddress() {
		return bodyMinAddress;
	}

	public String getBodyMaxAddress() {
		return bodyMaxAddress;
	}

	public boolean isGlobal() {
		return isGlobal;
	}
}