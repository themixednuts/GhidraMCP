package com.themixednuts.models;

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
public class NamespaceInfo {

	private final String name;
	private final String fullName;
	private final long id;
	private final String bodyMinAddress;
	private final String bodyMaxAddress;
	private final boolean isGlobal;

	public NamespaceInfo(Namespace namespace) {
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

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("full_name")
	public String getFullName() {
		return fullName;
	}

	@JsonProperty("id")
	public long getId() {
		return id;
	}

	@JsonProperty("body_min_address")
	public String getBodyMinAddress() {
		return bodyMinAddress;
	}

	@JsonProperty("body_max_address")
	public String getBodyMaxAddress() {
		return bodyMaxAddress;
	}

	@JsonProperty("is_global")
	public boolean isGlobal() {
		return isGlobal;
	}
}