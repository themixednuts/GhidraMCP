package com.themixednuts.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class GhidraFunctionsToolInfo {
	@JsonProperty("name")
	private final String name;
	@JsonProperty("address")
	private final String address;
	@JsonProperty("signature")
	private final String signature;
	@JsonProperty("calling_convention")
	private final String callingConvention;
	@JsonProperty("namespace")
	private final String namespace;
	@JsonProperty("body_min_address")
	private final String bodyMinAddress;
	@JsonProperty("body_max_address")
	private final String bodyMaxAddress;

	public GhidraFunctionsToolInfo(Function function) {
		this.name = function.getName();

		if (function.getEntryPoint() != null) {
			this.address = function.getEntryPoint().toString();
		} else {
			this.address = null;
		}

		this.signature = function.getSignature(true).getPrototypeString();
		this.callingConvention = function.getCallingConventionName();

		Namespace parentNs = function.getParentNamespace();
		if (parentNs != null) {
			this.namespace = parentNs.getName(true);
		} else {
			this.namespace = null;
		}

		if (function.getBody() != null) {
			if (function.getBody().getMinAddress() != null) {
				this.bodyMinAddress = function.getBody().getMinAddress().toString();
			} else {
				this.bodyMinAddress = null;
			}
			if (function.getBody().getMaxAddress() != null) {
				this.bodyMaxAddress = function.getBody().getMaxAddress().toString();
			} else {
				this.bodyMaxAddress = null;
			}
		} else {
			this.bodyMinAddress = null;
			this.bodyMaxAddress = null;
		}

	}

	public String getName() {
		return name;
	}

	public String getAddress() {
		return address;
	}

	public String getSignature() {
		return signature;
	}

	public String getCallingConvention() {
		return callingConvention;
	}

	public String getNamespace() {
		return namespace;
	}

	public String getBodyMinAddress() {
		return bodyMinAddress;
	}

	public String getBodyMaxAddress() {
		return bodyMaxAddress;
	}
}