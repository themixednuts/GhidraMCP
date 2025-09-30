package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionInfo {
	private final String name;
	private final String qualifiedName;
	private final String address;
	private final String signature;
	private final String callingConvention;
	private final String namespace;
	private final String bodyMinAddress;
	private final String bodyMaxAddress;

	public FunctionInfo(Function function) {
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
			// Get fully qualified name using NamespaceUtils
			this.qualifiedName = NamespaceUtils.getNamespaceQualifiedName(
				parentNs,
				function.getName(),
				false
			);
		} else {
			this.namespace = null;
			this.qualifiedName = function.getName();
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

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("qualified_name")
	public String getQualifiedName() {
		return qualifiedName;
	}

	@JsonProperty("address")
	public String getAddress() {
		return address;
	}

	@JsonProperty("signature")
	public String getSignature() {
		return signature;
	}

	@JsonProperty("calling_convention")
	public String getCallingConvention() {
		return callingConvention;
	}

	@JsonProperty("namespace")
	public String getNamespace() {
		return namespace;
	}

	@JsonProperty("body_min_address")
	public String getBodyMinAddress() {
		return bodyMinAddress;
	}

	@JsonProperty("body_max_address")
	public String getBodyMaxAddress() {
		return bodyMaxAddress;
	}
}