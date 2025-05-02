package com.themixednuts.utils;

import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;

public class GhidraFunctionsToolInfo {
	private final String name;
	private final String address;
	private final String signature;
	private final String callingConvention;
	private final String namespace;
	private final String bodyMinAddress;
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