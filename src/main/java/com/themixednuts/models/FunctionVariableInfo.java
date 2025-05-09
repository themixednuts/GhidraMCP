package com.themixednuts.models;

import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonGetter;

/**
 * Represents detailed information about a variable (parameter, local, or
 * decompiler-generated) within a function.
 */
@JsonPropertyOrder({ "effectiveName", "listingName", "decompilerName", "variableCategory", "isParameter", "dataType",
		"storage", "sourceType", "comment", "address", "symbolID" })
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionVariableInfo {

	public enum VariableCategory {
		PARAMETER,
		LOCAL_STACK,
		LOCAL_REGISTER,
		LOCAL_OTHER, // For listing variables with storage not easily categorized as stack/register
		DECOMPILER_SYNTHETIC // For variables primarily identified via decompiler, may not have direct
													// listing Variable
	}

	private String listingName; // Name from Variable.getName()
	private String decompilerName; // Name from HighVariable.getName()
	private final VariableCategory variableCategory;
	private final String dataType;
	private final String storage; // From VariableStorage or HighVariable varnode
	private final String sourceType; // From Variable.getSource(), or "DECOMPILER" if synthetic
	private final boolean isParameter;
	private final String comment; // From Variable.getComment()
	private final String address; // Symbol address or MinAddress of storage
	private final Long symbolID; // Symbol ID from Variable.getSymbol()

	// Constructor for formal listing Variables
	public FunctionVariableInfo(Variable var) {
		this.listingName = var.getName();
		this.dataType = var.getDataType().getDisplayName();
		this.storage = var.getVariableStorage().toString();
		this.sourceType = var.getSource().toString();
		this.isParameter = var instanceof Parameter;

		if (var instanceof Parameter) {
			this.variableCategory = VariableCategory.PARAMETER;
		} else if (var.isStackVariable()) {
			this.variableCategory = VariableCategory.LOCAL_STACK;
		} else if (var.isRegisterVariable()) {
			this.variableCategory = VariableCategory.LOCAL_REGISTER;
		} else {
			this.variableCategory = VariableCategory.LOCAL_OTHER;
		}

		String cmt = var.getComment();
		this.comment = (cmt == null || cmt.trim().isEmpty()) ? null : cmt;

		Symbol symbol = var.getSymbol();
		if (symbol != null) {
			this.symbolID = symbol.getID();
			Address symAddr = symbol.getAddress();
			this.address = (symAddr != null && symAddr.isMemoryAddress()) ? symAddr.toString() : null;
		} else {
			this.symbolID = null;
			if (var.isMemoryVariable() && var.getMinAddress() != null) {
				this.address = var.getMinAddress().toString();
			} else {
				this.address = null;
			}
		}
		this.decompilerName = null;
	}

	// Constructor for decompiler-centric variables (HighVariable)
	public FunctionVariableInfo(HighVariable highVar, Program program) {
		this.listingName = null;
		this.decompilerName = highVar.getName();
		this.dataType = highVar.getDataType().getDisplayName();

		Varnode repVarnode = highVar.getRepresentative();
		this.storage = repVarnode != null ? repVarnode.toString() : "<unknown_decompiler_storage>";

		this.sourceType = "DECOMPILER";
		this.variableCategory = VariableCategory.DECOMPILER_SYNTHETIC;

		HighSymbol highSymbol = highVar.getSymbol();
		Symbol symbol = null;
		boolean hvIsParameter = false;

		if (highSymbol != null) {
			symbol = highSymbol.getSymbol(); // Get listing Symbol from HighSymbol
			hvIsParameter = highSymbol.isParameter();
			if (hvIsParameter) {
				// this.variableCategory = VariableCategory.PARAMETER; // Refine category if
				// it's a parameter via HighSymbol
			} else {
				// Could try to infer stack/register from repVarnode if needed, but
				// DECOMPILER_SYNTHETIC is a good general category
			}
		}
		this.isParameter = hvIsParameter;

		this.comment = null; // HighVariable doesn't directly have comments

		if (symbol != null) {
			this.symbolID = symbol.getID();
			Address symAddr = symbol.getAddress();
			this.address = (symAddr != null && symAddr.isMemoryAddress()) ? symAddr.toString() : null;
		} else {
			this.symbolID = null;
			// For HighVariables, address might be inferred from its representative varnode
			if (repVarnode != null && repVarnode.isAddress()) {
				this.address = repVarnode.getAddress().toString();
			} else {
				this.address = null;
			}
		}
	}

	// Getter for the name that should be primarily used for display/identification
	@JsonGetter("effectiveName")
	public String getEffectiveName() {
		if (decompilerName != null && !decompilerName.trim().isEmpty()) {
			return decompilerName;
		}
		if (listingName != null && !listingName.trim().isEmpty()) {
			return listingName;
		}
		return "<unnamed_variable>"; // Fallback if both are somehow null/empty
	}

	// Standard Getters
	public String getListingName() {
		return listingName;
	}

	public String getDecompilerName() {
		return decompilerName;
	}

	public VariableCategory getVariableCategory() {
		return variableCategory;
	}

	public String getDataType() {
		return dataType;
	}

	public String getStorage() {
		return storage;
	}

	public String getSourceType() {
		return sourceType;
	}

	public boolean isParameter() {
		return isParameter;
	}

	public String getComment() {
		return comment;
	}

	public String getAddress() {
		return address;
	}

	public Long getSymbolID() {
		return symbolID;
	}

	// Setter for decompilerName, to be used by the listing tool when correlating
	public void setDecompilerName(String decompilerName) {
		this.decompilerName = decompilerName;
	}

	public void setListingName(String listingName) {
		this.listingName = listingName;
	}

}