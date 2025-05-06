package com.themixednuts.models;

import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;

public record VarnodeInfo(
		String type,
		String address,
		int size,
		Long constantValue,
		String registerName) {
	public static VarnodeInfo fromVarnode(Varnode vn, HighFunction highFunc) {
		if (vn == null || highFunc == null) {
			return null;
		}

		String typeStr;
		String addrStr = null;
		Long constVal = null;
		String regName = null;
		Program program = highFunc.getFunction().getProgram();

		if (vn.isRegister()) {
			typeStr = "register";
			regName = program.getLanguage().getRegister(vn.getAddress(), vn.getSize()).getName();
			addrStr = vn.getAddress().toString();
		} else if (vn.isConstant()) {
			typeStr = "constant";
			constVal = vn.getOffset();
		} else if (vn.isAddress()) {
			typeStr = "ram";
			addrStr = vn.getAddress().toString();
		} else if (vn.isUnique()) {
			typeStr = "unique";
			addrStr = "unique_0x" + Long.toHexString(vn.getOffset());
		} else {
			typeStr = "unknown";
		}

		return new VarnodeInfo(typeStr, addrStr, vn.getSize(), constVal, regName);
	}
}