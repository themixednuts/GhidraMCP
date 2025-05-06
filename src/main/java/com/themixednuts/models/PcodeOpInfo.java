package com.themixednuts.models;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.HighFunction; // For context to VarnodeInfo

public record PcodeOpInfo(
		String opAddress,
		int order,
		String mnemonic,
		VarnodeInfo output,
		List<VarnodeInfo> inputs,
		String rawPcodeOp) {
	public static PcodeOpInfo fromPcodeOpAST(PcodeOpAST pcodeOp, HighFunction highFunc) {
		if (pcodeOp == null || highFunc == null) {
			return null;
		}

		String address = pcodeOp.getSeqnum().getTarget().toString();
		int seqOrder = pcodeOp.getSeqnum().getTime();
		String mnem = pcodeOp.getMnemonic();
		String rawPcode = pcodeOp.toString();

		VarnodeInfo outVnInfo = null;
		Varnode outputVarnode = pcodeOp.getOutput();
		if (outputVarnode != null) {
			outVnInfo = VarnodeInfo.fromVarnode(outputVarnode, highFunc);
		}

		List<VarnodeInfo> inVnInfos;
		Varnode[] inputVarnodes = pcodeOp.getInputs();
		if (inputVarnodes != null) {
			inVnInfos = Arrays.stream(inputVarnodes)
					.map(vn -> VarnodeInfo.fromVarnode(vn, highFunc))
					.collect(Collectors.toList());
		} else {
			inVnInfos = Collections.emptyList();
		}

		return new PcodeOpInfo(address, seqOrder, mnem, outVnInfo, inVnInfos, rawPcode);
	}
}