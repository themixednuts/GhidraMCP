package com.themixednuts.models;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A simplified POJO for representing a raw P-code operation directly from an
 * Instruction,
 * without decompiler (HighFunction) context.
 */
public record RawPcodeOpInfo(
		String mnemonic,
		String outputVarnode, // String representation of the output varnode
		List<String> inputVarnodes, // List of string representations of input varnodes
		String rawPcodeOp // Full PcodeOp.toString()
) {
	private static String varnodeToString(Varnode vn) {
		if (vn == null) {
			return null;
		}
		// Provides a basic string representation. More detail (like type, size) could
		// be added.
		return vn.toString();
	}

	public static RawPcodeOpInfo fromPcodeOp(PcodeOp pcodeOp) {
		if (pcodeOp == null) {
			return null;
		}

		String mnemonic = pcodeOp.getMnemonic();
		String rawRepresentation = pcodeOp.toString();

		String outputVnStr = varnodeToString(pcodeOp.getOutput());

		List<String> inputVnStrs;
		Varnode[] inputs = pcodeOp.getInputs();
		if (inputs != null) {
			inputVnStrs = Arrays.stream(inputs)
					.map(RawPcodeOpInfo::varnodeToString)
					.collect(Collectors.toList());
		} else {
			inputVnStrs = Collections.emptyList();
		}

		return new RawPcodeOpInfo(mnemonic, outputVnStr, inputVnStrs, rawRepresentation);
	}
}