package com.themixednuts.models;

import java.util.List;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.block.CodeBlock;

/**
 * Plain Old Java Object (POJO) representing information about a basic block.
 */
public class BasicBlockInfo {

	private final String name;
	private final String startAddress;
	private final String endAddress;
	private final long size;
	private final List<String> addressRanges;

	/**
	 * Constructs a BasicBlockInfo from a Ghidra CodeBlock.
	 *
	 * @param block The Ghidra CodeBlock.
	 */
	public BasicBlockInfo(CodeBlock block) {
		this.name = block.getName();
		Address start = block.getFirstStartAddress();
		Address end = block.getMaxAddress();
		this.startAddress = start != null ? start.toString() : "N/A";
		this.endAddress = end != null ? end.toString() : "N/A";
		this.size = block.getNumAddresses();
		this.addressRanges = StreamSupport.stream(
				Spliterators.spliteratorUnknownSize(block.getAddressRanges(), Spliterator.ORDERED),
				false)
				.map(AddressRange::toString)
				.collect(Collectors.toList());
	}

	// --- Getters ---

	public String getName() {
		return name;
	}

	public String getStartAddress() {
		return startAddress;
	}

	public String getEndAddress() {
		return endAddress;
	}

	public long getSize() {
		return size;
	}

	public List<String> getAddressRanges() {
		return addressRanges;
	}
}