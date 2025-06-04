package com.themixednuts.models;

import java.util.List;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.block.CodeBlock;

/**
 * Plain Old Java Object (POJO) representing information about a basic block.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
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

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("start_address")
	public String getStartAddress() {
		return startAddress;
	}

	@JsonProperty("end_address")
	public String getEndAddress() {
		return endAddress;
	}

	@JsonProperty("size")
	public long getSize() {
		return size;
	}

	@JsonProperty("address_ranges")
	public List<String> getAddressRanges() {
		return addressRanges;
	}
}