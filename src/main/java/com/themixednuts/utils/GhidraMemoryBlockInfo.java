package com.themixednuts.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class GhidraMemoryBlockInfo {

	@JsonProperty("name")
	private String name;

	@JsonProperty("start_address")
	private String startAddress;

	@JsonProperty("end_address")
	private String endAddress;

	@JsonProperty("size")
	private long size;

	@JsonProperty("read")
	private boolean read;

	@JsonProperty("write")
	private boolean write;

	@JsonProperty("execute")
	private boolean execute;

	@JsonProperty("volatile")
	private boolean isVolatile;

	// Private constructor for Jackson
	private GhidraMemoryBlockInfo() {
	}

	public GhidraMemoryBlockInfo(MemoryBlock block) {
		this.name = block.getName();
		this.startAddress = block.getStart().toString();
		this.endAddress = block.getEnd().toString();
		this.size = block.getSize();
		this.read = block.isRead();
		this.write = block.isWrite();
		this.execute = block.isExecute();
		this.isVolatile = block.isVolatile();
	}

	// Getters (optional, Jackson uses fields or getters)
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

	public boolean isRead() {
		return read;
	}

	public boolean isWrite() {
		return write;
	}

	public boolean isExecute() {
		return execute;
	}

	public boolean isVolatile() {
		return isVolatile;
	}
}