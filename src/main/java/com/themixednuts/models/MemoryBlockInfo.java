package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import ghidra.program.model.mem.MemoryBlock;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class MemoryBlockInfo {

	private String name;
	private String startAddress;
	private String endAddress;
	private long size;
	private boolean read;
	private boolean write;
	private boolean execute;
	private boolean isVolatile;

	public MemoryBlockInfo(MemoryBlock block) {
		this.name = block.getName();
		this.startAddress = block.getStart().toString();
		this.endAddress = block.getEnd().toString();
		this.size = block.getSize();
		this.read = block.isRead();
		this.write = block.isWrite();
		this.execute = block.isExecute();
		this.isVolatile = block.isVolatile();
	}

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

	@JsonProperty("read")
	public boolean isRead() {
		return read;
	}

	@JsonProperty("write")
	public boolean isWrite() {
		return write;
	}

	@JsonProperty("execute")
	public boolean isExecute() {
		return execute;
	}

	@JsonProperty("volatile")
	public boolean isVolatile() {
		return isVolatile;
	}
}