package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import ghidra.program.model.mem.MemoryBlock;

@JsonPropertyOrder({"name", "start_address", "end_address", "size", "permissions", "volatile"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MemoryBlockInfo {

  private final String name;
  private final String startAddress;
  private final String endAddress;
  private final long size;
  private final String permissions;
  private final Boolean volatileBlock;

  public MemoryBlockInfo(MemoryBlock block) {
    this.name = block.getName();
    this.startAddress = block.getStart().toString();
    this.endAddress = block.getEnd().toString();
    this.size = block.getSize();
    this.permissions = formatPermissions(block);
    this.volatileBlock = block.isVolatile() ? Boolean.TRUE : null;
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

  @JsonProperty("permissions")
  public String getPermissions() {
    return permissions;
  }

  @JsonProperty("volatile")
  public Boolean getVolatileBlock() {
    return volatileBlock;
  }

  @JsonIgnore
  public boolean isRead() {
    return permissions.charAt(0) == 'r';
  }

  @JsonIgnore
  public boolean isWrite() {
    return permissions.charAt(1) == 'w';
  }

  @JsonIgnore
  public boolean isExecute() {
    return permissions.charAt(2) == 'x';
  }

  @JsonIgnore
  public boolean isVolatile() {
    return Boolean.TRUE.equals(volatileBlock);
  }

  private static String formatPermissions(MemoryBlock block) {
    return (block.isRead() ? "r" : "-")
        + (block.isWrite() ? "w" : "-")
        + (block.isExecute() ? "x" : "-");
  }
}
