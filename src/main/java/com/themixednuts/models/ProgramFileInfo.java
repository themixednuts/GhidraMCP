package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents information about a program file in a Ghidra project, including both open and closed
 * programs.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProgramFileInfo {

  private final String name;
  private final String path;
  private final int version;
  private final boolean isOpen;
  private final boolean changed;
  private final boolean readOnly;
  private final String architecture;
  private final String imageBase;
  private final Long size;
  private final String format;

  public ProgramFileInfo(
      String name,
      String path,
      int version,
      boolean open,
      boolean changed,
      boolean readOnly,
      String architecture,
      String imageBase,
      Long size,
      String format) {
    this.name = name;
    this.path = path;
    this.version = version;
    this.isOpen = open;
    this.changed = changed;
    this.readOnly = readOnly;
    this.architecture = architecture;
    this.imageBase = imageBase;
    this.size = size;
    this.format = format;
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("path")
  public String getPath() {
    return path;
  }

  @JsonProperty("version")
  public int getVersion() {
    return version;
  }

  @JsonProperty("is_open")
  public boolean isOpen() {
    return isOpen;
  }

  @JsonProperty("changed")
  public boolean isChanged() {
    return changed;
  }

  @JsonProperty("read_only")
  public boolean isReadOnly() {
    return readOnly;
  }

  @JsonProperty("architecture")
  public String getArchitecture() {
    return architecture;
  }

  @JsonProperty("image_base")
  public String getImageBase() {
    return imageBase;
  }

  @JsonProperty("size")
  public Long getSize() {
    return size;
  }

  @JsonProperty("format")
  public String getFormat() {
    return format;
  }
}
