package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Represents information about a program file in a Ghidra project, including both open and closed
 * programs.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProgramFileInfo {

  private final String name;
  private final String path;
  private final String programId;
  private final int version;
  private final boolean isOpen;
  private final boolean isChanged;
  private final boolean isReadOnly;
  private final String architecture;
  private final String imageBase;
  private final Long programSize;
  private final String executableFormat;

  public ProgramFileInfo(
      String name,
      String path,
      String programId,
      int version,
      boolean isOpen,
      boolean isChanged,
      boolean isReadOnly,
      String architecture,
      String imageBase,
      Long programSize,
      String executableFormat) {
    this.name = name;
    this.path = path;
    this.programId = programId;
    this.version = version;
    this.isOpen = isOpen;
    this.isChanged = isChanged;
    this.isReadOnly = isReadOnly;
    this.architecture = architecture;
    this.imageBase = imageBase;
    this.programSize = programSize;
    this.executableFormat = executableFormat;
  }

  public String getName() {
    return name;
  }

  public String getPath() {
    return path;
  }

  public String getProgramId() {
    return programId;
  }

  public int getVersion() {
    return version;
  }

  public boolean isOpen() {
    return isOpen;
  }

  public boolean isChanged() {
    return isChanged;
  }

  public boolean isReadOnly() {
    return isReadOnly;
  }

  public String getArchitecture() {
    return architecture;
  }

  public String getImageBase() {
    return imageBase;
  }

  public Long getProgramSize() {
    return programSize;
  }

  public String getExecutableFormat() {
    return executableFormat;
  }
}
