package com.themixednuts.utils;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Utility class for accessing Ghidra state (projects, programs, files). Consolidates common
 * operations used across tools, resources, prompts, and completions.
 */
public final class GhidraStateUtils {

  private GhidraStateUtils() {
    // Prevent instantiation
  }

  /**
   * Gets the currently active Ghidra project.
   *
   * @return The active project
   * @throws GhidraMcpException If no project is open
   */
  public static Project getActiveProject() throws GhidraMcpException {
    Project project = AppInfo.getActiveProject();
    if (project == null) {
      throw new GhidraMcpException(
          GhidraMcpError.permissionState()
              .errorCode(GhidraMcpError.ErrorCode.PROGRAM_NOT_OPEN)
              .message("No active project found")
              .build());
    }
    return project;
  }

  /**
   * Finds a DomainFile by name, searching both open files and the entire project.
   *
   * @param fileName The name of the file to find
   * @return The DomainFile
   * @throws GhidraMcpException If the file is not found
   */
  public static DomainFile findDomainFile(String fileName) throws GhidraMcpException {
    Project project = getActiveProject();

    // Check open files first (fast path)
    Optional<DomainFile> openFile =
        project.getOpenData().stream().filter(f -> f.getName().equals(fileName)).findFirst();

    if (openFile.isPresent()) {
      return openFile.get();
    }

    // Search the entire project recursively
    List<DomainFile> allFiles = new ArrayList<>();
    collectFilesRecursive(project.getProjectData().getRootFolder(), allFiles);

    return allFiles.stream()
        .filter(f -> f.getName().equals(fileName))
        .findFirst()
        .orElseThrow(() -> createFileNotFoundError(project, fileName));
  }

  /**
   * Gets a Program from a DomainFile.
   *
   * @param domainFile The DomainFile to open
   * @param consumer The object that will use the program (for tracking)
   * @return The Program
   * @throws GhidraMcpException If the file doesn't contain a Program or can't be opened
   */
  public static Program getProgramFromFile(DomainFile domainFile, Object consumer)
      throws GhidraMcpException {
    try {
      DomainObject obj = domainFile.getDomainObject(consumer, true, false, null);
      if (obj instanceof Program) {
        return (Program) obj;
      }
      String actualType = obj != null ? obj.getClass().getSimpleName() : "null";
      if (obj != null) {
        obj.release(consumer);
      }
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message("File '" + domainFile.getName() + "' is not a Program. Found: " + actualType)
              .build());
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpErrorUtils.unexpectedError("GhidraStateUtils", "getProgramFromFile", e));
    }
  }

  /**
   * Gets a Program by file name.
   *
   * @param fileName The name of the program file
   * @param consumer The object that will use the program (for tracking)
   * @return The Program
   * @throws GhidraMcpException If the program is not found or can't be opened
   */
  public static Program getProgramByName(String fileName, Object consumer)
      throws GhidraMcpException {
    DomainFile file = findDomainFile(fileName);
    return getProgramFromFile(file, consumer);
  }

  /**
   * Gets all DomainFiles in the project.
   *
   * @return List of all DomainFiles
   * @throws GhidraMcpException If no project is open
   */
  public static List<DomainFile> getAllFiles() throws GhidraMcpException {
    Project project = getActiveProject();
    List<DomainFile> files = new ArrayList<>();
    collectFilesRecursive(project.getProjectData().getRootFolder(), files);
    return files;
  }

  /**
   * Gets all file names in the project that match a prefix.
   *
   * @param prefix The prefix to match (case-insensitive)
   * @param maxResults Maximum number of results to return
   * @return List of matching file names
   * @throws GhidraMcpException If no project is open
   */
  public static List<String> getFileNames(String prefix, int maxResults) throws GhidraMcpException {
    Project project = getActiveProject();
    List<String> names = new ArrayList<>();
    String lowerPrefix = prefix != null ? prefix.toLowerCase() : "";
    collectFileNamesRecursive(
        project.getProjectData().getRootFolder(), lowerPrefix, names, maxResults);
    return names;
  }

  /** Collects all DomainFiles recursively from a folder. */
  public static void collectFilesRecursive(DomainFolder folder, List<DomainFile> files) {
    files.addAll(List.of(folder.getFiles()));
    for (DomainFolder subfolder : folder.getFolders()) {
      collectFilesRecursive(subfolder, files);
    }
  }

  private static void collectFileNamesRecursive(
      DomainFolder folder, String prefix, List<String> names, int maxResults) {
    for (DomainFile file : folder.getFiles()) {
      if (names.size() >= maxResults) {
        return;
      }
      String name = file.getName();
      if (prefix.isEmpty()
          || name.toLowerCase().startsWith(prefix)
          || name.toLowerCase().contains(prefix)) {
        names.add(name);
      }
    }
    for (DomainFolder subfolder : folder.getFolders()) {
      if (names.size() >= maxResults) {
        return;
      }
      collectFileNamesRecursive(subfolder, prefix, names, maxResults);
    }
  }

  private static GhidraMcpException createFileNotFoundError(Project project, String fileName) {
    List<String> openFiles =
        project.getOpenData().stream()
            .map(DomainFile::getName)
            .sorted()
            .collect(Collectors.toList());

    return new GhidraMcpException(
        GhidraMcpErrorUtils.fileNotFound(fileName, openFiles, "GhidraStateUtils"));
  }
}
