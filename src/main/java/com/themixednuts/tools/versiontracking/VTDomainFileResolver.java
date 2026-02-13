package com.themixednuts.tools.versiontracking;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Resolves VT-related domain files by unique name or explicit project path. */
final class VTDomainFileResolver {

  private static final int AMBIGUOUS_PATH_HINT_LIMIT = 5;

  static final class FileDescriptor {
    final String name;
    final String pathname;
    final String contentType;

    FileDescriptor(String name, String pathname, String contentType) {
      this.name = name;
      this.pathname = pathname;
      this.contentType = contentType;
    }
  }

  private VTDomainFileResolver() {}

  static DomainFile resolveSessionFile(Project project, String sessionIdentifier, String argumentName)
      throws GhidraMcpException {
    return resolveUniqueDomainFile(
        project,
        sessionIdentifier,
        argumentName,
        "VT session",
        "VersionTracking",
        "Provide the full session path (for example, /Folder/Session.vt). Use list_programs to"
            + " inspect available project paths.");
  }

  static DomainFile resolveProgramFile(Project project, String programIdentifier, String argumentName)
      throws GhidraMcpException {
    return resolveUniqueDomainFile(
        project,
        programIdentifier,
        argumentName,
        "program",
        "Program",
        "Provide the full program path (for example, /Folder/program.exe). Use list_programs to"
            + " inspect available project paths.");
  }

  private static DomainFile resolveUniqueDomainFile(
      Project project,
      String identifier,
      String argumentName,
      String objectName,
      String expectedContentType,
      String ambiguityHint)
      throws GhidraMcpException {
    List<DomainFile> allFiles = new ArrayList<>();
    collectFilesRecursive(project.getProjectData().getRootFolder(), allFiles);

    List<FileDescriptor> fileDescriptors =
        allFiles.stream()
            .map(file -> new FileDescriptor(file.getName(), file.getPathname(), file.getContentType()))
            .toList();

    String selectedPath =
        selectUniquePath(
            fileDescriptors,
            identifier,
            argumentName,
            objectName,
            expectedContentType,
            ambiguityHint);

    return allFiles.stream()
        .filter(file -> pathEquals(file.getPathname(), selectedPath))
        .findFirst()
        .orElseThrow(
            () ->
                new GhidraMcpException(
                    GhidraMcpError.internal(
                        "resolved path not found in domain files: " + selectedPath)));
  }

  static String selectUniquePath(
      List<FileDescriptor> files,
      String identifier,
      String argumentName,
      String objectName,
      String expectedContentType,
      String ambiguityHint)
      throws GhidraMcpException {
    Objects.requireNonNull(files, "files");

    String trimmedIdentifier = identifier == null ? "" : identifier.trim();
    boolean pathLike = isPathLike(trimmedIdentifier);
    String normalizedIdentifierPath = normalizePath(trimmedIdentifier);

    List<FileDescriptor> matches = new ArrayList<>();
    for (FileDescriptor file : files) {
      if (!matchesExpectedContentType(file, expectedContentType)) {
        continue;
      }

      if (pathLike) {
        if (pathEquals(file.pathname, normalizedIdentifierPath)) {
          matches.add(file);
        }
      } else if (file.name.equals(trimmedIdentifier)) {
        matches.add(file);
      }
    }

    if (matches.isEmpty()) {
      throw new GhidraMcpException(
          GhidraMcpError.notFound(
              objectName,
              trimmedIdentifier,
              pathLike
                  ? "No file exists at that project path. Use list_programs to inspect valid paths."
                  : null));
    }

    if (matches.size() > 1) {
      List<String> samplePaths =
          matches.stream()
              .map(match -> match.pathname)
              .sorted()
              .limit(AMBIGUOUS_PATH_HINT_LIMIT)
              .toList();

      String reason =
          "matches multiple "
              + objectName
              + " files: "
              + String.join(", ", samplePaths)
              + (matches.size() > AMBIGUOUS_PATH_HINT_LIMIT ? ", ..." : "")
              + ". "
              + ambiguityHint;
      throw new GhidraMcpException(GhidraMcpError.invalid(argumentName, trimmedIdentifier, reason));
    }

    return matches.get(0).pathname;
  }

  private static boolean matchesExpectedContentType(FileDescriptor file, String expectedContentType) {
    if (expectedContentType == null || expectedContentType.isBlank()) {
      return true;
    }

    String contentType = file.contentType;
    if (contentType != null && contentType.contains(expectedContentType)) {
      return true;
    }

    return "VersionTracking".equals(expectedContentType) && file.name.endsWith(".vt");
  }

  private static boolean isPathLike(String identifier) {
    return identifier.contains("/") || identifier.contains("\\");
  }

  private static boolean pathEquals(String pathname, String normalizedIdentifierPath) {
    String normalizedPath = stripLeadingSlash(normalizePath(pathname));
    String normalizedIdentifier = stripLeadingSlash(normalizePath(normalizedIdentifierPath));
    return normalizedPath.equals(normalizedIdentifier);
  }

  private static String normalizePath(String path) {
    return path == null ? "" : path.trim().replace('\\', '/');
  }

  private static String stripLeadingSlash(String value) {
    String normalized = value == null ? "" : value;
    while (normalized.startsWith("/")) {
      normalized = normalized.substring(1);
    }
    return normalized;
  }

  private static void collectFilesRecursive(DomainFolder folder, List<DomainFile> files) {
    for (DomainFile file : folder.getFiles()) {
      files.add(file);
    }
    for (DomainFolder subfolder : folder.getFolders()) {
      collectFilesRecursive(subfolder, files);
    }
  }
}
