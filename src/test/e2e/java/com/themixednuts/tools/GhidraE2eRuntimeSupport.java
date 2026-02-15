package com.themixednuts.tools;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.Application;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

final class GhidraE2eRuntimeSupport {

  private GhidraE2eRuntimeSupport() {}

  static synchronized void ensureGhidraRuntimeInitialized(Path repoRoot) {
    if (Application.isInitialized()) {
      return;
    }

    File installDir = resolveInstallDir(repoRoot);
    assumeTrue(installDir != null, "Could not resolve Ghidra install dir for e2e tests");
    assumeTrue(installDir.isDirectory(), "Resolved Ghidra install dir is not a directory: " + installDir);

    try {
      System.setProperty("ghidra.external.modules", repoRoot.toAbsolutePath().toString());
      Application.initializeApplication(
          new IsolatedGhidraApplicationLayout(installDir), new ApplicationConfiguration());
    } catch (Throwable t) {
      assumeTrue(false, "Skipping: failed to initialize Ghidra runtime: " + t.getMessage());
    }
  }

  private static File resolveInstallDir(Path repoRoot) {
    String installDirProperty = System.getProperty("ghidra.install.dir", "").trim();
    if (!installDirProperty.isEmpty()) {
      return new File(installDirProperty);
    }

    try {
      Path bootstrapPropertiesPath = repoRoot.resolve("lib/.ghidra-bootstrap.properties");
      if (!Files.exists(bootstrapPropertiesPath)) {
        assumeTrue(
            false,
            "Missing lib/.ghidra-bootstrap.properties. Run bootstrap first or set -Dghidra.install.dir");
        return null;
      }

      Properties bootstrapProperties = new Properties();
      try (InputStream input = new FileInputStream(bootstrapPropertiesPath.toFile())) {
        bootstrapProperties.load(input);
      }

      String zipName = bootstrapProperties.getProperty("ghidra.bootstrap.zip", "").trim();
      if (zipName.isEmpty()) {
        assumeTrue(
            false,
            "ghidra.bootstrap.zip missing in lib/.ghidra-bootstrap.properties. Set -Dghidra.install.dir");
        return null;
      }

      Path zipPath = repoRoot.resolve(".cache").resolve(zipName);
      if (!Files.exists(zipPath)) {
        assumeTrue(
            false,
            "Bootstrap zip not found at " + zipPath + ". Run bootstrap first or set -Dghidra.install.dir");
        return null;
      }

      String extractedDirName = zipName.endsWith(".zip") ? zipName.substring(0, zipName.length() - 4) : zipName;
      Path extractedBaseDir = repoRoot.resolve(".cache").resolve(extractedDirName);
      Path installDir = findInstallDir(extractedBaseDir);
      if (installDir == null) {
        extractZip(zipPath, extractedBaseDir);
        installDir = findInstallDir(extractedBaseDir);
      }

      assumeTrue(
          installDir != null,
          "Extracted Ghidra runtime does not contain Ghidra/application.properties under "
              + extractedBaseDir
              + ". Set -Dghidra.install.dir to a valid Ghidra install root.");

      return installDir.toFile();
    } catch (Throwable t) {
      assumeTrue(false, "Failed to resolve install dir from bootstrap assets: " + t.getMessage());
      return null;
    }
  }

  private static void extractZip(Path zipPath, Path destinationDir) throws Exception {
    Files.createDirectories(destinationDir);

    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipPath.toFile()))) {
      ZipEntry entry;
      while ((entry = zis.getNextEntry()) != null) {
        if (entry.isDirectory()) {
          Path dirPath = destinationDir.resolve(entry.getName()).normalize();
          if (dirPath.startsWith(destinationDir)) {
            Files.createDirectories(dirPath);
          }
          continue;
        }

        Path outputPath = destinationDir.resolve(entry.getName()).normalize();
        if (!outputPath.startsWith(destinationDir)) {
          throw new IllegalStateException("Unexpected zip entry path traversal: " + entry.getName());
        }

        Files.createDirectories(outputPath.getParent());
        Files.copy(zis, outputPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
      }
    }
  }

  private static Path findInstallDir(Path extractedBaseDir) throws Exception {
    if (!Files.isDirectory(extractedBaseDir)) {
      return null;
    }

    Path directMarker = extractedBaseDir.resolve("Ghidra/application.properties");
    if (Files.exists(directMarker)) {
      return extractedBaseDir;
    }

    try (java.util.stream.Stream<Path> children = Files.list(extractedBaseDir)) {
      return children
          .filter(Files::isDirectory)
          .filter(child -> Files.exists(child.resolve("Ghidra/application.properties")))
          .findFirst()
          .orElse(null);
    }
  }

  private static class IsolatedGhidraApplicationLayout extends GhidraApplicationLayout {
    IsolatedGhidraApplicationLayout(File installDir) throws java.io.IOException {
      super(installDir);
    }

    @Override
    protected List<ResourceFile> findExtensionInstallationDirectories() {
      return List.of();
    }

    @Override
    protected ResourceFile findExtensionArchiveDirectory() {
      return null;
    }
  }

}
