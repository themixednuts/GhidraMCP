package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

final class RttiFixtureSupport {

  private static final Object MSVC_BUILD_LOCK = new Object();

  private RttiFixtureSupport() {}

  static FixtureArtifacts buildMsvcX64Fixture(Path repoRoot) throws Exception {
    synchronized (MSVC_BUILD_LOCK) {
      Path fixtureSource = repoRoot.resolve("src/test/resources/fixtures/msvc_rtti_fixture.cpp");
      assertTrue(Files.exists(fixtureSource), "Fixture source file is missing");

      Path vsDevCmd = resolveVsDevCmdPath();
      assertTrue(Files.exists(vsDevCmd), "Could not locate VsDevCmd.bat for MSVC x64 build");

      Path outDir = repoRoot.resolve("target/rtti-fixture").resolve("run-" + System.nanoTime());
      Files.createDirectories(outDir);

      Path exePath = outDir.resolve("msvc_rtti_fixture.exe");
      Path pdbPath = outDir.resolve("msvc_rtti_fixture.pdb");
      Path compilePdbPath = outDir.resolve("msvc_rtti_fixture_compile.pdb");
      Path objectPath = outDir.resolve("msvc_rtti_fixture.obj");
      Path mapPath = outDir.resolve("msvc_rtti_fixture.map");

      String command =
          String.format(
              "call \"%s\" -arch=amd64 && cl /nologo /EHsc /GR /std:c++17 /Od /Zi /FS /Fd:\"%s\" /Fo:\"%s\" \"%s\" /link /OUT:\"%s\" /PDB:\"%s\" /MAP:\"%s\"",
              vsDevCmd,
              compilePdbPath,
              objectPath,
              fixtureSource,
              exePath,
              pdbPath,
              mapPath);

      CommandResult buildResult = runCommand(List.of("cmd.exe", "/c", command), repoRoot);
      assertEquals(
          0,
          buildResult.exitCode,
          "MSVC x64 fixture build failed:\n" + String.join("\n", buildResult.outputLines));

      assertTrue(Files.exists(exePath), "Expected fixture executable was not created");
      assertTrue(Files.exists(mapPath), "Expected linker MAP file was not created");

      return new FixtureArtifacts(fixtureSource, exePath, pdbPath, mapPath);
    }
  }

  static String findAddressForSymbol(Path mapPath, String symbol, String objectFilter)
      throws IOException {
    String targetObject = objectFilter == null ? "" : objectFilter;
    try (BufferedReader reader = Files.newBufferedReader(mapPath, StandardCharsets.UTF_8)) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (!line.contains(symbol)) {
          continue;
        }
        if (!targetObject.isEmpty() && !line.contains(targetObject)) {
          continue;
        }

        String[] tokens = line.trim().split("\\s+");
        if (tokens.length < 3) {
          continue;
        }

        for (String token : tokens) {
          if (token.matches("[0-9A-Fa-f]{16}")) {
            return "0x" + token;
          }
        }
      }
    }

    throw new IOException("Could not find symbol in map: " + symbol);
  }

  static boolean isWindows() {
    return System.getProperty("os.name", "").toLowerCase().contains("win");
  }

  private static Path resolveVsDevCmdPath() {
    String override = System.getProperty("msvc.vsdevcmd.path", "").trim();
    if (!override.isEmpty()) {
      return Path.of(override);
    }

    return Path.of(
        "C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/Tools/VsDevCmd.bat");
  }

  private static CommandResult runCommand(List<String> command, Path workingDirectory)
      throws IOException, InterruptedException {
    ProcessBuilder builder = new ProcessBuilder(command);
    builder.directory(workingDirectory.toFile());
    builder.redirectErrorStream(true);

    Process process = builder.start();
    List<String> output = new ArrayList<>();

    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        output.add(line);
      }
    }

    int exitCode = process.waitFor();
    return new CommandResult(exitCode, output);
  }

  record FixtureArtifacts(Path sourcePath, Path exePath, Path pdbPath, Path mapPath) {}

  private record CommandResult(int exitCode, List<String> outputLines) {}
}
