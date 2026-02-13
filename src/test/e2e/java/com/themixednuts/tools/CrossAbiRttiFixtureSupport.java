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
import java.util.Arrays;
import java.util.List;

final class CrossAbiRttiFixtureSupport {

  private static final Object BUILD_LOCK = new Object();

  private CrossAbiRttiFixtureSupport() {}

  static ItaniumFixtureArtifacts buildItaniumPeFixture(Path repoRoot) throws Exception {
    synchronized (BUILD_LOCK) {
      Path source = repoRoot.resolve("src/test/resources/fixtures/itanium_rtti_fixture.cpp");
      assertTrue(Files.exists(source), "Itanium fixture source file is missing");

      Path compiler = resolveCxxCompiler(repoRoot);
      assertTrue(compiler != null, "Could not locate g++ or clang++ for Itanium fixture build");

      Path outDir = repoRoot.resolve("target/rtti-fixture").resolve("run-" + System.nanoTime());
      Files.createDirectories(outDir);

      Path exePath = outDir.resolve("itanium_rtti_fixture.exe");
      Path mapPath = outDir.resolve("itanium_rtti_fixture.map");
      Path nmRawPath = outDir.resolve("itanium_rtti_fixture.nm.txt");
      Path nmDemangledPath = outDir.resolve("itanium_rtti_fixture.nm.demangled.txt");

      CommandResult buildResult =
          runCommand(
              List.of(
                  compiler.toString(),
                  "-std=c++17",
                  "-O0",
                  "-g",
                  "-fno-inline",
                  "-fno-omit-frame-pointer",
                  "-o",
                  exePath.toString(),
                  source.toString(),
                  "-Wl,-Map," + mapPath),
              repoRoot);
      assertEquals(
          0,
          buildResult.exitCode,
          "Itanium fixture build failed:\n" + String.join("\n", buildResult.outputLines));

      assertTrue(Files.exists(exePath), "Expected Itanium fixture executable was not created");

      Path nmTool = resolveNmTool(compiler, repoRoot);
      assertTrue(nmTool != null, "Could not locate nm tool for Itanium fixture analysis");

      CommandResult rawNm = runCommand(List.of(nmTool.toString(), "-n", exePath.toString()), repoRoot);
      assertEquals(0, rawNm.exitCode, "nm failed on Itanium fixture binary");
      Files.write(nmRawPath, rawNm.outputLines, StandardCharsets.UTF_8);

      CommandResult demangledNm =
          runCommand(List.of(nmTool.toString(), "-C", "-n", exePath.toString()), repoRoot);
      assertEquals(0, demangledNm.exitCode, "demangled nm failed on Itanium fixture binary");
      Files.write(nmDemangledPath, demangledNm.outputLines, StandardCharsets.UTF_8);

      return new ItaniumFixtureArtifacts(source, exePath, mapPath, nmRawPath, nmDemangledPath);
    }
  }

  static GoFixtureArtifacts buildGoPeFixture(Path repoRoot) throws Exception {
    synchronized (BUILD_LOCK) {
      Path source = repoRoot.resolve("src/test/resources/fixtures/go_rtti_fixture.go");
      assertTrue(Files.exists(source), "Go fixture source file is missing");

      Path goTool = resolveCommand(repoRoot, "go", "go.exe");
      assertTrue(goTool != null, "Could not locate Go toolchain for Go fixture build");

      Path outDir = repoRoot.resolve("target/rtti-fixture").resolve("run-" + System.nanoTime());
      Files.createDirectories(outDir);

      Path exePath = outDir.resolve("go_rtti_fixture.exe");
      Path nmPath = outDir.resolve("go_rtti_fixture.nm.txt");

      CommandResult buildResult =
          runCommand(
              List.of(
                  goTool.toString(),
                  "build",
                  "-gcflags=all=-N -l",
                  "-o",
                  exePath.toString(),
                  source.toString()),
              repoRoot);
      assertEquals(
          0,
          buildResult.exitCode,
          "Go fixture build failed:\n" + String.join("\n", buildResult.outputLines));

      assertTrue(Files.exists(exePath), "Expected Go fixture executable was not created");

      CommandResult nmResult = runCommand(List.of(goTool.toString(), "tool", "nm", exePath.toString()), repoRoot);
      assertEquals(0, nmResult.exitCode, "go tool nm failed on Go fixture binary");
      Files.write(nmPath, nmResult.outputLines, StandardCharsets.UTF_8);

      return new GoFixtureArtifacts(source, exePath, nmPath);
    }
  }

  static String findAddressForSymbol(Path nmOutputPath, String symbolNeedle) throws IOException {
    for (String line : Files.readAllLines(nmOutputPath, StandardCharsets.UTF_8)) {
      ParsedNmLine parsed = parseNmLine(line);
      if (parsed == null) {
        continue;
      }
      if (parsed.symbol.contains(symbolNeedle)) {
        return "0x" + parsed.address;
      }
    }
    throw new IOException("Could not find symbol containing '" + symbolNeedle + "' in " + nmOutputPath);
  }

  static String findAddressForAnySymbol(Path nmOutputPath, String... symbolNeedles) throws IOException {
    for (String needle : symbolNeedles) {
      try {
        return findAddressForSymbol(nmOutputPath, needle);
      } catch (IOException ignored) {
        // try next candidate
      }
    }
    throw new IOException(
        "Could not find any candidate symbol in "
            + nmOutputPath
            + ": "
            + Arrays.toString(symbolNeedles));
  }

  static boolean hasToolchainForItanium(Path repoRoot) {
    return resolveCxxCompiler(repoRoot) != null;
  }

  static boolean hasToolchainForGo(Path repoRoot) {
    return resolveCommand(repoRoot, "go", "go.exe") != null;
  }

  private static Path resolveCxxCompiler(Path repoRoot) {
    String override = System.getProperty("itanium.cxx.path", "").trim();
    if (!override.isEmpty()) {
      Path path = Path.of(override);
      return Files.exists(path) ? path : null;
    }

    Path gpp = resolveCommand(repoRoot, "g++", "g++.exe");
    if (gpp != null) {
      return gpp;
    }
    return resolveCommand(repoRoot, "clang++", "clang++.exe");
  }

  private static Path resolveNmTool(Path compiler, Path repoRoot) {
    String override = System.getProperty("itanium.nm.path", "").trim();
    if (!override.isEmpty()) {
      Path path = Path.of(override);
      return Files.exists(path) ? path : null;
    }

    try {
      CommandResult result =
          runCommand(List.of(compiler.toString(), "-print-prog-name=nm"), repoRoot);
      if (result.exitCode == 0 && !result.outputLines.isEmpty()) {
        String candidate = result.outputLines.get(0).trim();
        if (!candidate.isEmpty()) {
          Path candidatePath = Path.of(candidate);
          if (Files.exists(candidatePath)) {
            return candidatePath;
          }

          Path resolved = resolveCommand(repoRoot, candidate, candidate + ".exe");
          if (resolved != null) {
            return resolved;
          }
        }
      }
    } catch (Exception ignored) {
      // fallback below
    }

    Path nm = resolveCommand(repoRoot, "nm", "nm.exe");
    if (nm != null) {
      return nm;
    }
    return resolveCommand(repoRoot, "llvm-nm", "llvm-nm.exe");
  }

  private static Path resolveCommand(Path workingDirectory, String... commandNames) {
    for (String commandName : commandNames) {
      try {
        CommandResult result = runCommand(List.of(commandName, "--version"), workingDirectory);
        if (result.exitCode == 0) {
          return Path.of(commandName);
        }
      } catch (Exception ignored) {
        // try next
      }
    }
    return null;
  }

  private static ParsedNmLine parseNmLine(String line) {
    if (line == null || line.isBlank()) {
      return null;
    }

    String[] tokens = line.trim().split("\\s+", 3);
    if (tokens.length < 3) {
      return null;
    }

    String address = tokens[0];
    if (!address.matches("[0-9A-Fa-f]+")) {
      return null;
    }

    return new ParsedNmLine(address, tokens[2]);
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

  record ItaniumFixtureArtifacts(
      Path sourcePath, Path exePath, Path mapPath, Path nmRawPath, Path nmDemangledPath) {}

  record GoFixtureArtifacts(Path sourcePath, Path exePath, Path nmPath) {}

  private record ParsedNmLine(String address, String symbol) {}

  private record CommandResult(int exitCode, List<String> outputLines) {}
}
