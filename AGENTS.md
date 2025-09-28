# Repository Guidelines

## Project Structure & Module Organization
Core plugin sources live in src/main/java, with domain models under com.themixednuts.models, tool implementations in com.themixednuts.tools, and shared helpers inside com.themixednuts.utils. Extension metadata lives in src/assembly/ghidra-extension.xml and src/main/resources, while tests belong in src/test/java. Keep a local lib/ directory for the required Ghidra JARs; copy them from the installation at D:\ghidra_latest or the source tree under F:\LLMDocs\ghidra-Ghidra_11.4.2_build\Ghidra. Reference SDK interfaces in F:\LLMDocs\java-sdk\io.modelcontextprotocol.sdk when updating MCP contracts.

## Build, Test & Development Commands
- mvn clean package assembly:single produces the installable ZIP in 	arget/, bundling every registered tool.
- mvn test runs the JUnit 5 suite; run it before tagging releases or submitting PRs.
- mvn -DskipTests package speeds up local iterations, but follow with mvn verify before review to ensure packaging and checks pass.

## Coding Style & Naming
Target Java 17+ with four-space indentation and K&R braces. Classes, enums, and records use UpperCamelCase; interfaces may retain the IGhidra* prefix. Methods and variables stay in lowerCamelCase, and constants use UPPER_SNAKE_CASE. Prefer immutable DTOs, annotate new tools with @GhidraMcpTool, and add concise Javadoc for public entry points or non-obvious logic.

## Testing Expectations
Create JUnit 5 tests in src/test/java, mirroring packages from the main tree. Name test classes *Test and cover tool behaviors, parameter validation, and MCP error propagation. When adjusting JSON payloads, add assertions against the helpers in com.themixednuts.utils.jsonschema to lock down schema drift. Exercise Ghidra interactions with fakes or recorded fixtures where possible.

## Commit & PR Process
Commits follow Conventional Commits (eat, ix, efactor, chore, etc.) with focused scopes, e.g., eat: add symbol search pagination. Squash WIP commits before opening a PR. Pull requests should summarize intent, list the validation performed (mvn test, manual Ghidra steps, screenshots/logs), and link issues or releases. Update CHANGELOG.md when you ship user-visible changes.

## Agent-Specific Notes
Keep the tool registry synchronized across xtension.properties, ghidra-extension.xml, and GhidraMcpTools. Verify that long-running actions respect GhidraMcpTaskMonitor and avoid hard-coded absolute paths so agents can run headless. After adding MCP surfaces, cross-check types against the SDK in F:\LLMDocs\java-sdk\io.modelcontextprotocol.sdk.