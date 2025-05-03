package com.themixednuts.tools.projectmanagement;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.ScriptArgumentInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Run Ghidra Script", mcpName = "run_ghidra_script", mcpDescription = "Runs a specified Ghidra script with given arguments.", category = ToolCategory.PROJECT_MANAGEMENT, description = "Runs a Ghidra script.")
public class GhidraRunScriptTool implements IGhidraMcpSpecification {

	private static final String ARG_SCRIPT_NAME = "scriptName";
	private static final String ARG_SCRIPT_ARGS = "scriptArguments"; // JSON object/map

	private static final Pattern ARG_PATTERN = Pattern.compile("@arg\\s+([^\\s]+)\\s+([^\\s]+)(?:\\s+\"(.*?)\")?");

	// --- Data Structures ---

	// --- Schema Definition ---

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The program context in which the script should run."));
		schemaRoot.property(ARG_SCRIPT_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the script to run (e.g., 'MyScript.java')."));

		// Define schema for the input argument object using the unified model structure
		IObjectSchemaBuilder argInfoSchema = JsonSchemaBuilder.object(mapper)
				.property("order", JsonSchemaBuilder.integer(mapper).description("The 0-based order of the argument."))
				.property("type", JsonSchemaBuilder.string(mapper).description("Expected argument type (informational)."))
				.property("name", JsonSchemaBuilder.string(mapper).description("Argument name (informational)."))
				.property("description", JsonSchemaBuilder.string(mapper).description("Argument description (informational)."))
				.property("value", JsonSchemaBuilder.object(mapper).description("The value to pass for this argument."))
				.requiredProperty("order")
				.requiredProperty("value");

		schemaRoot.property(ARG_SCRIPT_ARGS,
				JsonSchemaBuilder.array(mapper)
						.description(
								"Optional: An ordered list of arguments (including value) to pass to the script.")
						.items(argInfoSchema));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_SCRIPT_NAME);

		return schemaRoot.build();
	}

	// --- Tool Execution ---

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					try {
						GhidraState ghidraState = createState(tool, program);
						if (ghidraState == null) {
							return createErrorResult("Could not create valid GhidraState.");
						}

						final String scriptName = getRequiredStringArgument(args, ARG_SCRIPT_NAME);
						ResourceFile scriptFile = GhidraScriptUtil.findScriptByName(scriptName);
						if (scriptFile == null) {
							return createErrorResult("Script not found: " + scriptName);
						}

						// Argument Processing
						List<ScriptArgumentInfo.ScriptArgument> expectedArgsMetadata = parseScriptArguments(scriptFile);
						final int expectedArgCount = expectedArgsMetadata.size();
						List<ScriptArgumentInfo.ScriptArgument> providedArgs = getOptionalListOfScriptArgs(args,
								ARG_SCRIPT_ARGS)
								.orElse(new ArrayList<>());
						if (providedArgs.size() != expectedArgCount) {
							return createErrorResult("Argument count mismatch for script '" + scriptName + ". Expected " +
									expectedArgCount + ", but received " + providedArgs.size() + ".");
						}
						String[] scriptArgsArray = buildStringArrayFromProvidedArgs(providedArgs);

						// Setup Monitor and Writer
						GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, scriptName);
						StringWriter stringWriter = new StringWriter();
						PrintWriter printWriter = new PrintWriter(stringWriter);

						// Get Provider and Script Instance
						Msg.info(this, "Attempting to run script via instance: " + scriptName + "...");
						GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
						if (provider == null) {
							return createErrorResult("Could not find script provider for: " + scriptName);
						}
						GhidraScript scriptInstance = provider.getScriptInstance(scriptFile, printWriter);
						if (scriptInstance == null) {
							return createErrorResult("Could not get script instance for: " + scriptName);
						}

						// --- Execute Script Instance ---
						scriptInstance.setScriptArgs(scriptArgsArray);
						scriptInstance.execute(ghidraState, monitor, printWriter);

						// Post-Execution Checks
						if (monitor.isCancelled()) {
							return createErrorResult("Script execution cancelled: " + scriptName);
						}

						Msg.info(this, "Script execution completed: " + scriptName);
						String capturedOutput = stringWriter.toString();
						return createSuccessResult(Map.of(
								"message", "Script '%s' executed successfully.".formatted(scriptName),
								"output", capturedOutput));

					} catch (Throwable setupError) {
						return createErrorResult(setupError);
					}
				})
				.onErrorResume(e -> createErrorResult(e));
	}

	// --- Helper Logic ---

	// Update Helper to get and convert the list argument to List<ScriptArgument>
	private Optional<List<ScriptArgumentInfo.ScriptArgument>> getOptionalListOfScriptArgs(Map<String, Object> args,
			String argumentName) {
		Object value = args.get(argumentName);
		if (value == null || !(value instanceof List)) {
			return Optional.empty();
		}
		try {
			List<ScriptArgumentInfo.ScriptArgument> convertedList = mapper.convertValue(value,
					new TypeReference<List<ScriptArgumentInfo.ScriptArgument>>() {
					});
			return Optional.of(convertedList);
		} catch (IllegalArgumentException e) {
			Msg.warn(this, "Failed to convert argument list ", e);
			return Optional.empty();
		}
	}

	// Update Helper to build the String[] from List<ScriptArgument>
	private String[] buildStringArrayFromProvidedArgs(List<ScriptArgumentInfo.ScriptArgument> providedArgs) {
		if (providedArgs == null || providedArgs.isEmpty()) {
			return new String[0];
		}
		providedArgs.sort(Comparator.comparingInt(ScriptArgumentInfo.ScriptArgument::order));

		String[] scriptArgsArray = new String[providedArgs.size()];
		for (int i = 0; i < providedArgs.size(); i++) {
			ScriptArgumentInfo.ScriptArgument arg = providedArgs.get(i);
			scriptArgsArray[i] = convertArgumentToString(arg.value());
		}
		return scriptArgsArray;
	}

	// Attempt to create GhidraState. May need refinement based on actual API.
	private GhidraState createState(PluginTool tool, Program program) {
		try {
			// Use the constructor that seems most appropriate, providing basic context.
			// Nulls are for currentLocation, currentSelection, currentHighlight.
			return new GhidraState(tool, tool.getProject(), program, null, null, null);
		} catch (Exception e) {
			Msg.error(this, "Failed to create GhidraState", e);
			return null;
		}
	}

	// Update parseScriptArguments to return List<ScriptArgument>
	private List<ScriptArgumentInfo.ScriptArgument> parseScriptArguments(ResourceFile scriptFile) {
		List<ScriptArgumentInfo.ScriptArgument> arguments = new ArrayList<>();
		int argOrder = 0;
		try (BufferedReader reader = Files.newBufferedReader(Path.of(scriptFile.getAbsolutePath()),
				StandardCharsets.UTF_8)) {
			String line;
			while ((line = reader.readLine()) != null) {
				line = line.trim();
				Matcher argMatcher = ARG_PATTERN.matcher(line);
				if (argMatcher.find()) {
					String type = argMatcher.group(1);
					String name = argMatcher.group(2);
					String argDesc = argMatcher.group(3) != null ? argMatcher.group(3) : "";
					arguments.add(new ScriptArgumentInfo.ScriptArgument(argOrder++, type, name, argDesc, null));
					continue;
				}
				if (line.startsWith("import ") || line.startsWith("public class") || line.startsWith("class ")) {
					break;
				}
			}
		} catch (IOException e) {
			Msg.warn(this, "Failed to read or parse script file for arguments: " + scriptFile.getName(), e);
		}
		return arguments;
	}

	private String convertArgumentToString(Object value) {
		if (value == null) {
			return null;
		}
		if (value instanceof String) {
			return (String) value;
		} else if (value instanceof Number || value instanceof Boolean) {
			return value.toString();
		} else if (value instanceof List || value instanceof Map) {
			try {
				return new ObjectMapper().writeValueAsString(value);
			} catch (JsonProcessingException e) {
				Msg.warn(this, "Failed to serialize complex argument to JSON: " + e.getMessage());
				return value.toString(); // Fallback
			}
		}
		return value.toString();
	}

	// --- Specification Method ---

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();
		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}
}