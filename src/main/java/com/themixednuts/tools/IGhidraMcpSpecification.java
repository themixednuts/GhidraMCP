package com.themixednuts.tools;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.framework.model.DomainObject;
import ghidra.util.Msg;
import ghidra.util.Swing;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import reactor.core.publisher.Mono;

public interface IGhidraMcpSpecification {
	static final ObjectMapper mapper = new ObjectMapper();

	/**
	 * Generates the MCP AsyncToolSpecification for this tool.
	 *
	 * @param project The current Ghidra Project context.
	 * @return An AsyncToolSpecification containing the tool's definition and
	 *         execution logic,
	 *         or null if the specification cannot be created (e.g., missing
	 *         annotation or schema error).
	 */
	AsyncToolSpecification specification(Project project);

	Optional<String> schema();

	/**
	 * Creates a base ObjectNode for a tool schema with common fields.
	 * 
	 * @return An ObjectNode with 'type' and 'id' pre-populated.
	 */
	static ObjectNode createBaseSchemaNode() {
		ObjectNode schemaRoot = JsonNodeFactory.instance.objectNode();
		schemaRoot.put("type", "object");
		schemaRoot.put("id", "urn:jsonschema:Operation");
		return schemaRoot;
	}

	default DomainFile getDomainFile(Map<String, Object> args, Project project) throws Exception {
		Object fileName = args.get("fileName");
		if (fileName == null) {
			String msg = "Called list_function_names without a valid 'fileName'. " +
					"Please provide an file name obtained from the 'list_files' tool.";

			throw new Exception(msg);
		}

		if (!(fileName instanceof String)) {
			String msg = "Called list_function_names without a valid 'fileName'. " +
					"Expected a String, got " + fileName.getClass().getName();

			throw new Exception(msg);

		}

		DomainFile domainFile = project.getOpenData().stream().filter(f -> f.getName().equals(fileName))
				.findFirst().orElse(null);
		if (domainFile == null) {
			String msg = "Invalid file name: " + fileName + ". " +
					"Please provide a valid file name obtained from the 'list_files' tool.";

			throw new Exception(msg);
		}

		return domainFile;
	}

	/**
	 * Retrieves the Program object from a DomainFile.
	 * Throws an exception if the DomainFile does not contain a Program object
	 * or if access fails.
	 *
	 * @param domainFile The DomainFile to access.
	 * @param consumer   The object requesting access (typically 'this').
	 * @return The Program object.
	 * @throws Exception If the object is not a Program or access fails.
	 */
	default Program getProgramFromDomainFile(DomainFile domainFile, Object consumer) throws Exception {
		// The 'restore' parameter is true, meaning Ghidra *should* handle
		// restoring the object state, implying we don't need explicit release here.
		DomainObject domainObj = domainFile.getDomainObject(consumer, true, false, null);

		if (domainObj instanceof Program) {
			return (Program) domainObj;
		} else {
			// If it's not a program, we should release the object we acquired.
			String actualType = (domainObj != null) ? domainObj.getClass().getName() : "null";
			if (domainObj != null) {
				domainObj.release(consumer); // Release the non-program object
			}
			throw new Exception("File '" + domainFile.getName() + "' does not contain a Program. Found: " + actualType);
		}
	}

	/**
	 * Executes a given piece of work within a Ghidra transaction on the Swing EDT.
	 * Handles starting and ending the transaction, committing on success (indicated
	 * by the returned CallToolResult) and rolling back on failure or exception.
	 * Exceptions from the work Callable are propagated (wrapped in
	 * InvocationTargetException).
	 *
	 * @param program         The program instance to operate on.
	 * @param transactionName The name for the Ghidra transaction.
	 * @param work            A Callable that performs the Ghidra operations, can
	 *                        throw
	 *                        Exception, and returns a CallToolResult. The
	 *                        success/error
	 *                        status of this result determines if the transaction is
	 *                        committed.
	 * @return The CallToolResult returned by the work Callable.
	 */
	default CallToolResult executeInTransaction(Program program, String transactionName, Callable<CallToolResult> work) {

		try {

			return Swing.runNow(() -> {
				int txId = -1;
				boolean success = false;
				CallToolResult result = null;
				try {
					txId = program.startTransaction(transactionName);

					try {
						result = work.call();
					} catch (Exception e) {
						throw new RuntimeException("Exception during Ghidra transaction work: " + transactionName, e);
					}

					if (result != null && !result.isError()) {
						success = true;
					}
					return result;
				} finally {
					if (txId != -1) {
						program.endTransaction(txId, success);
					}
				}
			});
		} catch (Exception e) {
			Msg.error(this, "Error during tool execution (executeInTransaction): " + e.getMessage(), e);
			throw new RuntimeException("Error during tool execution (executeInTransaction): " + e.getMessage(), e);
		}
	}

	/**
	 * Retrieves a required string argument from the provided map.
	 * 
	 * @param args         The map of arguments.
	 * @param argumentName The name of the argument to retrieve.
	 * @return The string value of the argument.
	 * @throws IllegalArgumentException If the argument is missing or invalid.
	 */
	default String getRequiredStringArgument(Map<String, Object> args, String argumentName)
			throws IllegalArgumentException {
		Object valueNode = args.get(argumentName);
		if (valueNode == null || !(valueNode instanceof String)) {
			throw new IllegalArgumentException(
					"Missing or invalid type for argument '" + argumentName + "'. Expected String.");
		}
		String value = (String) valueNode;
		if (value.isBlank()) {
			throw new IllegalArgumentException("Argument '" + argumentName + "' cannot be blank.");
		}
		return value;
	}

	/**
	 * Retrieves an optional string argument from the provided map.
	 * 
	 * @param args         The map of arguments.
	 * @param argumentName The name of the argument to retrieve.
	 * @return The string value of the argument, or null if the argument is missing
	 *         or invalid.
	 */
	default Optional<String> getOptionalStringArgument(Map<String, Object> args, String argumentName) {
		Object valueNode = args.get(argumentName);
		if (valueNode == null || !(valueNode instanceof String)) {
			return Optional.empty();
		}
		String value = (String) valueNode;
		if (value.isBlank()) {
			return Optional.empty();
		}
		return Optional.of(value);
	}

	/**
	 * Retrieves an optional integer argument from the provided map.
	 * 
	 * @param args         The map of arguments.
	 * @param argumentName The name of the argument to retrieve.
	 * @return An Optional containing the integer value, or empty if the argument is
	 *         missing, blank, or not a valid integer.
	 */
	default Optional<Integer> getOptionalIntArgument(Map<String, Object> args, String argumentName) {
		Object valueNode = args.get(argumentName);
		if (valueNode == null) {
			return Optional.empty();
		}
		// Handle both Number types (like Integer, Long from JSON) and String types
		if (valueNode instanceof Number) {
			return Optional.of(((Number) valueNode).intValue());
		} else if (valueNode instanceof String) {
			String value = (String) valueNode;
			if (value.isBlank()) {
				return Optional.empty();
			}
			try {
				return Optional.of(Integer.parseInt(value));
			} catch (NumberFormatException e) {
				return Optional.empty(); // Not a valid integer string
			}
		} else {
			return Optional.empty(); // Invalid type
		}
	}

	default Mono<Program> getProgram(Map<String, Object> args, Project project) {
		return Mono.fromCallable(() -> {
			DomainFile domainFile = getDomainFile(args, project);
			return getProgramFromDomainFile(domainFile, this);
		});
	}
}
