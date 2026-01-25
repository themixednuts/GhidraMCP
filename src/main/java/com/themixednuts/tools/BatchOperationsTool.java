package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.BatchOperationResult;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.*;
import reactor.core.publisher.Mono;

/**
 * Batch operations tool that executes multiple tool calls in sequence within a single transaction.
 * If any operation fails, the entire transaction is rolled back and the error is bubbled up.
 */
@GhidraMcpTool(
    name = "Batch Operations",
    description =
        "Execute multiple tool operations in a single transaction. All operations succeed or all"
            + " are reverted.",
    mcpName = "batch_operations",
    mcpDescription =
        """
        <use_case>
        Executes multiple Ghidra tool operations in sequence within a single transaction.
        Useful for bulk operations like defining multiple symbols, creating multiple data types,
        or performing complex multi-step modifications. All operations are executed in order,
        and if any operation fails, the entire transaction is rolled back.
        </use_case>

        <important_notes>
        - All operations are executed within a single database transaction
        - Operations are executed in the order provided
        - If ANY operation fails, ALL changes are reverted (transaction rollback)
        - The failing operation's error details are included in the response
        - Each operation must specify a valid tool mcpName and its required arguments
        - The 'fileName' argument is required at the batch level and applies to all operations
        </important_notes>

        <parameters_summary>
        - 'fileName': The program file to operate on (required, applies to all operations)
        - 'operations': Array of operations to execute (required), each containing:
          - 'tool': The mcpName of the tool to execute (e.g., "manage_symbols", "manage_data_types")
          - 'arguments': Map of arguments to pass to the tool (each tool has its own schema)
        </parameters_summary>

        <workflow>
        1. Validates that all specified tools exist and are available
        2. Opens the specified program
        3. Starts a single transaction
        4. Executes each operation in sequence:
           a. Loads the tool instance
           b. Executes the tool with provided arguments
           c. Collects the result
        5. If any operation fails:
           a. Transaction is automatically rolled back
           b. Returns error details from the failed operation
           c. No subsequent operations are executed
        6. If all operations succeed:
           a. Transaction is committed
           b. Returns all operation results
        </workflow>

        <return_value_summary>
        Returns a BatchOperationResult containing:
        - 'success': Whether all operations succeeded
        - 'total_operations': Total number of operations requested
        - 'successful_operations': Number of operations that succeeded before any failure
        - 'failed_operations': Number of operations that failed (0 or 1)
        - 'operations': Array of individual operation results, each containing:
          - 'operation_index': Index of the operation (0-based)
          - 'tool_name': Name of the tool executed
          - 'success': Whether this specific operation succeeded
          - 'result': The tool's result object (if successful)
          - 'error': Structured error details (if failed)
        - 'message': Summary message
        </return_value_summary>

        <agent_response_guidance>
        After execution, inform the user about:
        - The number of operations that were executed
        - Whether all operations succeeded or which operation failed
        - Key changes made (summarize, don't dump all details)
        - If a failure occurred, explain which operation failed and why

        Example success response:
        "I executed 5 operations in a single transaction: created 3 symbols, defined 1 struct, and set 1 comment.
        All operations completed successfully."

        Example failure response:
        "I attempted to execute 5 operations, but operation #3 (manage_data_types) failed because the struct 'MyStruct'
        already exists. All changes have been rolled back. Would you like me to retry with different parameters?"

        MUST NOT simply dump the raw JSON response to the user.
        </agent_response_guidance>

        <examples>
        Create multiple symbols at once:
        {
          "file_name": "program.exe",
          "operations": [
            {
              "tool": "manage_symbols",
              "arguments": {
                "action": "create",
                "name": "g_config",
                "address": "0x401000",
                "symbol_type": "label"
              }
            },
            {
              "tool": "manage_symbols",
              "arguments": {
                "action": "create",
                "name": "g_buffer",
                "address": "0x401010",
                "symbol_type": "label"
              }
            }
          ]
        }

        Define a struct and apply it to memory:
        {
          "file_name": "program.exe",
          "operations": [
            {
              "tool": "manage_data_types",
              "arguments": {
                "action": "create",
                "data_type_kind": "struct",
                "name": "Config",
                "members": [
                  {"name": "version", "data_type_path": "int"},
                  {"name": "flags", "data_type_path": "int"}
                ]
              }
            },
            {
              "tool": "manage_memory",
              "arguments": {
                "action": "apply_data_type",
                "address": "0x401000",
                "data_type_path": "/Config"
              }
            }
          ]
        }
        </examples>

        <error_handling_summary>
        - Throws VALIDATION error if 'operations' array is empty or missing
        - Throws VALIDATION error if a specified tool mcpName is not found
        - Throws VALIDATION error if operation arguments are missing required fields
        - Propagates the original tool's error if an operation fails during execution
        - Transaction rollback is automatic on any failure
        </error_handling_summary>
        """)
public class BatchOperationsTool extends BaseMcpTool {

  public static final String ARG_OPERATIONS = "operations";
  public static final String ARG_TOOL = "tool";
  public static final String ARG_ARGUMENTS = "arguments";

  private static final Map<String, BaseMcpTool> toolCache = new HashMap<>();

  static {
    ServiceLoader.load(BaseMcpTool.class)
        .forEach(
            toolInstance -> {
              GhidraMcpTool annotation = toolInstance.getClass().getAnnotation(GhidraMcpTool.class);
              if (annotation != null) {
                toolCache.put(annotation.mcpName(), toolInstance);
              }
            });
    Msg.info(
        BatchOperationsTool.class, "Loaded " + toolCache.size() + " tools for batch operations");
  }

  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME,
        SchemaBuilder.string(mapper).description("The name of the program file to operate on."));

    schemaRoot.property(
        ARG_OPERATIONS,
        SchemaBuilder.array(mapper)
            .items(
                SchemaBuilder.object(mapper)
                    .property(
                        ARG_TOOL,
                        SchemaBuilder.string(mapper)
                            .description("The mcpName of the tool to execute"))
                    .property(
                        ARG_ARGUMENTS,
                        SchemaBuilder.object(mapper).description("Arguments to pass to the tool"))
                    .requiredProperty(ARG_TOOL)
                    .requiredProperty(ARG_ARGUMENTS))
            .description("Array of operations to execute in order"));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_OPERATIONS);

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

    List<Map<String, Object>> operations = getRequiredArrayArgument(args, ARG_OPERATIONS);

    if (operations.isEmpty()) {
      GhidraMcpError error =
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
              .message("At least one operation must be provided")
              .context(
                  new GhidraMcpError.ErrorContext(
                      annotation.mcpName(),
                      "operations validation",
                      args,
                      Map.of(ARG_OPERATIONS, operations),
                      Map.of("operationsProvided", 0, "minimumRequired", 1)))
              .suggestions(
                  List.of(
                      new GhidraMcpError.ErrorSuggestion(
                          GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                          "Provide at least one operation",
                          "Include at least one operation in the 'operations' array",
                          List.of(ARG_OPERATIONS),
                          null)))
              .build();
      return Mono.error(new GhidraMcpException(error));
    }

    for (int i = 0; i < operations.size(); i++) {
      Map<String, Object> operation = operations.get(i);
      String toolName;
      try {
        toolName = getRequiredStringArgument(operation, ARG_TOOL);
      } catch (GhidraMcpException e) {
        return Mono.error(e);
      }

      if (!toolCache.containsKey(toolName)) {
        GhidraMcpError error =
            GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Unknown tool: " + toolName)
                .context(
                    new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        "tool validation",
                        operation,
                        Map.of(ARG_TOOL, toolName, "operationIndex", i),
                        Map.of("availableTools", toolCache.keySet())))
                .relatedResources(new ArrayList<>(toolCache.keySet()))
                .suggestions(
                    List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                            "Use a valid tool name",
                            "Available tools: " + String.join(", ", toolCache.keySet()),
                            null,
                            null)))
                .build();
        return Mono.error(new GhidraMcpException(error));
      }
    }

    return getProgram(args, tool)
        .flatMap(
            program ->
                executeInTransaction(
                    program,
                    "Batch Operations",
                    () -> {
                      List<BatchOperationResult.IndividualOperationResult> results =
                          new ArrayList<>();

                      for (int i = 0; i < operations.size(); i++) {
                        Map<String, Object> operation = operations.get(i);
                        String toolName = getOptionalStringArgument(operation, ARG_TOOL).orElse("");
                        Map<String, Object> toolArgs =
                            getRequiredMapArgument(operation, ARG_ARGUMENTS);

                        toolArgs.put(ARG_FILE_NAME, args.get(ARG_FILE_NAME));

                        BaseMcpTool toolInstance = toolCache.get(toolName);

                        try {
                          Object result = toolInstance.execute(context, toolArgs, tool).block();
                          results.add(
                              BatchOperationResult.IndividualOperationResult.success(
                                  i, toolName, result));
                        } catch (Exception e) {
                          GhidraMcpError error;
                          if (e instanceof GhidraMcpException) {
                            error = ((GhidraMcpException) e).getErr();
                          } else {
                            error =
                                GhidraMcpError.execution()
                                    .errorCode(GhidraMcpError.ErrorCode.SCRIPT_EXECUTION_FAILED)
                                    .message("Operation failed: " + e.getMessage())
                                    .context(
                                        new GhidraMcpError.ErrorContext(
                                            toolName,
                                            "tool execution",
                                            toolArgs,
                                            Map.of("operationIndex", i),
                                            Map.of("exception", e.getClass().getSimpleName())))
                                    .build();
                          }
                          results.add(
                              BatchOperationResult.IndividualOperationResult.failure(
                                  i, toolName, error));
                          throw new GhidraMcpException(error);
                        }
                      }

                      int successCount =
                          (int)
                              results.stream()
                                  .filter(BatchOperationResult.IndividualOperationResult::isSuccess)
                                  .count();
                      int failCount = results.size() - successCount;

                      return new BatchOperationResult(
                          failCount == 0,
                          results.size(),
                          successCount,
                          failCount,
                          results,
                          failCount == 0
                              ? "All " + results.size() + " operations completed successfully"
                              : "Batch operation failed at operation "
                                  + results.stream()
                                      .filter(r -> !r.isSuccess())
                                      .findFirst()
                                      .map(
                                          BatchOperationResult.IndividualOperationResult
                                              ::getOperationIndex)
                                      .orElse(-1));
                    }));
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> getRequiredArrayArgument(Map<String, Object> args, String key) {
    Object value = args.get(key);
    if (value == null) {
      throw new IllegalArgumentException("Required argument '" + key + "' is missing");
    }
    if (!(value instanceof List)) {
      throw new IllegalArgumentException("Argument '" + key + "' must be an array");
    }
    return (List<Map<String, Object>>) value;
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> getRequiredMapArgument(Map<String, Object> args, String key) {
    Object value = args.get(key);
    if (value == null) {
      throw new IllegalArgumentException("Required argument '" + key + "' is missing");
    }
    if (!(value instanceof Map)) {
      throw new IllegalArgumentException("Argument '" + key + "' must be an object");
    }
    return (Map<String, Object>) value;
  }
}
