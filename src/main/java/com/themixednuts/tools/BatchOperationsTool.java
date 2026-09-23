package com.themixednuts.tools;

import com.themixednuts.GhidraMcpPlugin;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.BatchOperationResult;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.ui.ToolOutcome;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.*;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

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
        Run related tool operations against one file_name in a single Ghidra transaction. Each
        operations entry names a tool and supplies that tool's arguments. Operations run in order. On
        the first failure, execution stops and the transaction rolls back; the result identifies the
        failed operation. Use when several program edits must succeed together.
        """)
public class BatchOperationsTool extends BaseMcpTool {

  public static final String ARG_OPERATIONS = "operations";
  public static final String ARG_TOOL = "tool";
  public static final String ARG_ARGUMENTS = "arguments";

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
    Map<String, BaseMcpTool> availableTools = loadAvailableTools();
    ToolOptions options = tool.getOptions(GhidraMcpPlugin.OPTIONS_CATEGORY);

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
                      Map.of("operations_provided", 0, "minimum_required", 1)))
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

      BaseMcpTool toolInstance = availableTools.get(toolName);
      if (toolInstance == null) {
        GhidraMcpError error =
            GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Unknown tool: " + toolName)
                .context(
                    new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        "tool validation",
                        operation,
                        Map.of(ARG_TOOL, toolName, "operation_index", i),
                        Map.of("available_tools", availableTools.keySet())))
                .relatedResources(new ArrayList<>(availableTools.keySet()))
                .suggestions(
                    List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                            "Use a valid tool name",
                            "Available tools: " + String.join(", ", availableTools.keySet()),
                            null,
                            null)))
                .build();
        return Mono.error(new GhidraMcpException(error));
      }

      if (!isToolEnabled(toolInstance, options)) {
        GhidraMcpError error =
            GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Tool is disabled via options: " + toolName)
                .context(
                    new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        "tool enabled validation",
                        operation,
                        Map.of(ARG_TOOL, toolName, "operation_index", i),
                        Map.of("disabled_tool", toolName)))
                .suggestions(
                    List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                            "Enable the requested tool",
                            "Enable '"
                                + toolName
                                + "' from Ghidra MCP tool options or remove it from batch"
                                + " operations",
                            List.of(ARG_TOOL),
                            null)))
                .build();
        return Mono.error(new GhidraMcpException(error));
      }
    }

    return Mono.deferContextual(
        contextView ->
            getProgram(args, tool)
                .flatMap(
                    program ->
                        withTaskMonitor(
                            "batch_operations.execute",
                            monitor ->
                                executeBatchInSingleTransaction(
                                    program,
                                    context,
                                    args,
                                    operations,
                                    availableTools,
                                    tool,
                                    monitor,
                                    contextView))));
  }

  private BatchOperationResult executeBatchInSingleTransaction(
      Program program,
      McpTransportContext context,
      Map<String, Object> batchArgs,
      List<Map<String, Object>> operations,
      Map<String, BaseMcpTool> availableTools,
      PluginTool pluginTool,
      TaskMonitor monitor,
      ContextView parentContext) {
    int txId = -1;
    boolean commit = false;
    List<BatchOperationResult.IndividualOperationResult> results = new ArrayList<>();

    try {
      txId = program.startTransaction("Batch Operations");
      monitor.initialize(operations.size());

      for (int i = 0; i < operations.size(); i++) {
        Map<String, Object> operation = operations.get(i);
        String toolName = getOptionalStringArgument(operation, ARG_TOOL).orElse("");
        monitor.setMessage(
            "Running batch operation " + (i + 1) + "/" + operations.size() + ": " + toolName);
        Map<String, Object> operationArgs = getRequiredMapArgument(operation, ARG_ARGUMENTS);
        Map<String, Object> toolArgs = new HashMap<>(operationArgs);
        toolArgs.put(ARG_FILE_NAME, batchArgs.get(ARG_FILE_NAME));

        BaseMcpTool toolInstance = availableTools.get(toolName);
        if (toolInstance == null) {
          GhidraMcpError error =
              GhidraMcpError.validation()
                  .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                  .message("Unknown tool during execution: " + toolName)
                  .context(
                      new GhidraMcpError.ErrorContext(
                          getMcpName(),
                          "tool execution",
                          operation,
                          Map.of("operation_index", i, ARG_TOOL, toolName),
                          null))
                  .build();
          results.add(BatchOperationResult.IndividualOperationResult.failure(i, toolName, error));
          throw new GhidraMcpException(error);
        }

        try {
          Object result =
              toolInstance
                  .execute(context, toolArgs, pluginTool)
                  .contextWrite(ctx -> ctx.putAll(parentContext))
                  .block();
          Object responseData = result instanceof ToolOutcome<?> outcome ? outcome.data() : result;
          results.add(
              BatchOperationResult.IndividualOperationResult.success(i, toolName, responseData));
        } catch (Exception e) {
          Throwable root = unwrapExecutionException(e);
          GhidraMcpError error;
          if (root instanceof GhidraMcpException gme) {
            error = gme.getErr();
          } else {
            error =
                GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.SCRIPT_EXECUTION_FAILED)
                    .message("Operation failed: " + root.getMessage())
                    .context(
                        new GhidraMcpError.ErrorContext(
                            toolName,
                            "tool execution",
                            toolArgs,
                            Map.of("operation_index", i),
                            Map.of("exception", root.getClass().getSimpleName())))
                    .build();
          }
          results.add(BatchOperationResult.IndividualOperationResult.failure(i, toolName, error));
          throw new GhidraMcpException(error, root);
        }

        monitor.setProgress(i + 1L);
      }

      commit = true;
      return buildBatchResult(results);
    } finally {
      if (txId != -1) {
        try {
          program.endTransaction(txId, commit);
        } catch (Exception e) {
          Msg.error(this, "Failed to end batch transaction", e);
          if (commit) {
            throw new IllegalStateException("Failed to commit batch transaction", e);
          }
        }
      }
    }
  }

  private BatchOperationResult executeBatchInSingleTransaction(
      Program program,
      McpTransportContext context,
      Map<String, Object> batchArgs,
      List<Map<String, Object>> operations,
      Map<String, BaseMcpTool> availableTools,
      PluginTool pluginTool) {
    return executeBatchInSingleTransaction(
        program,
        context,
        batchArgs,
        operations,
        availableTools,
        pluginTool,
        TaskMonitor.DUMMY,
        reactor.util.context.Context.empty());
  }

  private BatchOperationResult buildBatchResult(
      List<BatchOperationResult.IndividualOperationResult> results) {
    int successCount =
        (int)
            results.stream()
                .filter(BatchOperationResult.IndividualOperationResult::isSuccess)
                .count();
    int failCount = results.size() - successCount;
    return new BatchOperationResult(successCount, failCount, results);
  }

  private Map<String, BaseMcpTool> loadAvailableTools() {
    Map<String, BaseMcpTool> tools = new HashMap<>();
    ServiceLoader.load(BaseMcpTool.class)
        .forEach(
            toolInstance -> {
              GhidraMcpTool toolAnnotation =
                  toolInstance.getClass().getAnnotation(GhidraMcpTool.class);
              if (toolAnnotation != null) {
                tools.put(toolAnnotation.mcpName(), toolInstance);
              }
            });
    return tools;
  }

  private boolean isToolEnabled(BaseMcpTool toolInstance, ToolOptions options) {
    if (options == null) {
      return true;
    }

    GhidraMcpTool toolAnnotation = toolInstance.getClass().getAnnotation(GhidraMcpTool.class);
    if (toolAnnotation == null) {
      return false;
    }

    return options.getBoolean(toolAnnotation.name(), true);
  }

  private Throwable unwrapExecutionException(Throwable throwable) {
    Throwable current = throwable;
    while (current.getCause() != null
        && current != current.getCause()
        && (current instanceof RuntimeException || current instanceof IllegalStateException)) {
      current = current.getCause();
    }
    return current;
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
