package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Delete Function",
    description = "Delete functions by address, name, or symbol ID.",
    mcpName = "delete_function",
    title = "Delete Function",
    destructiveHint = true,
    mcpDescription =
        """
                <use_case>
                Deletes a function from the program. Essential for cleaning up incorrectly identified
                functions or removing functions that are actually data or part of other functions.
                </use_case>

                <important_notes>
                - IMPORTANT: If you plan to delete a function and then create/recreate it, use ManageFunctionsTool with 'update_prototype' action instead to preserve references
                - Supports multiple function identification methods (name, address, symbol ID, regex)
                - Only one identifier should be provided at a time
                - Function deletion is permanent and cannot be undone without undo/redo
                - Use with caution as it modifies the program database
                - Deleting and recreating will break existing references; prefer updating when possible
                </important_notes>

        <examples>
                Delete a function at an address:
                {
                  "file_name": "program.exe",
                  "address": "0x401500"
                }

                Delete a function by name:
                {
                  "file_name": "program.exe",
                  "name": "incorrect_function"
                }

                Delete a function by symbol ID:
                {
                  "file_name": "program.exe",
                  "symbol_id": 12345
                }
                </examples>
        """)
public class DeleteFunctionTool extends BaseMcpTool {

  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_SYMBOL_ID,
        SchemaBuilder.integer(mapper)
            .description("Symbol ID to identify target function (highest precedence)"));

    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Function address to identify target function")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_NAME,
        SchemaBuilder.string(mapper)
            .description("Function name for identification (supports regex matching)"));

    schemaRoot.requiredProperty(ARG_FILE_NAME);

    // At least one identifier must be provided (JSON Schema Draft 7 anyOf)
    schemaRoot.anyOf(
        SchemaBuilder.object(mapper).requiredProperty(ARG_SYMBOL_ID),
        SchemaBuilder.object(mapper).requiredProperty(ARG_ADDRESS),
        SchemaBuilder.object(mapper).requiredProperty(ARG_NAME));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

    return getProgram(args, tool)
        .flatMap(
            program -> {
              try {
                return handleDelete(program, args, annotation);
              } catch (GhidraMcpException e) {
                return Mono.error(e);
              }
            });
  }

  private Mono<? extends Object> handleDelete(
      Program program, Map<String, Object> args, GhidraMcpTool annotation)
      throws GhidraMcpException {
    String toolOperation = annotation.mcpName();

    // Apply precedence: symbol_id > address > name
    if (args.containsKey(ARG_SYMBOL_ID)) {
      Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
      if (symbolId != null) {
        return deleteBySymbolId(program, symbolId, toolOperation, args, annotation);
      }
    } else if (args.containsKey(ARG_ADDRESS)) {
      String address = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
      if (address != null && !address.trim().isEmpty()) {
        return deleteByAddress(program, address, toolOperation, args, annotation);
      }
    } else if (args.containsKey(ARG_NAME)) {
      String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
      if (name != null && !name.trim().isEmpty()) {
        return deleteByName(program, name, toolOperation, args, annotation);
      }
    }

    // No valid parameters provided
    Map<String, Object> providedIdentifiers =
        Map.of(
            ARG_SYMBOL_ID, "not provided",
            ARG_ADDRESS, "not provided",
            ARG_NAME, "not provided");

    GhidraMcpError error =
        GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
            .message("At least one identifier must be provided")
            .context(
                new GhidraMcpError.ErrorContext(
                    toolOperation,
                    "function identifier validation",
                    args,
                    providedIdentifiers,
                    Map.of("identifiersProvided", 0, "minimumRequired", 1)))
            .suggestions(
                List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                        "Provide at least one function identifier",
                        "Include symbol ID, address, or name of the function",
                        List.of(
                            ARG_SYMBOL_ID + ": 12345",
                            ARG_ADDRESS + ": \"0x401000\"",
                            ARG_NAME + ": \"main\""),
                        null)))
            .build();
    return Mono.error(new GhidraMcpException(error));
  }

  private Mono<? extends Object> deleteBySymbolId(
      Program program,
      Long symbolId,
      String toolOperation,
      Map<String, Object> args,
      GhidraMcpTool annotation) {
    return Mono.fromCallable(
            () -> {
              Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
              if (symbol == null) {
                throw new GhidraMcpException(
                    createFunctionNotFoundError(toolOperation, "symbol_id", symbolId.toString()));
              }
              Function function = program.getFunctionManager().getFunctionAt(symbol.getAddress());
              if (function == null) {
                throw new GhidraMcpException(
                    createFunctionNotFoundError(toolOperation, "symbol_id", symbolId.toString()));
              }
              return function;
            })
        .flatMap(function -> deleteFunction(program, function, toolOperation));
  }

  private Mono<? extends Object> deleteByAddress(
      Program program,
      String addressStr,
      String toolOperation,
      Map<String, Object> args,
      GhidraMcpTool annotation) {
    return parseAddress(program, addressStr, toolOperation)
        .flatMap(
            addressResult -> {
              Function function =
                  program.getFunctionManager().getFunctionAt(addressResult.getAddress());
              if (function == null) {
                return Mono.error(
                    new GhidraMcpException(
                        createFunctionNotFoundError(toolOperation, "address", addressStr)));
              }
              return deleteFunction(program, function, toolOperation);
            });
  }

  private Mono<? extends Object> deleteByName(
      Program program,
      String name,
      String toolOperation,
      Map<String, Object> args,
      GhidraMcpTool annotation) {
    return Mono.fromCallable(
            () -> {
              // Try exact match first
              Optional<Function> exactMatch =
                  StreamSupport.stream(
                          program.getFunctionManager().getFunctions(true).spliterator(), false)
                      .filter(f -> f.getName().equals(name))
                      .findFirst();

              if (exactMatch.isPresent()) {
                return exactMatch.get();
              }

              // Try regex match
              List<Function> regexMatches =
                  StreamSupport.stream(
                          program.getFunctionManager().getFunctions(true).spliterator(), false)
                      .filter(f -> f.getName().matches(name))
                      .collect(Collectors.toList());

              if (regexMatches.isEmpty()) {
                throw new GhidraMcpException(
                    createFunctionNotFoundError(toolOperation, "name", name));
              } else if (regexMatches.size() > 1) {
                throw new GhidraMcpException(
                    createMultipleFunctionsFoundError(toolOperation, name, regexMatches));
              }

              return regexMatches.get(0);
            })
        .flatMap(function -> deleteFunction(program, function, toolOperation));
  }

  private Mono<? extends Object> deleteFunction(
      Program program, Function function, String toolOperation) {
    Address entryPoint = function.getEntryPoint();
    String entryPointStr = entryPoint.toString();

    return executeInTransaction(
        program,
        "MCP - Delete Function at " + entryPointStr,
        () -> {
          DeleteFunctionCmd cmd = new DeleteFunctionCmd(entryPoint);
          if (!cmd.applyTo(program)) {
            String status = Optional.ofNullable(cmd.getStatusMsg()).orElse("Unknown error");
            GhidraMcpError error =
                GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to delete function: " + status)
                    .context(
                        new GhidraMcpError.ErrorContext(
                            toolOperation,
                            "function deletion command",
                            Map.of(ARG_ADDRESS, entryPointStr),
                            Map.of("commandStatus", status),
                            Map.of("commandSuccess", false)))
                    .suggestions(
                        List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Verify the function is not protected",
                                "Ensure the target function is not locked or already removed",
                                null,
                                null)))
                    .build();
            throw new GhidraMcpException(error);
          }

          return OperationResult.success(
                  "delete_function", entryPointStr, "Function deleted successfully")
              .setMetadata(Map.of("name", function.getName(), "entry_point", entryPointStr));
        });
  }

  private GhidraMcpError createFunctionNotFoundError(
      String toolOperation, String searchType, String searchValue) {
    return GhidraMcpError.validation()
        .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
        .message("Function not found using " + searchType + ": " + searchValue)
        .context(
            new GhidraMcpError.ErrorContext(
                toolOperation,
                "function resolution",
                Map.of(searchType, searchValue),
                Map.of(),
                Map.of("searchMethod", searchType)))
        .suggestions(
            List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Verify the function exists",
                    "Check that the function identifier is correct",
                    List.of(
                        "\"symbol_id\": 12345", "\"address\": \"0x401000\"", "\"name\": \"main\""),
                    null)))
        .build();
  }

  private GhidraMcpError createMultipleFunctionsFoundError(
      String toolOperation, String searchValue, List<Function> functions) {
    List<String> functionNames =
        functions.stream().map(Function::getName).limit(5).collect(Collectors.toList());

    return GhidraMcpError.validation()
        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
        .message("Multiple functions found for name pattern: " + searchValue)
        .context(
            new GhidraMcpError.ErrorContext(
                toolOperation,
                "function resolution",
                Map.of("name", searchValue),
                Map.of("matchCount", functions.size()),
                Map.of("firstFiveMatches", functionNames)))
        .suggestions(
            List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Use a more specific function identifier",
                    "Consider using symbol_id or address for exact identification",
                    List.of(
                        "\"symbol_id\": 12345",
                        "\"address\": \"0x401000\"",
                        "\"name\": \"exact_function_name\""),
                    null)))
        .build();
  }
}
