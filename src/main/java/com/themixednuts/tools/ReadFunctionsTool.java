package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Read Functions",
    description =
        "Read a single function or list functions in a Ghidra program with pagination and filtering"
            + " options.",
    mcpName = "read_functions",
    title = "Read Functions",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
        <use_case>
        Read a single function by identifier (symbol_id, address, name) or browse/list functions
        in Ghidra programs with optional filtering by name pattern and pagination support.
        Returns detailed function information including addresses, signatures, and metadata.
        </use_case>

        <important_notes>
        - Supports two modes: single function read (provide symbol_id/address/name) or list mode (no identifiers)
        - When reading a single function, returns FunctionInfo object directly
        - When listing functions, returns paginated results with cursor support
        - Supports filtering by name patterns (regex) in list mode
        - Functions are sorted by entry point address for consistent ordering
        - Name-based lookup supports exact and wildcard (*, ?) matching
        </important_notes>

        <examples>
        Read a single function by address:
        {
          "file_name": "program.exe",
          "address": "0x401000"
        }

        Read a single function by name:
        {
          "file_name": "program.exe",
          "name": "main"
        }

        Read a single function by symbol ID:
        {
          "file_name": "program.exe",
          "symbol_id": 12345
        }

        List all functions (first page):
        {
          "file_name": "program.exe"
        }

        List functions matching pattern:
        {
          "file_name": "program.exe",
          "name_pattern": ".*decrypt.*"
        }

        Get next page of results:
        {
          "file_name": "program.exe",
          "cursor": "v1:MHg0MDEwMDA:bWFpbg"
        }
        </examples>
        """)
public class ReadFunctionsTool extends BaseMcpTool {

  @Override
  public JsonSchema schema() {
    var schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_SYMBOL_ID,
        SchemaBuilder.integer(mapper)
            .description("Symbol ID to identify a specific function (single read mode)"));

    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Function address to identify a specific function (single read mode)")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_NAME,
        SchemaBuilder.string(mapper)
            .description("Function name for single function lookup (supports * and ? wildcards)"));

    schemaRoot.property(
        ARG_NAME_PATTERN,
        SchemaBuilder.string(mapper)
            .description("Optional regex pattern to filter function names (list mode)"));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper)
            .description(
                "Pagination cursor from previous request (format:"
                    + " v1:<base64url_address>:<base64url_function_name>)"));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description(
                "Number of functions to return per page (default: "
                    + DEFAULT_PAGE_LIMIT
                    + ", max: "
                    + MAX_PAGE_LIMIT
                    + ")")
            .minimum(1)
            .maximum(MAX_PAGE_LIMIT));

    schemaRoot.requiredProperty(ARG_FILE_NAME);

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return getProgram(args, tool)
        .flatMap(
            program -> {
              boolean hasSingleIdentifier =
                  args.containsKey(ARG_SYMBOL_ID)
                      || args.containsKey(ARG_ADDRESS)
                      || args.containsKey(ARG_NAME);

              if (hasSingleIdentifier) {
                return readSingleFunction(program, args);
              } else {
                return Mono.fromCallable(() -> listFunctions(program, args));
              }
            });
  }

  private Mono<FunctionInfo> readSingleFunction(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          FunctionManager functionManager = program.getFunctionManager();

          // Apply precedence: symbol_id > address > name
          if (args.containsKey(ARG_SYMBOL_ID)) {
            return readBySymbolId(program, functionManager, args);
          } else if (args.containsKey(ARG_ADDRESS)) {
            return readByAddress(program, functionManager, args);
          } else if (args.containsKey(ARG_NAME)) {
            return readByName(program, functionManager, args);
          } else {
            throw new GhidraMcpException(GhidraMcpError.missing("symbol_id, address, or name"));
          }
        });
  }

  private FunctionInfo readBySymbolId(
      Program program, FunctionManager functionManager, Map<String, Object> args)
      throws GhidraMcpException {
    Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
    if (symbolId == null) {
      throw new GhidraMcpException(GhidraMcpError.missing(ARG_SYMBOL_ID));
    }

    Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
    if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
      Function function = functionManager.getFunctionAt(symbol.getAddress());
      if (function != null) {
        return new FunctionInfo(function);
      }
    }

    throw new GhidraMcpException(GhidraMcpError.notFound("function", "symbol_id=" + symbolId));
  }

  private FunctionInfo readByAddress(
      Program program, FunctionManager functionManager, Map<String, Object> args)
      throws GhidraMcpException {
    String addressStr = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
    if (addressStr == null || addressStr.isBlank()) {
      throw new GhidraMcpException(GhidraMcpError.missing(ARG_ADDRESS));
    }

    try {
      Address functionAddress = program.getAddressFactory().getAddress(addressStr);
      if (functionAddress != null) {
        Function function = functionManager.getFunctionAt(functionAddress);
        if (function != null) {
          return new FunctionInfo(function);
        }
      }
    } catch (Exception e) {
      throw new GhidraMcpException(GhidraMcpError.parse("address", addressStr));
    }

    throw new GhidraMcpException(GhidraMcpError.notFound("function", "address=" + addressStr));
  }

  private FunctionInfo readByName(
      Program program, FunctionManager functionManager, Map<String, Object> args)
      throws GhidraMcpException {
    String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
    if (name == null || name.isBlank()) {
      throw new GhidraMcpException(GhidraMcpError.missing(ARG_NAME));
    }

    SymbolTable symbolTable = program.getSymbolTable();

    // Use native SymbolTable.getSymbols() for efficient exact name lookup
    SymbolIterator symbolIter = symbolTable.getSymbols(name);
    while (symbolIter.hasNext()) {
      Symbol symbol = symbolIter.next();
      if (symbol.getSymbolType() == SymbolType.FUNCTION) {
        Function function = functionManager.getFunctionAt(symbol.getAddress());
        if (function != null) {
          return new FunctionInfo(function);
        }
      }
    }

    // If no exact match, try wildcard search using SymbolTable's native wildcard support
    // SymbolTable.getSymbolIterator supports * and ? wildcards
    if (name.contains("*") || name.contains("?")) {
      SymbolIterator wildcardIter = symbolTable.getSymbolIterator(name, false);
      Function firstMatch = null;
      int matchCount = 0;

      while (wildcardIter.hasNext()) {
        Symbol symbol = wildcardIter.next();
        if (symbol.getSymbolType() == SymbolType.FUNCTION) {
          Function function = functionManager.getFunctionAt(symbol.getAddress());
          if (function != null) {
            if (firstMatch == null) {
              firstMatch = function;
            }
            matchCount++;
            if (matchCount > 1) {
              throw new GhidraMcpException(
                  GhidraMcpError.conflict(
                      "Multiple functions found for wildcard pattern: " + name));
            }
          }
        }
      }

      if (firstMatch != null) {
        return new FunctionInfo(firstMatch);
      }
    }

    throw new GhidraMcpException(GhidraMcpError.notFound("function", "name=" + name));
  }

  private PaginatedResult<FunctionInfo> listFunctions(Program program, Map<String, Object> args) {
    FunctionManager functionManager = program.getFunctionManager();
    int pageSize =
        getOptionalIntArgument(args, ARG_PAGE_SIZE)
            .filter(size -> size > 0)
            .map(size -> Math.min(size, MAX_PAGE_LIMIT))
            .orElse(DEFAULT_PAGE_LIMIT);

    Optional<String> namePatternOpt = getOptionalStringArgument(args, ARG_NAME_PATTERN);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

    FunctionCursor cursor = cursorOpt.map(value -> parseFunctionCursor(program, value)).orElse(null);

    // Compile name pattern if provided
    Pattern namePattern = null;
    if (namePatternOpt.isPresent()) {
      try {
        namePattern = Pattern.compile(namePatternOpt.get());
      } catch (PatternSyntaxException e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid("name_pattern", namePatternOpt.get(), e.getMessage()));
      }
    }

    List<FunctionInfo> allMatches = new ArrayList<>();
    FunctionIterator funcIter = functionManager.getFunctions(true);
    while (funcIter.hasNext()) {
      Function function = funcIter.next();
      if (namePattern != null && !namePattern.matcher(function.getName()).matches()) {
        continue;
      }
      allMatches.add(new FunctionInfo(function));
    }

    int startIndex = 0;
    if (cursor != null) {
      boolean matched = false;
      for (int i = 0; i < allMatches.size(); i++) {
        FunctionInfo functionInfo = allMatches.get(i);
        if (functionInfo.getEntryPoint().equalsIgnoreCase(cursor.address)
            && functionInfo.getName().equals(cursor.name)) {
          startIndex = i + 1;
          matched = true;
          break;
        }
      }

      if (!matched) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR,
                cursor.toCursorString(),
                "cursor is invalid or no longer present in this function listing"));
      }
    }

    int endExclusive = Math.min(allMatches.size(), startIndex + pageSize + 1);
    List<FunctionInfo> paginatedResults = new ArrayList<>(allMatches.subList(startIndex, endExclusive));

    boolean hasMore = paginatedResults.size() > pageSize;
    List<FunctionInfo> results =
        hasMore ? new ArrayList<>(paginatedResults.subList(0, pageSize)) : paginatedResults;

    String nextCursor = null;
    if (hasMore && !results.isEmpty()) {
      FunctionInfo lastFunc = results.get(results.size() - 1);
      nextCursor = encodeCursor(lastFunc.getEntryPoint(), lastFunc.getName());
    }

    return new PaginatedResult<>(results, nextCursor);
  }

  private FunctionCursor parseFunctionCursor(Program program, String cursorValue) {
    List<String> parts =
        OpaqueCursorCodec.decodeV1(
            cursorValue,
            2,
            ARG_CURSOR,
            "v1:<base64url_address>:<base64url_function_name>");

    Address cursorAddress = program.getAddressFactory().getAddress(parts.get(0));
    if (cursorAddress == null) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, cursorValue, "contains an invalid address component"));
    }

    String decodedName = parts.get(1);

    if (decodedName.isBlank()) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, cursorValue, "contains an empty function name"));
    }

    return new FunctionCursor(cursorAddress.toString(), decodedName, cursorValue);
  }

  private String encodeCursor(String address, String functionName) {
    return OpaqueCursorCodec.encodeV1(address, functionName);
  }

  private static final class FunctionCursor {
    private final String address;
    private final String name;
    private final String rawCursor;

    private FunctionCursor(String address, String name, String rawCursor) {
      this.address = address;
      this.name = name;
      this.rawCursor = rawCursor;
    }

    private String toCursorString() {
      return rawCursor;
    }
  }
}
