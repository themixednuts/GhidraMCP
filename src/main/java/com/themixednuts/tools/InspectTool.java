package com.themixednuts.tools;

import com.themixednuts.GhidraMcpServer;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.CodeSearchResult;
import com.themixednuts.models.DecompilationResult;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.ListingInfo;
import com.themixednuts.models.ReferenceInfo;
import com.themixednuts.ui.NavigateToAddressEffect;
import com.themixednuts.ui.ToolOutcome;
import com.themixednuts.utils.CursorDataResult;
import com.themixednuts.utils.GhidraAddressParser;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.SymbolLookupHelper;
import com.themixednuts.utils.TextSearch;
import com.themixednuts.utils.TextWindow;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Inspect",
    description =
        "Inspect code at a location: decompile to C, view assembly listing, find cross-references.",
    mcpName = "inspect",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
        Read code in an open program. Use decompile for C-like pseudocode, search_code to find
        text across functions, listing for assembly, and references_to or references_from for
        cross-references. Decompile returns 200 source lines by default. Follow next_line with
        start_line, or search with search_text; pass decompilation_id on follow-up reads to reuse
        the completed result. Decompilation uses the configured request timeout unless a shorter
        timeout is supplied. Search, listing, and reference results are paged.
        """)
public class InspectTool extends BaseMcpTool {

  @Override
  protected Optional<String> createSuccessTextContent(
      com.themixednuts.models.McpResponse<?> response,
      Map<String, Object> args,
      String toolName,
      String operation) {
    Object data = response.getData();

    if (data instanceof String text && !text.isBlank()) {
      return Optional.of(text);
    }

    if (ACTION_DECOMPILE.equals(operation)) {
      Optional<String> rendered = renderDecompileText(data);
      String snapshotHint =
          data instanceof DecompilationResult result && result.getDecompilationId() != null
              ? "\n// Reuse with decompilation_id=" + result.getDecompilationId() + "."
              : "";
      if (data instanceof DecompilationResult result && result.getSearchText() != null) {
        String summary =
            "// "
                + result.getTotalMatches()
                + " matching source lines; "
                + result.getOmittedMatches()
                + " omitted."
                + (result.getNextMatchOffset() != null
                    ? " Continue with match_offset=" + result.getNextMatchOffset() + "."
                    : "");
        return Optional.of(rendered.map(code -> code + summary + snapshotHint).orElse(summary));
      }
      if (data instanceof DecompilationResult result && result.getNextLine() != null) {
        return rendered.map(
            code ->
                code
                    + "\n// Lines "
                    + result.getCodeStartLine()
                    + "-"
                    + (result.getNextLine() - 1)
                    + " of "
                    + result.getCodeTotalLines()
                    + ". Continue with start_line="
                    + result.getNextLine()
                    + "."
                    + snapshotHint);
      }
      return rendered.map(code -> code + snapshotHint);
    }
    if (ACTION_SEARCH_CODE.equals(operation) && data instanceof CodeSearchResult result) {
      StringBuilder output = new StringBuilder();
      for (CodeSearchResult.Hit hit : result.matches()) {
        output.append("// ").append(hit.functionName()).append(" @ ").append(hit.entryAddress());
        if (hit.decompilationId() != null) {
          output.append("; decompilation_id=").append(hit.decompilationId());
        }
        output.append('\n').append(hit.excerpt());
      }
      output.append("// Scanned ").append(result.functionsScanned()).append(" functions.");
      if (result.nextCursor() != null) {
        output.append(" Continue with cursor=").append(result.nextCursor()).append('.');
      }
      if (result.interruptedAt() != null) {
        output
            .append(" Decompilation paused at ")
            .append(result.interruptedAt())
            .append("; increase MCP Request Timeout if it repeats.");
      }
      return Optional.of(output.toString());
    }
    if (ACTION_LISTING.equals(operation)) {
      return renderListingText(data);
    }

    return Optional.empty();
  }

  public static final String ARG_INCLUDE_PCODE = "include_pcode";
  public static final String ARG_INCLUDE_AST = "include_ast";
  public static final String ARG_TIMEOUT = "timeout";
  public static final String ARG_ANALYSIS_LEVEL = "analysis_level";
  public static final String ARG_END_ADDRESS = "end_address";
  public static final String ARG_MAX_LINES = "max_lines";
  public static final String ARG_START_LINE = "start_line";
  public static final String ARG_SEARCH_TEXT = "search_text";
  public static final String ARG_CASE_SENSITIVE = "case_sensitive";
  public static final String ARG_CONTEXT_LINES = "context_lines";
  public static final String ARG_MAX_MATCHES = "max_matches";
  public static final String ARG_MATCH_OFFSET = "match_offset";
  public static final String ARG_DECOMPILATION_ID = "decompilation_id";
  public static final String ARG_REFERENCE_TYPE = "reference_type";

  private static final String ACTION_DECOMPILE = "decompile";
  private static final String ACTION_SEARCH_CODE = "search_code";
  private static final String ACTION_LISTING = "listing";
  private static final String ACTION_REFERENCES_TO = "references_to";
  private static final String ACTION_REFERENCES_FROM = "references_from";

  private static final int DEFAULT_MAX_LINES = 100;
  private static final int DEFAULT_DECOMPILE_MAX_LINES = 200;
  private static final int DEFAULT_SEARCH_CONTEXT_LINES = 2;
  private static final int DEFAULT_SEARCH_MAX_MATCHES = 8;
  private static final int DEFAULT_SEARCH_MAX_FUNCTIONS = 8;
  private final DecompilationSnapshots snapshots = new DecompilationSnapshots();

  private record TextSearchOptions(
      String query, boolean caseSensitive, int contextLines, int matchOffset, int maxMatches) {}

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();
    int requestTimeoutSeconds = GhidraMcpServer.getRequestTimeoutSeconds();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_DECOMPILE,
                ACTION_SEARCH_CODE,
                ACTION_LISTING,
                ACTION_REFERENCES_TO,
                ACTION_REFERENCES_FROM)
            .description("Inspection action to perform"));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_ACTION);

    schemaRoot.allOf(
        // action=decompile: requires identifier (symbol_id, address, or name)
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_DECOMPILE)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description("Function symbol ID to decompile"))
                    .property(
                        ARG_DECOMPILATION_ID,
                        SchemaBuilder.string(mapper)
                            .description(
                                "ID from a previous decompile result; reuses its saved code"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Address of function or code to decompile")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name to decompile (supports * and ? wildcards)"))
                    .property(
                        ARG_INCLUDE_PCODE,
                        SchemaBuilder.bool(mapper)
                            .description("Include P-code intermediate representation")
                            .defaultValue(false))
                    .property(
                        ARG_INCLUDE_AST,
                        SchemaBuilder.bool(mapper)
                            .description("Include abstract syntax tree information")
                            .defaultValue(false))
                    .property(
                        ARG_TIMEOUT,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Decompilation timeout in seconds, up to the configured MCP"
                                    + " Request Timeout")
                            .minimum(1)
                            .maximum(requestTimeoutSeconds)
                            .defaultValue(requestTimeoutSeconds))
                    .property(
                        ARG_ANALYSIS_LEVEL,
                        SchemaBuilder.string(mapper)
                            .enumValues("basic", "standard", "advanced")
                            .description("Level of decompilation analysis")
                            .defaultValue("standard"))
                    .property(
                        ARG_START_LINE,
                        SchemaBuilder.integer(mapper)
                            .description("One-based first decompiled source line to return")
                            .minimum(1)
                            .defaultValue(1))
                    .property(
                        ARG_MAX_LINES,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Decompiled source lines to return (default: 200, max: 1000)."
                                    + " Use 0 for the full function; follow next_line to continue.")
                            .minimum(0)
                            .maximum(1000)
                            .defaultValue(DEFAULT_DECOMPILE_MAX_LINES))
                    .property(
                        ARG_SEARCH_TEXT,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Literal text to find across all decompiled source lines."
                                    + " When supplied, returns numbered matches with context"
                                    + " instead of the start_line/max_lines window."))
                    .property(
                        ARG_CASE_SENSITIVE,
                        SchemaBuilder.bool(mapper)
                            .description("Match search_text case exactly (default: false)")
                            .defaultValue(false))
                    .property(
                        ARG_CONTEXT_LINES,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Source lines before and after each match (default: 2, max: 3)")
                            .minimum(0)
                            .maximum(3)
                            .defaultValue(DEFAULT_SEARCH_CONTEXT_LINES))
                    .property(
                        ARG_MAX_MATCHES,
                        SchemaBuilder.integer(mapper)
                            .description("Matching source lines per page (default: 8, max: 10)")
                            .minimum(1)
                            .maximum(10)
                            .defaultValue(DEFAULT_SEARCH_MAX_MATCHES))
                    .property(
                        ARG_MATCH_OFFSET,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Matching lines to skip; copy next_match_offset to continue")
                            .minimum(0)
                            .defaultValue(0))
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_DECOMPILATION_ID))),

        // action=search_code: bounded program-wide decompiled source search
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_SEARCH_CODE)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SEARCH_TEXT)
                    .property(
                        ARG_SEARCH_TEXT,
                        SchemaBuilder.string(mapper)
                            .description("Literal text to find in decompiled functions")
                            .minLength(1)
                            .maxLength(256))
                    .property(
                        ARG_CASE_SENSITIVE,
                        SchemaBuilder.bool(mapper)
                            .description("Match case exactly (default: false)"))
                    .property(
                        ARG_CONTEXT_LINES,
                        SchemaBuilder.integer(mapper)
                            .description("Context lines around each match (default: 2, max: 3)")
                            .minimum(0)
                            .maximum(3))
                    .property(
                        ARG_MAX_MATCHES,
                        SchemaBuilder.integer(mapper)
                            .description("Matching lines per page (default: 8, max: 10)")
                            .minimum(1)
                            .maximum(10))
                    .property(
                        "max_functions",
                        SchemaBuilder.integer(mapper)
                            .description("Functions to scan per page (default: 8, max: 50)")
                            .minimum(1)
                            .maximum(50))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Opaque continuation cursor from search_code next_cursor"))),

        // action=listing: requires explicit target (address, name, or symbol_id)
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_LISTING)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Start address to view listing for")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_END_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Optional end address for address range viewing")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name to view listing for"))
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description("Function symbol ID to view listing for"))
                    .property(
                        ARG_MAX_LINES,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Maximum listing lines to return (default: 100, max: 1000)."
                                    + " Use next_cursor/cursor to continue long listings.")
                            .minimum(1)
                            .maximum(1000)
                            .defaultValue(DEFAULT_MAX_LINES))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Opaque cursor copied from the previous inspect.listing"
                                    + " next_cursor. Keep address/name/symbol_id and end_address"
                                    + " unchanged. Format: v1:<base64url_listing_address>."))
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID))),

        // action=references_to: requires address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_REFERENCES_TO)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Target address to find references to")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_REFERENCE_TYPE,
                        SchemaBuilder.string(mapper)
                            .description("Filter by reference type (e.g., 'DATA', 'CALL', 'JUMP')"))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Opaque cursor copied from the previous references_to"
                                    + " next_cursor. Keep address and reference_type unchanged."))
                    .property(
                        ARG_PAGE_SIZE,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Number of references per page (default: "
                                    + DEFAULT_PAGE_LIMIT
                                    + ", max: "
                                    + MAX_PAGE_LIMIT
                                    + ")")
                            .minimum(1)
                            .maximum(MAX_PAGE_LIMIT))),

        // action=references_from: requires address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_REFERENCES_FROM)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Source address to find references from")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_REFERENCE_TYPE,
                        SchemaBuilder.string(mapper)
                            .description("Filter by reference type (e.g., 'DATA', 'CALL', 'JUMP')"))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Opaque cursor copied from the previous references_from"
                                    + " next_cursor. Keep address and reference_type unchanged."))
                    .property(
                        ARG_PAGE_SIZE,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Number of references per page (default: "
                                    + DEFAULT_PAGE_LIMIT
                                    + ", max: "
                                    + MAX_PAGE_LIMIT
                                    + ")")
                            .minimum(1)
                            .maximum(MAX_PAGE_LIMIT))));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

    return getProgram(args, tool)
        .flatMap(
            program -> {
              String action;
              try {
                action = getRequiredStringArgument(args, ARG_ACTION);
              } catch (GhidraMcpException e) {
                return Mono.error(e);
              }

              return switch (action.toLowerCase()) {
                case ACTION_DECOMPILE -> executeDecompile(program, args, annotation);
                case ACTION_SEARCH_CODE -> executeSearchCode(program, args);
                case ACTION_LISTING -> executeListing(program, args, annotation);
                // Aliases for the common shorthand names — references / xrefs / xrefs_to(from).
                case ACTION_REFERENCES_TO, "references", "xrefs", "xrefs_to" ->
                    executeReferences(program, args, annotation, true);
                case ACTION_REFERENCES_FROM, "xrefs_from" ->
                    executeReferences(program, args, annotation, false);
                default -> {
                  Map<String, String> aliases =
                      Map.of(
                          "disassemble", ACTION_LISTING,
                          "asm", ACTION_LISTING,
                          "assembly", ACTION_LISTING,
                          "callers", ACTION_REFERENCES_TO,
                          "callees", ACTION_REFERENCES_FROM,
                          "decomp", ACTION_DECOMPILE,
                          "pseudocode", ACTION_DECOMPILE);
                  GhidraMcpError error =
                      GhidraMcpErrorUtils.invalidAction(
                          action,
                          List.of(
                              ACTION_DECOMPILE,
                              ACTION_SEARCH_CODE,
                              ACTION_LISTING,
                              ACTION_REFERENCES_TO,
                              ACTION_REFERENCES_FROM),
                          aliases);
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  // =================== Decompile Action ===================

  private Mono<? extends Object> executeDecompile(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    boolean includePcode = getOptionalBooleanArgument(args, ARG_INCLUDE_PCODE).orElse(false);
    boolean includeAst = getOptionalBooleanArgument(args, ARG_INCLUDE_AST).orElse(false);
    int requestTimeoutSeconds = GhidraMcpServer.getRequestTimeoutSeconds();
    int timeout = getOptionalIntArgument(args, ARG_TIMEOUT).orElse(requestTimeoutSeconds);
    if (timeout < 1 || timeout > requestTimeoutSeconds) {
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.invalid(
                  ARG_TIMEOUT,
                  timeout,
                  "must be between 1 and the configured MCP Request Timeout of "
                      + requestTimeoutSeconds
                      + " seconds")));
    }
    int startLine = getOptionalIntArgument(args, ARG_START_LINE).orElse(1);
    int maxLines = getOptionalIntArgument(args, ARG_MAX_LINES).orElse(DEFAULT_DECOMPILE_MAX_LINES);
    TextSearchOptions searchOptions = parseTextSearchOptions(args);
    if (startLine < 1 || maxLines < 0 || maxLines > 1000) {
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.invalid(
                  "decompile line window", startLine + "/" + maxLines, "invalid line range")));
    }

    Optional<String> decompilationId = getOptionalStringArgument(args, ARG_DECOMPILATION_ID);
    if (decompilationId.isPresent()) {
      DecompilationSnapshots.Snapshot snapshot = snapshots.get(decompilationId.get(), program);
      if (snapshot == null) {
        return Mono.error(
            new GhidraMcpException(
                GhidraMcpError.invalid(
                    ARG_DECOMPILATION_ID,
                    decompilationId.get(),
                    "snapshot expired, was evicted, or belongs to another program; decompile"
                        + " again")));
      }
      if ((includePcode && snapshot.pcodeOperations() == null)
          || (includeAst && snapshot.basicBlockCount() == null)) {
        return Mono.error(
            new GhidraMcpException(
                GhidraMcpError.invalid(
                    ARG_DECOMPILATION_ID,
                    decompilationId.get(),
                    "requested P-code or AST was not captured; decompile again with that option")));
      }
      return Mono.fromCallable(
          () ->
              renderSnapshot(
                  snapshot, includePcode, includeAst, startLine, maxLines, searchOptions));
    }

    // Determine if we have an address-only target (no function name/symbol)
    Optional<Long> symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID);
    Optional<String> addressOpt =
        getOptionalStringArgument(args, ARG_ADDRESS).map(String::trim).filter(v -> !v.isEmpty());
    Optional<String> nameOpt =
        getOptionalStringArgument(args, ARG_NAME).map(String::trim).filter(v -> !v.isEmpty());

    // If only address is given (no name, no symbol_id), try address-mode decompile
    if (symbolId.isEmpty() && nameOpt.isEmpty() && addressOpt.isPresent()) {
      return decompileAtAddress(
          program,
          addressOpt.get(),
          includePcode,
          includeAst,
          timeout,
          startLine,
          maxLines,
          searchOptions,
          annotation);
    }

    // Otherwise resolve as function
    return withTaskMonitor(
        "inspect.decompile",
        monitor -> {
          Function targetFunction = resolveFunctionForDecompilation(program, args);
          DecompilationResult result =
              performDecompilation(
                  program,
                  targetFunction,
                  includePcode,
                  includeAst,
                  timeout,
                  startLine,
                  maxLines,
                  searchOptions,
                  annotation,
                  monitor);
          return ToolOutcome.of(
              result, NavigateToAddressEffect.decompiler(program, targetFunction.getEntryPoint()));
        });
  }

  private TextSearchOptions parseTextSearchOptions(Map<String, Object> args) {
    Optional<String> queryOpt = getOptionalStringArgument(args, ARG_SEARCH_TEXT);
    if (queryOpt.isEmpty()) {
      return null;
    }
    String query = queryOpt.get();
    if (query.isBlank()
        || query.length() > 256
        || query.indexOf('\n') >= 0
        || query.indexOf('\r') >= 0) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_SEARCH_TEXT, "must be a nonblank single line of at most 256 characters"));
    }
    int contextLines =
        getOptionalIntArgument(args, ARG_CONTEXT_LINES).orElse(DEFAULT_SEARCH_CONTEXT_LINES);
    int maxMatches =
        getOptionalIntArgument(args, ARG_MAX_MATCHES).orElse(DEFAULT_SEARCH_MAX_MATCHES);
    int matchOffset = getOptionalIntArgument(args, ARG_MATCH_OFFSET).orElse(0);
    if (contextLines < 0
        || contextLines > 3
        || maxMatches < 1
        || maxMatches > 10
        || matchOffset < 0) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              "decompile search bounds",
              "context_lines, max_matches, or match_offset is out of range"));
    }
    boolean caseSensitive = getOptionalBooleanArgument(args, ARG_CASE_SENSITIVE).orElse(false);
    return new TextSearchOptions(query, caseSensitive, contextLines, matchOffset, maxMatches);
  }

  private record CodeSearchCursor(Address address, int matchOffset, String snapshotId) {}

  private Mono<CodeSearchResult> executeSearchCode(Program program, Map<String, Object> args) {
    TextSearchOptions options = parseTextSearchOptions(args);
    if (options == null) {
      return Mono.error(new GhidraMcpException(GhidraMcpError.missing(ARG_SEARCH_TEXT)));
    }
    int maxFunctions =
        getOptionalIntArgument(args, "max_functions").orElse(DEFAULT_SEARCH_MAX_FUNCTIONS);
    if (maxFunctions < 1 || maxFunctions > 50) {
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.invalid("max_functions", maxFunctions, "must be between 1 and 50")));
    }
    CodeSearchCursor cursor =
        getOptionalStringArgument(args, ARG_CURSOR)
            .map(value -> parseCodeSearchCursor(program, value, options))
            .orElse(null);
    return withTaskMonitor(
        "inspect.search_code",
        monitor -> searchCode(program, options, maxFunctions, cursor, monitor));
  }

  private CodeSearchCursor parseCodeSearchCursor(
      Program program, String value, TextSearchOptions options) {
    List<String> parts =
        decodeOpaqueCursorV1(
            value, 4, ARG_CURSOR, "v1:<address>:<match_offset>:<search_key>:<snapshot_id>");
    Address address = parseAddressValue(program, parts.get(0), ARG_CURSOR);
    int offset;
    try {
      offset = Integer.parseInt(parts.get(1));
    } catch (NumberFormatException e) {
      throw new GhidraMcpException(GhidraMcpError.invalid(ARG_CURSOR, value, "invalid offset"));
    }
    if (offset < -1 || !parts.get(2).equals(searchFingerprint(options))) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, value, "cursor does not match this search"));
    }
    return new CodeSearchCursor(address, offset, parts.get(3));
  }

  private String encodeCodeSearchCursor(
      Address address, int matchOffset, TextSearchOptions options, String snapshotId) {
    return OpaqueCursorCodec.encodeV1(
        address.toString(),
        Integer.toString(matchOffset),
        searchFingerprint(options),
        snapshotId == null ? "none" : snapshotId);
  }

  private String searchFingerprint(TextSearchOptions options) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update((byte) (options.caseSensitive() ? 1 : 0));
      byte[] hash = digest.digest(options.query().getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOf(hash, 12));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }

  private CodeSearchResult searchCode(
      Program program,
      TextSearchOptions options,
      int maxFunctions,
      CodeSearchCursor cursor,
      TaskMonitor monitor) {
    FunctionManager manager = program.getFunctionManager();
    FunctionIterator functions =
        cursor == null ? manager.getFunctions(true) : manager.getFunctions(cursor.address(), true);
    List<CodeSearchResult.Hit> hits = new ArrayList<>();
    int scanned = 0;
    int returnedMatches = 0;
    Address lastAddress = cursor == null ? null : cursor.address();
    int nextOffset = -1;
    String nextSnapshotId = null;
    String interruptedAt = null;
    int requestTimeout = GhidraMcpServer.getRequestTimeoutSeconds();
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(requestTimeout);
    DecompInterface decomp = null;
    try {
      while (functions.hasNext()
          && scanned < maxFunctions
          && returnedMatches < options.maxMatches()) {
        monitor.checkCancelled();
        if (scanned > 0 && deadline - System.nanoTime() < TimeUnit.SECONDS.toNanos(3)) {
          break;
        }
        Function function = functions.next();
        Address address = function.getEntryPoint();
        if (cursor != null
            && scanned == 0
            && address.equals(cursor.address())
            && cursor.matchOffset() == -1) {
          continue;
        }
        int matchOffset =
            cursor != null && scanned == 0 && address.equals(cursor.address())
                ? cursor.matchOffset()
                : 0;
        DecompilationSnapshots.Snapshot snapshot =
            cursor != null && scanned == 0 && matchOffset > 0
                ? snapshots.get(cursor.snapshotId(), program)
                : null;
        if (snapshot != null && !snapshot.entryAddress().equals(address.toString())) {
          snapshot = null;
        }
        if (snapshot == null) {
          if (decomp == null) {
            decomp = new DecompInterface();
            if (!decomp.openProgram(program)) {
              throw new GhidraMcpException(
                  GhidraMcpError.failed("decompilation", "could not open program"));
            }
          }
          long remainingSeconds =
              Math.max(
                  1,
                  TimeUnit.NANOSECONDS.toSeconds(
                      deadline - System.nanoTime() - TimeUnit.SECONDS.toNanos(2)));
          int timeout = (int) Math.min(requestTimeout, remainingSeconds);
          DecompileResults decompResult = decomp.decompileFunction(function, timeout, monitor);
          if (decompResult == null || !decompResult.decompileCompleted()) {
            boolean timedOut = decompResult == null || decompResult.isTimedOut();
            if (timedOut && scanned > 0) {
              lastAddress = address;
              nextOffset = 0;
              interruptedAt = address.toString();
              break;
            }
            String reason =
                decompResult == null
                    ? "timed out"
                    : Optional.ofNullable(decompResult.getErrorMessage()).orElse("no result");
            throw new GhidraMcpException(
                GhidraMcpError.failed(
                    "decompilation at " + address,
                    timedOut
                        ? reason + "; increase MCP Request Timeout and retry the search"
                        : reason));
          }
          snapshot = saveDecompilation(program, function, decompResult, false, false);
          decomp.flushCache();
        }
        scanned++;
        lastAddress = address;
        TextSearch search =
            TextSearch.of(
                snapshot.code(),
                options.query(),
                options.caseSensitive(),
                options.contextLines(),
                matchOffset,
                options.maxMatches() - returnedMatches);
        if (matchOffset > search.totalMatches()) {
          throw new GhidraMcpException(
              GhidraMcpError.invalid(
                  ARG_CURSOR, matchOffset, "match offset is past the end of this function"));
        }
        if (!search.matchingLines().isEmpty()) {
          hits.add(
              new CodeSearchResult.Hit(
                  snapshot.targetName(),
                  snapshot.entryAddress(),
                  snapshot.id(),
                  search.excerpt(),
                  search.matchingLines(),
                  search.totalMatches()));
          returnedMatches += search.matchingLines().size();
        }
        if (search.nextMatchOffset() != null) {
          nextOffset = search.nextMatchOffset();
          nextSnapshotId = snapshot.id();
          break;
        }
      }
      String nextCursor =
          lastAddress != null && (nextOffset >= 0 || functions.hasNext())
              ? encodeCodeSearchCursor(lastAddress, nextOffset, options, nextSnapshotId)
              : null;
      return new CodeSearchResult(
          List.copyOf(hits), scanned, nextCursor, nextCursor == null, interruptedAt);
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("code search", describeDecompilationFailure(e)), e);
    } finally {
      if (decomp != null) {
        decomp.dispose();
      }
    }
  }

  private Function resolveFunctionForDecompilation(Program program, Map<String, Object> args)
      throws GhidraMcpException {
    FunctionManager functionManager = program.getFunctionManager();
    SymbolTable symbolTable = program.getSymbolTable();

    Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
    String addressArg =
        getOptionalStringArgument(args, ARG_ADDRESS)
            .map(String::trim)
            .filter(v -> !v.isEmpty())
            .orElse(null);
    String nameArg =
        getOptionalStringArgument(args, ARG_NAME)
            .map(String::trim)
            .filter(v -> !v.isEmpty())
            .orElse(null);

    if (symbolId != null) {
      Symbol symbol = symbolTable.getSymbol(symbolId);
      if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
        Function function = functionManager.getFunctionAt(symbol.getAddress());
        if (function != null) {
          return function;
        }
      }
      throw new GhidraMcpException(GhidraMcpError.notFound("function", "symbol_id=" + symbolId));
    }

    if (addressArg != null) {
      Address functionAddress = parseAddressValue(program, addressArg, ARG_ADDRESS);
      Function function = getOrCreateFunction(program, functionAddress);
      if (function == null) {
        function = followFunctionPointer(program, functionAddress);
      }
      if (function != null) {
        return function;
      }
      throw new GhidraMcpException(GhidraMcpError.notFound("function", "address=" + addressArg));
    }

    if (nameArg != null && !nameArg.isBlank()) {
      return SymbolLookupHelper.resolveFunction(program, nameArg);
    }

    throw new GhidraMcpException(
        GhidraMcpError.of(
            "Decompile target is missing", "Provide one of: symbol_id, address, or name"));
  }

  private Mono<? extends Object> decompileAtAddress(
      Program program,
      String addressStr,
      boolean includePcode,
      boolean includeAst,
      int timeout,
      int startLine,
      int maxLines,
      TextSearchOptions searchOptions,
      GhidraMcpTool annotation) {
    return parseAddress(program, addressStr, "inspect.decompile")
        .flatMap(
            addressResult ->
                withTaskMonitor(
                    "inspect.decompile",
                    monitor -> {
                      Address address = addressResult.getAddress();
                      Function function = getOrCreateFunction(program, address);
                      if (function == null) {
                        function = followFunctionPointer(program, address);
                      }

                      if (function == null) {
                        // No function and auto-create failed — check for raw instruction
                        Listing listing = program.getListing();
                        Instruction instruction = listing.getInstructionAt(address);

                        if (instruction != null) {
                          return ToolOutcome.of(
                              analyzeInstructionPcode(instruction, address),
                              NavigateToAddressEffect.listing(program, address));
                        }

                        throw new GhidraMcpException(
                            GhidraMcpError.notFound("function or instruction", addressStr));
                      }

                      DecompilationResult result =
                          performDecompilation(
                              program,
                              function,
                              includePcode,
                              includeAst,
                              timeout,
                              startLine,
                              maxLines,
                              searchOptions,
                              annotation,
                              monitor);
                      return ToolOutcome.of(
                          result,
                          NavigateToAddressEffect.decompiler(program, function.getEntryPoint()));
                    }));
  }

  private Map<String, Object> analyzeInstructionPcode(Instruction instruction, Address address) {
    PcodeOp[] pcodeOps = instruction.getPcode();

    List<Map<String, Object>> pcodeList =
        Arrays.stream(pcodeOps)
            .map(
                op -> {
                  Map<String, Object> pcodeEntry = new LinkedHashMap<>();
                  pcodeEntry.put("opcode", op.getOpcode());
                  pcodeEntry.put("mnemonic", op.getMnemonic());
                  pcodeEntry.put("sequence_number", op.getSeqnum().getTime());
                  pcodeEntry.put(
                      "inputs",
                      Arrays.stream(op.getInputs())
                          .map(varnode -> varnode.toString())
                          .collect(Collectors.toList()));
                  if (op.getOutput() != null) {
                    pcodeEntry.put("output", op.getOutput().toString());
                  }
                  return pcodeEntry;
                })
            .collect(Collectors.toList());

    return Map.of(
        "type",
        "instruction_analysis",
        "address",
        address.toString(),
        "instruction",
        instruction.toString(),
        "pcode_operations",
        pcodeList,
        "decompiled_code",
        "// Single instruction at " + address + ": " + instruction.toString());
  }

  private DecompilationResult performDecompilation(
      Program program,
      Function function,
      boolean includePcode,
      boolean includeAst,
      int timeout,
      int startLine,
      int maxLines,
      TextSearchOptions searchOptions,
      GhidraMcpTool annotation,
      TaskMonitor monitor)
      throws GhidraMcpException {
    DecompInterface decomp = new DecompInterface();
    try {
      decomp.openProgram(program);

      DecompileResults decompResult = decomp.decompileFunction(function, timeout, monitor);
      if (decompResult == null || !decompResult.decompileCompleted()) {
        String errorMsg =
            Optional.ofNullable(decompResult)
                .map(DecompileResults::getErrorMessage)
                .orElse("Unknown decompilation error");
        if ((decompResult != null && decompResult.isTimedOut())
            || errorMsg.toLowerCase(Locale.ROOT).contains("timeout")) {
          throw new GhidraMcpException(
              GhidraMcpError.execution()
                  .message("Decompilation exceeded the " + timeout + "-second limit")
                  .hint(
                      "Increase GhidraMCP HTTP Server > Request Timeout in Ghidra, then"
                          + " retry. A shorter per-call timeout can also be supplied.")
                  .context(
                      new GhidraMcpError.ErrorContext(
                          annotation.mcpName(),
                          ACTION_DECOMPILE,
                          null,
                          Map.of(ARG_TIMEOUT, timeout),
                          Map.of(
                              "configured_request_timeout_seconds",
                              GhidraMcpServer.getRequestTimeoutSeconds())))
                  .build());
        }
        throw new GhidraMcpException(GhidraMcpError.failed("decompilation", errorMsg));
      }
      DecompilationSnapshots.Snapshot snapshot =
          saveDecompilation(program, function, decompResult, includePcode, includeAst);
      return renderSnapshot(snapshot, includePcode, includeAst, startLine, maxLines, searchOptions);

    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("decompilation", describeDecompilationFailure(e)), e);
    } finally {
      decomp.dispose();
    }
  }

  private DecompilationSnapshots.Snapshot saveDecompilation(
      Program program,
      Function function,
      DecompileResults decompResult,
      boolean includePcode,
      boolean includeAst) {
    String code =
        Optional.ofNullable(decompResult.getDecompiledFunction())
            .map(df -> df.getC())
            .orElse("// Decompilation produced no output");
    HighFunction highFunction = decompResult.getHighFunction();
    Integer basicBlockCount =
        includeAst && highFunction != null ? highFunction.getBasicBlocks().size() : null;
    List<Map<String, Object>> pcodeOperations =
        includePcode && highFunction != null ? collectPcodeOperations(highFunction) : null;
    return snapshots.put(
        program,
        function.getName(),
        function.getEntryPoint().toString(),
        code,
        (int) function.getBody().getNumAddresses(),
        basicBlockCount,
        pcodeOperations);
  }

  private DecompilationResult renderSnapshot(
      DecompilationSnapshots.Snapshot snapshot,
      boolean includePcode,
      boolean includeAst,
      int startLine,
      int maxLines,
      TextSearchOptions searchOptions) {
    String code = snapshot.code();
    DecompilationResult result;
    if (searchOptions != null) {
      TextSearch search =
          TextSearch.of(
              code,
              searchOptions.query(),
              searchOptions.caseSensitive(),
              searchOptions.contextLines(),
              searchOptions.matchOffset(),
              searchOptions.maxMatches());
      result =
          new DecompilationResult(
              snapshot.targetName(),
              snapshot.entryAddress(),
              search.excerpt(),
              snapshot.bodySize());
      result.setCodeSearch(searchOptions.query(), search);
    } else {
      TextWindow window = TextWindow.of(code, startLine, maxLines);
      if (startLine > window.totalLines()) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_START_LINE, startLine, "past end of " + window.totalLines() + " lines"));
      }
      result =
          new DecompilationResult(
              snapshot.targetName(), snapshot.entryAddress(), window.text(), snapshot.bodySize());
      result.setCodeWindow(window.startLine(), window.totalLines(), window.nextLine());
    }

    result.setDecompilationId(snapshot.id());
    if (includePcode) {
      result.setPcodeOperations(snapshot.pcodeOperations());
    }
    if (includeAst) {
      result.setBasicBlockCount(snapshot.basicBlockCount());
    }

    return result;
  }

  private List<Map<String, Object>> collectPcodeOperations(HighFunction highFunc) {
    return StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(highFunc.getPcodeOps(), Spliterator.ORDERED), false)
        .limit(100)
        .map(
            op ->
                Map.<String, Object>of(
                    "opcode", op.getOpcode(),
                    "mnemonic", op.getMnemonic(),
                    "sequence", op.getSeqnum().getTime(),
                    "address", op.getSeqnum().getTarget().toString(),
                    "operation", op.toString()))
        .collect(Collectors.toList());
  }

  private String describeDecompilationFailure(Throwable throwable) {
    if (throwable == null) {
      return "Unknown decompilation error";
    }

    String message = throwable.getMessage();
    if (message == null || message.isBlank()) {
      return throwable.getClass().getSimpleName();
    }

    return throwable.getClass().getSimpleName() + ": " + message;
  }

  // =================== Listing Action ===================

  private Mono<? extends Object> executeListing(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    // Determine which viewing mode: address-based or function-based
    if (args.containsKey(ARG_ADDRESS)) {
      if (args.containsKey(ARG_END_ADDRESS)) {
        return handleAddressRange(program, args, annotation);
      } else {
        return handleSingleAddress(program, args, annotation);
      }
    } else if (args.containsKey(ARG_NAME) || args.containsKey(ARG_SYMBOL_ID)) {
      return handleFunction(program, args, annotation);
    } else {
      // No silent default — require explicit target
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.of(
                  "Listing target is missing", "Provide one of: address, name, or symbol_id")));
    }
  }

  private Mono<? extends Object> handleSingleAddress(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String addressStr;
    try {
      addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }
    return parseAddress(program, addressStr, "inspect.listing_single")
        .flatMap(
            addressResult ->
                Mono.fromCallable(
                    () -> {
                      Address address = addressResult.getAddress();
                      Listing listing = program.getListing();
                      CodeUnit codeUnit = listing.getCodeUnitAt(address);

                      if (codeUnit == null) {
                        throw new GhidraMcpException(
                            GhidraMcpError.resourceNotFound()
                                .errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
                                .message("No code found at address: " + address)
                                .context(
                                    new GhidraMcpError.ErrorContext(
                                        annotation.mcpName(),
                                        "listing lookup",
                                        args,
                                        Map.of(ARG_ADDRESS, address.toString()),
                                        Map.of()))
                                .suggestions(
                                    List.of(
                                        new GhidraMcpError.ErrorSuggestion(
                                            GhidraMcpError.ErrorSuggestion.SuggestionType
                                                .CHECK_RESOURCES,
                                            "Try a different address",
                                            "Use memory (action: list_blocks) to find valid"
                                                + " addresses",
                                            null,
                                            List.of("memory"))))
                                .build());
                      }

                      // Render to objdump-style text — same shape as range/function listings
                      // so callers get a uniform output regardless of how they targeted it.
                      ListingInfo info = createListingInfo(program, codeUnit);
                      String rendered = renderListingText(info).orElse("");
                      return ToolOutcome.of(
                          new CursorDataResult<>(rendered, null),
                          NavigateToAddressEffect.listing(program, address));
                    }));
  }

  private Mono<? extends Object> handleFunction(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    return Mono.fromCallable(
        () -> {
          FunctionManager functionManager = program.getFunctionManager();
          SymbolTable symbolTable = program.getSymbolTable();

          Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
          String functionSelector =
              getOptionalStringArgument(args, ARG_NAME).map(String::trim).orElse("");

          Function function = null;

          if (symbolIdOpt.isPresent()) {
            Symbol symbol = symbolTable.getSymbol(symbolIdOpt.get());
            if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
              function = functionManager.getFunctionAt(symbol.getAddress());
            }
            if (function == null && functionSelector.isBlank()) {
              throw new GhidraMcpException(
                  GhidraMcpError.notFound("function", "symbol_id=" + symbolIdOpt.get()));
            }
          }

          if (function == null && functionSelector.isBlank()) {
            throw new GhidraMcpException(
                GhidraMcpError.of(
                    "Function target is missing",
                    "Provide one of: name (name/address/pattern) or symbol_id"));
          }

          if (function == null) {
            Optional<Address> selectorAddress =
                GhidraAddressParser.tryParse(program, functionSelector);
            if (selectorAddress.isPresent()) {
              Address asAddress = selectorAddress.get();
              function = functionManager.getFunctionContaining(asAddress);
            }
          }

          if (function == null) {
            function = SymbolLookupHelper.resolveFunction(program, functionSelector);
          }

          CursorDataResult<String> result =
              listListingInRange(
                  program,
                  function.getEntryPoint(),
                  function.getBody().getMaxAddress(),
                  args,
                  annotation);
          return ToolOutcome.of(
              result, NavigateToAddressEffect.listing(program, function.getEntryPoint()));
        });
  }

  private Mono<? extends Object> handleAddressRange(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String startStr;
    String endStr;
    try {
      startStr = getRequiredStringArgument(args, ARG_ADDRESS);
      endStr = getRequiredStringArgument(args, ARG_END_ADDRESS);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    Mono<AddressResult> startMono = parseAddress(program, startStr, "inspect.listing_range_start");
    Mono<AddressResult> endMono = parseAddress(program, endStr, "inspect.listing_range_end");

    return startMono.flatMap(
        startResult ->
            endMono.flatMap(
                endResult -> {
                  Address startAddr = startResult.getAddress();
                  Address endAddr = endResult.getAddress();

                  if (startAddr.compareTo(endAddr) > 0) {
                    return Mono.error(
                        new GhidraMcpException(
                            GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                .message("Start address is after end address")
                                .context(
                                    new GhidraMcpError.ErrorContext(
                                        annotation.mcpName(),
                                        "range validation",
                                        args,
                                        Map.of(
                                            ARG_ADDRESS, startStr,
                                            ARG_END_ADDRESS, endStr),
                                        Map.of()))
                                .suggestions(
                                    List.of(
                                        new GhidraMcpError.ErrorSuggestion(
                                            GhidraMcpError.ErrorSuggestion.SuggestionType
                                                .FIX_REQUEST,
                                            "Swap addresses if needed",
                                            "Ensure address <= end_address",
                                            null,
                                            null)))
                                .build()));
                  }

                  return Mono.fromCallable(
                      () -> {
                        CursorDataResult<String> result =
                            listListingInRange(program, startAddr, endAddr, args, annotation);
                        return ToolOutcome.of(
                            result, NavigateToAddressEffect.listing(program, startAddr));
                      });
                }));
  }

  private CursorDataResult<String> listListingInRange(
      Program program,
      Address startAddr,
      Address endAddr,
      Map<String, Object> args,
      GhidraMcpTool annotation)
      throws GhidraMcpException {
    Listing listing = program.getListing();
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int maxLines = getOptionalIntArgument(args, ARG_MAX_LINES).orElse(DEFAULT_MAX_LINES);

    // Determine effective start address based on cursor
    Address effectiveStart = startAddr;
    if (cursorOpt.isPresent()) {
      String cursorValue = cursorOpt.get();
      String decodedCursorAddress =
          decodeOpaqueCursorSingleV1(cursorValue, ARG_CURSOR, "v1:<base64url_listing_address>");
      Address cursorAddr = program.getAddressFactory().getAddress(decodedCursorAddress);
      if (cursorAddr == null) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(ARG_CURSOR, cursorValue, "cursor must be a valid address"));
      }

      if (cursorAddr.compareTo(startAddr) < 0 || cursorAddr.compareTo(endAddr) > 0) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR, cursorValue, "cursor is outside the requested address range"));
      }

      // Start from just after the cursor address (cursor points to last item returned)
      try {
        effectiveStart = cursorAddr.add(1);
      } catch (Exception e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR, cursorValue, "cursor cannot be advanced within this address space"));
      }
    }

    List<ListingInfo> results = new ArrayList<>();

    // Get the first code unit at or after the effective start
    CodeUnit codeUnit = listing.getCodeUnitContaining(effectiveStart);
    if (codeUnit == null) {
      codeUnit = listing.getCodeUnitAfter(effectiveStart);
    } else if (codeUnit.getMinAddress().compareTo(effectiveStart) < 0) {
      // Code unit contains effectiveStart but starts before it - get the next one
      codeUnit = listing.getCodeUnitAfter(codeUnit.getMaxAddress());
    }

    // Collect items up to maxLines + 1 to determine if there are more
    while (codeUnit != null
        && codeUnit.getMinAddress().compareTo(endAddr) <= 0
        && results.size() <= maxLines) {
      try {
        results.add(createListingInfo(program, codeUnit));
        codeUnit = listing.getCodeUnitAfter(codeUnit.getMaxAddress());
      } catch (Exception e) {
        throw new GhidraMcpException(
            GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.OPERATION_FAILED)
                .message(
                    "Failed to read listing entry at address "
                        + codeUnit.getMinAddress()
                        + ": "
                        + e.getMessage())
                .context(
                    new GhidraMcpError.ErrorContext(
                        this.getMcpName(),
                        "list_listing_in_range",
                        args,
                        Map.of("failed_address", codeUnit.getMinAddress().toString()),
                        null))
                .build());
      }
    }

    // Determine if there are more results
    boolean hasMore = results.size() > maxLines;
    if (hasMore) {
      results = results.subList(0, maxLines);
    }

    String nextCursor = null;
    if (hasMore && !results.isEmpty()) {
      nextCursor = OpaqueCursorCodec.encodeV1(results.get(results.size() - 1).getAddress());
    }

    return new CursorDataResult<>(renderListingText(results).orElse(""), nextCursor);
  }

  private ListingInfo createListingInfo(Program program, CodeUnit codeUnit) {
    String address = codeUnit.getMinAddress().toString();
    String label = null;
    String byteString = formatCodeUnitBytes(codeUnit);
    String instruction = null;
    String mnemonic = null;
    String operands = null;
    String dataRepresentation = null;
    String type;
    Integer length = codeUnit.getLength();
    String functionName = null;
    String comment = null;
    try {
      comment = codeUnit.getComment(CommentType.EOL);
    } catch (Exception e) {
      // Comment API may have changed, ignore
    }

    // Get function context
    FunctionManager functionManager = program.getFunctionManager();
    Function containingFunction = functionManager.getFunctionContaining(codeUnit.getMinAddress());
    if (containingFunction != null) {
      functionName = containingFunction.getName();
    }

    // Get label if exists
    ghidra.program.model.symbol.Symbol primarySymbol =
        program.getSymbolTable().getPrimarySymbol(codeUnit.getMinAddress());
    if (primarySymbol != null) {
      label = primarySymbol.getName();
    }

    if (codeUnit instanceof Instruction) {
      Instruction instr = (Instruction) codeUnit;
      type = "instruction";
      mnemonic = instr.getMnemonicString();
      operands = formatInstructionOperands(instr);
      instruction = operands == null || operands.isBlank() ? mnemonic : mnemonic + " " + operands;
    } else if (codeUnit instanceof Data) {
      Data data = (Data) codeUnit;
      type = "data";
      dataRepresentation = data.getDefaultValueRepresentation();
      instruction = dataRepresentation;
    } else {
      type = "unknown";
    }

    return new ListingInfo(
        address,
        label,
        byteString,
        instruction,
        mnemonic,
        operands,
        dataRepresentation,
        type,
        length,
        functionName,
        comment);
  }

  private Optional<String> renderDecompileText(Object data) {
    if (data instanceof String text && !text.isBlank()) {
      return Optional.of(text);
    }
    if (data instanceof DecompilationResult result) {
      return Optional.ofNullable(result.getDecompiledCode()).filter(code -> !code.isBlank());
    }
    if (data instanceof Map<?, ?> map) {
      Object decompiledCode = map.get("decompiled_code");
      if (decompiledCode instanceof String code && !code.isBlank()) {
        return Optional.of(code);
      }
    }
    return Optional.empty();
  }

  private Optional<String> renderListingText(Object data) {
    if (data instanceof String text && !text.isBlank()) {
      return Optional.of(text);
    }
    if (data instanceof ListingInfo listingInfo) {
      return Optional.of(
          renderListingLine(
              listingInfo,
              listingInfo.getByteString() != null ? listingInfo.getByteString().length() : 0));
    }
    if (!(data instanceof List<?> rows) || rows.isEmpty()) {
      return Optional.empty();
    }

    List<ListingInfo> listings =
        rows.stream().filter(ListingInfo.class::isInstance).map(ListingInfo.class::cast).toList();
    if (listings.isEmpty()) {
      return Optional.empty();
    }

    int byteColumnWidth =
        listings.stream()
            .map(ListingInfo::getByteString)
            .filter(bytes -> bytes != null && !bytes.isBlank())
            .mapToInt(String::length)
            .max()
            .orElse(0);

    return Optional.of(
        listings.stream()
            .map(listing -> renderListingLine(listing, byteColumnWidth))
            .collect(Collectors.joining("\n")));
  }

  private String renderListingLine(ListingInfo listing, int byteColumnWidth) {
    StringBuilder line = new StringBuilder(listing.getAddress());

    if (byteColumnWidth > 0) {
      line.append(' ');
      String bytes = Optional.ofNullable(listing.getByteString()).orElse("");
      line.append(String.format("%-" + byteColumnWidth + "s", bytes));
    }

    String body;
    if ("instruction".equals(listing.getType())) {
      String mnemonic = Optional.ofNullable(listing.getMnemonic()).orElse("");
      String operands = Optional.ofNullable(listing.getOperands()).orElse("");
      body = operands.isBlank() ? mnemonic : mnemonic + " " + operands;
    } else {
      body = Optional.ofNullable(listing.getDataRepresentation()).orElse(listing.getType());
    }

    if (!body.isBlank()) {
      line.append(' ').append(body);
    }
    if (listing.getComment() != null && !listing.getComment().isBlank()) {
      line.append(" ; ").append(listing.getComment());
    }

    return line.toString().stripTrailing();
  }

  private String renderReferencesText(List<ReferenceInfo> references, boolean referencesToMode) {
    if (references.isEmpty()) {
      return "(no references)";
    }

    int addressWidth =
        references.stream()
            .map(
                reference ->
                    referencesToMode ? reference.getFromAddress() : reference.getToAddress())
            .filter(address -> address != null && !address.isBlank())
            .mapToInt(String::length)
            .max()
            .orElse(0);

    int typeWidth =
        references.stream()
            .map(ReferenceInfo::getReferenceType)
            .filter(type -> type != null && !type.isBlank())
            .mapToInt(String::length)
            .max()
            .orElse(0);

    return references.stream()
        .map(reference -> renderReferenceLine(reference, referencesToMode, addressWidth, typeWidth))
        .collect(Collectors.joining("\n"));
  }

  private String renderReferenceLine(
      ReferenceInfo reference, boolean referencesToMode, int addressWidth, int typeWidth) {
    String endpointAddress =
        referencesToMode ? reference.getFromAddress() : reference.getToAddress();
    String endpointSymbol = referencesToMode ? reference.getFromSymbol() : reference.getToSymbol();

    StringBuilder line = new StringBuilder();
    line.append(
        String.format(
            "%-" + Math.max(addressWidth, 1) + "s",
            Optional.ofNullable(endpointAddress).orElse("")));

    String referenceType = Optional.ofNullable(reference.getReferenceType()).orElse("");
    if (!referenceType.isBlank()) {
      line.append(' ').append(String.format("%-" + Math.max(typeWidth, 1) + "s", referenceType));
    }

    if (endpointSymbol != null && !endpointSymbol.isBlank()) {
      line.append(' ').append(endpointSymbol);
    }

    return line.toString().stripTrailing();
  }

  private String formatInstructionOperands(Instruction instruction) {
    int operandCount = instruction.getNumOperands();
    if (operandCount <= 0) {
      return null;
    }

    StringBuilder builder = new StringBuilder();
    for (int operandIndex = 0; operandIndex < operandCount; operandIndex++) {
      String separator = Optional.ofNullable(instruction.getSeparator(operandIndex)).orElse("");
      String operand =
          Optional.ofNullable(instruction.getDefaultOperandRepresentation(operandIndex)).orElse("");

      if (!separator.isEmpty()) {
        builder.append(separator);
      }
      builder.append(operand);
    }

    String trailingSeparator =
        Optional.ofNullable(instruction.getSeparator(operandCount)).orElse("");
    if (!trailingSeparator.isEmpty()) {
      builder.append(trailingSeparator);
    }

    String operands = builder.toString().trim();
    return operands.isEmpty() ? null : operands;
  }

  private String formatCodeUnitBytes(CodeUnit codeUnit) {
    try {
      byte[] bytes = codeUnit.getBytes();
      if (bytes == null || bytes.length == 0) {
        return null;
      }

      StringBuilder builder = new StringBuilder(bytes.length * 3 - 1);
      for (int i = 0; i < bytes.length; i++) {
        if (i > 0) {
          builder.append(' ');
        }
        builder.append(String.format("%02x", Byte.toUnsignedInt(bytes[i])));
      }
      return builder.toString();
    } catch (Exception e) {
      return null;
    }
  }

  // =================== References Actions ===================

  private Mono<? extends Object> executeReferences(
      Program program,
      Map<String, Object> args,
      GhidraMcpTool annotation,
      boolean referencesToMode) {
    String addressStr;
    try {
      addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }
    String referenceType = getOptionalStringArgument(args, ARG_REFERENCE_TYPE).orElse("");
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

    return parseAddress(program, addressStr, "inspect.references")
        .flatMap(
            addressResult -> {
              if (referencesToMode) {
                return findReferencesTo(
                    program,
                    addressResult.getAddress(),
                    referenceType,
                    cursorOpt,
                    pageSize,
                    args,
                    annotation);
              } else {
                return findReferencesFrom(
                    program,
                    addressResult.getAddress(),
                    referenceType,
                    cursorOpt,
                    pageSize,
                    args,
                    annotation);
              }
            });
  }

  private Mono<CursorDataResult<String>> findReferencesTo(
      Program program,
      Address address,
      String referenceType,
      Optional<String> cursorOpt,
      int pageSize,
      Map<String, Object> args,
      GhidraMcpTool annotation) {
    return Mono.fromCallable(
        () -> {
          ReferenceManager refManager = program.getReferenceManager();

          // Native early-exit when nothing references this address. Empty results return a
          // literal "(no references)" so callers don't conflate empty with a missing payload.
          if (!refManager.hasReferencesTo(address)) {
            return new CursorDataResult<>("(no references)", null);
          }

          try {
            ReferenceIterator refIterator = refManager.getReferencesTo(address);
            List<ReferenceInfo> allReferences = new ArrayList<>();
            while (refIterator.hasNext()) {
              Reference ref = refIterator.next();

              // Apply reference type filter
              if (referenceType.isEmpty()
                  || ref.getReferenceType().toString().equalsIgnoreCase(referenceType)) {
                allReferences.add(new ReferenceInfo(program, ref));
              }
            }

            allReferences.sort(
                Comparator.comparing(ReferenceInfo::getFromAddress, String.CASE_INSENSITIVE_ORDER)
                    .thenComparing(ReferenceInfo::getToAddress, String.CASE_INSENSITIVE_ORDER)
                    .thenComparing(ReferenceInfo::getReferenceType, String.CASE_INSENSITIVE_ORDER));

            int startIndex = resolveCursorStartIndex(cursorOpt, allReferences, true);
            int endExclusive = Math.min(allReferences.size(), startIndex + pageSize + 1);
            List<ReferenceInfo> paginatedReferences =
                new ArrayList<>(allReferences.subList(startIndex, endExclusive));

            boolean hasMore = paginatedReferences.size() > pageSize;
            List<ReferenceInfo> results =
                hasMore
                    ? new ArrayList<>(paginatedReferences.subList(0, pageSize))
                    : new ArrayList<>(paginatedReferences);

            String nextCursor = null;
            if (hasMore && !results.isEmpty()) {
              nextCursor = buildReferencesToCursor(results.get(results.size() - 1));
            }

            return new CursorDataResult<>(renderReferencesText(results, true), nextCursor);
          } catch (GhidraMcpException e) {
            throw e;
          } catch (Exception e) {
            throw buildXrefAnalysisException(
                annotation, args, "references_to", address.toString(), 0, e);
          }
        });
  }

  private Mono<CursorDataResult<String>> findReferencesFrom(
      Program program,
      Address address,
      String referenceType,
      Optional<String> cursorOpt,
      int pageSize,
      Map<String, Object> args,
      GhidraMcpTool annotation) {
    return Mono.fromCallable(
        () -> {
          ReferenceManager refManager = program.getReferenceManager();

          // Native early-exit; same "(no references)" sentinel as references_to.
          if (!refManager.hasReferencesFrom(address)) {
            return new CursorDataResult<>("(no references)", null);
          }

          Reference[] referencesArray = refManager.getReferencesFrom(address);

          try {
            List<ReferenceInfo> allReferences = new ArrayList<>();
            if (referencesArray != null) {
              for (Reference ref : referencesArray) {
                // Apply reference type filter
                if (referenceType.isEmpty()
                    || ref.getReferenceType().toString().equalsIgnoreCase(referenceType)) {
                  allReferences.add(new ReferenceInfo(program, ref));
                }
              }
            }

            allReferences.sort(
                Comparator.comparing(ReferenceInfo::getToAddress, String.CASE_INSENSITIVE_ORDER)
                    .thenComparing(ReferenceInfo::getFromAddress, String.CASE_INSENSITIVE_ORDER)
                    .thenComparing(ReferenceInfo::getReferenceType, String.CASE_INSENSITIVE_ORDER));

            int startIndex = resolveCursorStartIndex(cursorOpt, allReferences, false);
            int endExclusive = Math.min(allReferences.size(), startIndex + pageSize + 1);
            List<ReferenceInfo> paginatedReferences =
                new ArrayList<>(allReferences.subList(startIndex, endExclusive));

            boolean hasMore = paginatedReferences.size() > pageSize;
            List<ReferenceInfo> results =
                hasMore
                    ? new ArrayList<>(paginatedReferences.subList(0, pageSize))
                    : new ArrayList<>(paginatedReferences);

            String nextCursor = null;
            if (hasMore && !results.isEmpty()) {
              nextCursor = buildReferencesFromCursor(results.get(results.size() - 1));
            }

            return new CursorDataResult<>(renderReferencesText(results, false), nextCursor);
          } catch (GhidraMcpException e) {
            throw e;
          } catch (Exception e) {
            throw buildXrefAnalysisException(
                annotation, args, "references_from", address.toString(), 0, e);
          }
        });
  }

  private GhidraMcpException buildXrefAnalysisException(
      GhidraMcpTool annotation,
      Map<String, Object> args,
      String operation,
      String normalizedAddress,
      int referencesCollected,
      Exception cause) {
    return new GhidraMcpException(
        GhidraMcpError.execution()
            .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
            .message("Failed during cross-reference analysis: " + cause.getMessage())
            .context(
                new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    operation,
                    args,
                    Map.of(ARG_ADDRESS, normalizedAddress),
                    Map.of("references_collected", referencesCollected)))
            .suggestions(
                List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                        "Verify program state and memory accessibility",
                        "Check that the program is properly loaded and the address is valid",
                        null,
                        null)))
            .build());
  }

  private int resolveCursorStartIndex(
      Optional<String> cursorOpt, List<ReferenceInfo> references, boolean referencesToMode) {
    if (cursorOpt.isEmpty()) {
      return 0;
    }

    String cursor = cursorOpt.get();
    List<String> cursorParts =
        decodeOpaqueCursorV1(
            cursor,
            3,
            ARG_CURSOR,
            "v1:<base64url_primary_address>:<base64url_secondary_address>"
                + ":<base64url_reference_type>");

    String cursorFirst = cursorParts.get(0);
    String cursorSecond = cursorParts.get(1);
    String cursorType = cursorParts.get(2);

    for (int i = 0; i < references.size(); i++) {
      ReferenceInfo info = references.get(i);

      String first = referencesToMode ? info.getFromAddress() : info.getToAddress();
      String second = referencesToMode ? info.getToAddress() : info.getFromAddress();
      String type = info.getReferenceType();

      if (first.equalsIgnoreCase(cursorFirst)
          && second.equalsIgnoreCase(cursorSecond)
          && type.equalsIgnoreCase(cursorType)) {
        return i + 1;
      }
    }

    throw new GhidraMcpException(
        GhidraMcpError.invalid(
            ARG_CURSOR, cursor, "cursor is invalid or no longer present in this reference set"));
  }

  private String buildReferencesToCursor(ReferenceInfo info) {
    return OpaqueCursorCodec.encodeV1(
        info.getFromAddress(), info.getToAddress(), info.getReferenceType());
  }

  private String buildReferencesFromCursor(ReferenceInfo info) {
    return OpaqueCursorCodec.encodeV1(
        info.getToAddress(), info.getFromAddress(), info.getReferenceType());
  }
}
