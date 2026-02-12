package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.MemoryBlockInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Read Memory Blocks",
    description = "List memory blocks in a Ghidra program with pagination and filtering options.",
    mcpName = "read_memory_blocks",
    mcpDescription =
        """
        <use_case>
        Browse and list memory blocks in Ghidra programs with optional filtering by name pattern,
        permission flags, and size ranges. Returns paginated results with detailed memory block
        information including addresses, sizes, and permissions.
        </use_case>

        <important_notes>
        - Results are paginated to prevent overwhelming responses
        - Supports filtering by name patterns and permission flags
        - Memory blocks are sorted by start address for consistent ordering
        - Returns detailed memory block information including read/write/execute permissions
        </important_notes>

        <examples>
        List first page of memory blocks:
        {
          "file_name": "program.exe"
        }

        List memory blocks with name filter:
        {
          "file_name": "program.exe",
          "name_filter": ".text"
        }

        Filter by permissions:
        {
          "file_name": "program.exe",
          "executable": true
        }

        Get next page of results:
        {
          "file_name": "program.exe",
          "cursor": "0x401000"
        }
        </examples>
        """)
public class ReadMemoryBlocksTool extends BaseMcpTool {

  public static final String ARG_NAME_FILTER = "name_filter";
  public static final String ARG_READABLE = "readable";
  public static final String ARG_WRITABLE = "writable";
  public static final String ARG_EXECUTABLE = "executable";
  public static final String ARG_MIN_SIZE = "min_size";
  public static final String ARG_MAX_SIZE = "max_size";

  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_NAME_FILTER,
        SchemaBuilder.string(mapper)
            .description("Filter memory blocks by name (case-insensitive substring match)"));

    schemaRoot.property(
        ARG_READABLE, SchemaBuilder.bool(mapper).description("Filter by read permission"));

    schemaRoot.property(
        ARG_WRITABLE, SchemaBuilder.bool(mapper).description("Filter by write permission"));

    schemaRoot.property(
        ARG_EXECUTABLE, SchemaBuilder.bool(mapper).description("Filter by execute permission"));

    schemaRoot.property(
        ARG_MIN_SIZE, SchemaBuilder.integer(mapper).description("Minimum block size in bytes"));

    schemaRoot.property(
        ARG_MAX_SIZE, SchemaBuilder.integer(mapper).description("Maximum block size in bytes"));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper).description("Pagination cursor from previous request"));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description(
                "Number of memory blocks to return per page (default: "
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
              return Mono.fromCallable(() -> listMemoryBlocks(program, args));
            });
  }

  private PaginatedResult<MemoryBlockInfo> listMemoryBlocks(
      Program program, Map<String, Object> args) throws GhidraMcpException {
    Memory memory = program.getMemory();

    Optional<String> nameFilterOpt = getOptionalStringArgument(args, ARG_NAME_FILTER);
    Optional<Boolean> readableOpt = getOptionalBooleanArgument(args, ARG_READABLE);
    Optional<Boolean> writableOpt = getOptionalBooleanArgument(args, ARG_WRITABLE);
    Optional<Boolean> executableOpt = getOptionalBooleanArgument(args, ARG_EXECUTABLE);
    Optional<Long> minSizeOpt = getOptionalLongArgument(args, ARG_MIN_SIZE);
    Optional<Long> maxSizeOpt = getOptionalLongArgument(args, ARG_MAX_SIZE);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int pageSize =
        getOptionalIntArgument(args, ARG_PAGE_SIZE)
            .filter(size -> size > 0)
            .map(size -> Math.min(size, MAX_PAGE_LIMIT))
            .orElse(DEFAULT_PAGE_LIMIT);

    // Get all memory blocks and apply filters
    List<MemoryBlockInfo> allMemoryBlocks =
        Arrays.stream(memory.getBlocks())
            .filter(
                block -> {
                  // Apply name filter
                  if (nameFilterOpt.isPresent() && !nameFilterOpt.get().isEmpty()) {
                    if (!block
                        .getName()
                        .toLowerCase()
                        .contains(nameFilterOpt.get().toLowerCase())) {
                      return false;
                    }
                  }

                  // Apply permission filters
                  if (readableOpt.isPresent() && block.isRead() != readableOpt.get()) {
                    return false;
                  }

                  if (writableOpt.isPresent() && block.isWrite() != writableOpt.get()) {
                    return false;
                  }

                  if (executableOpt.isPresent() && block.isExecute() != executableOpt.get()) {
                    return false;
                  }

                  // Apply size filters
                  long blockSize = block.getSize();
                  if (minSizeOpt.isPresent() && blockSize < minSizeOpt.get()) {
                    return false;
                  }

                  if (maxSizeOpt.isPresent() && blockSize > maxSizeOpt.get()) {
                    return false;
                  }

                  return true;
                })
            .sorted((b1, b2) -> b1.getStart().compareTo(b2.getStart()))
            .map(MemoryBlockInfo::new)
            .collect(Collectors.toList());

    String cursorAddress = cursorOpt.map(this::extractCursorAddress).orElse(null);

    int startIndex = 0;
    if (cursorAddress != null && !cursorAddress.isBlank()) {
      for (int i = 0; i < allMemoryBlocks.size(); i++) {
        if (cursorAddress.equals(allMemoryBlocks.get(i).getStartAddress())) {
          startIndex = i + 1;
          break;
        }
      }
    }

    List<MemoryBlockInfo> paginatedMemoryBlocks;
    if (startIndex >= allMemoryBlocks.size()) {
      paginatedMemoryBlocks = Collections.emptyList();
    } else {
      paginatedMemoryBlocks =
          allMemoryBlocks.stream()
              .skip(startIndex)
              .limit(pageSize + 1L)
              .collect(Collectors.toList());
    }

    boolean hasMore = paginatedMemoryBlocks.size() > pageSize;
    List<MemoryBlockInfo> resultsForPage =
        paginatedMemoryBlocks.subList(0, Math.min(paginatedMemoryBlocks.size(), pageSize));

    String nextCursor = null;
    if (hasMore && !resultsForPage.isEmpty()) {
      MemoryBlockInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
      nextCursor = lastItem.getStartAddress();
    }

    return new PaginatedResult<>(resultsForPage, nextCursor);
  }

  private String extractCursorAddress(String cursor) {
    if (cursor == null || cursor.isBlank()) {
      return "";
    }
    int separator = cursor.indexOf(':');
    if (separator >= 0 && separator < cursor.length() - 1) {
      return cursor.substring(separator + 1);
    }
    return cursor;
  }
}
