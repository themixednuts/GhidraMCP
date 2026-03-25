package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.MemoryBlockInfo;
import com.themixednuts.models.MemoryReadResult;
import com.themixednuts.models.MemoryWriteResult;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.features.base.memsearch.bytesource.ProgramByteSource;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Memory",
    description =
        "Memory operations: read, write, define, undefine, list_blocks, and search memory.",
    mcpName = "memory",
    mcpDescription =
        """
        <use_case>
        Memory operations for reverse engineering. Read and write bytes, define data types at
        addresses, undefine code units, list memory blocks with filtering, and search for patterns.
        Essential for understanding program structure, applying structs/vtables, patching code,
        clearing incorrect disassembly, and finding data in memory.
        </use_case>

        <important_notes>
        - Read/write operations validate memory accessibility and permissions
        - Memory modifications are transactional and reversible
        - list_blocks supports filtering by name, permissions, and size
        - search supports string, hex, binary, decimal, float, double, and regex patterns
        - Use `inspect` (action: references_to/references_from) for cross-reference analysis
        - For memory layout overview, use the ghidra://program/{name}/memory resource
        </important_notes>

        <examples>
        Read memory bytes:
        {
          "file_name": "program.exe",
          "action": "read",
          "address": "0x401000",
          "length": 16
        }

        Write bytes to memory:
        {
          "file_name": "program.exe",
          "action": "write",
          "address": "0x401000",
          "bytes_hex": "4889e5"
        }

        Undefine code unit at address:
        {
          "file_name": "program.exe",
          "action": "undefine",
          "address": "0x401000"
        }

        List memory blocks:
        {
          "file_name": "program.exe",
          "action": "list_blocks"
        }

        Search memory for hex pattern:
        {
          "file_name": "program.exe",
          "action": "search",
          "search_type": "hex",
          "search_value": "55 48 89 e5"
        }
        </examples>
        """)
public class MemoryTool extends BaseMcpTool {

  public static final String ARG_BYTES_HEX = "bytes_hex";
  public static final String ARG_NAME_FILTER = "name_filter";
  public static final String ARG_READABLE = "readable";
  public static final String ARG_WRITABLE = "writable";
  public static final String ARG_EXECUTABLE = "executable";
  public static final String ARG_MIN_SIZE = "min_size";
  public static final String ARG_MAX_SIZE = "max_size";
  public static final String ARG_SEARCH_TYPE = "search_type";
  public static final String ARG_SEARCH_VALUE = "search_value";
  public static final String ARG_CASE_SENSITIVE = "case_sensitive";

  private static final String ACTION_READ = "read";
  private static final String ACTION_WRITE = "write";
  private static final String ACTION_DEFINE = "define";
  private static final String ACTION_UNDEFINE = "undefine";
  private static final String ACTION_LIST_BLOCKS = "list_blocks";
  private static final String ACTION_SEARCH = "search";

  /** Enumeration of supported memory search types. */
  public enum SearchType {
    STRING("string", "Text string search"),
    HEX("hex", "Hexadecimal byte pattern search"),
    BINARY("binary", "Binary pattern search"),
    DECIMAL("decimal", "Decimal number search"),
    FLOAT("float", "32-bit floating point search"),
    DOUBLE("double", "64-bit floating point search"),
    REGEX("regex", "Regular expression pattern search");

    private final String value;
    private final String description;

    SearchType(String value, String description) {
      this.value = value;
      this.description = description;
    }

    public String getValue() {
      return value;
    }

    public String getDescription() {
      return description;
    }

    public static SearchType fromValue(String value) throws GhidraMcpException {
      return Arrays.stream(values())
          .filter(type -> type.value.equalsIgnoreCase(value))
          .findFirst()
          .orElseThrow(
              () ->
                  new GhidraMcpException(
                      GhidraMcpError.validation()
                          .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                          .message("Invalid search type: " + value)
                          .build()));
    }

    public static String[] getValidValues() {
      return Arrays.stream(values()).map(SearchType::getValue).toArray(String[]::new);
    }

    public SearchFormat getSearchFormat() {
      return switch (this) {
        case STRING -> SearchFormat.STRING;
        case BINARY -> SearchFormat.BINARY;
        case DECIMAL -> SearchFormat.DECIMAL;
        case FLOAT -> SearchFormat.FLOAT;
        case DOUBLE -> SearchFormat.DOUBLE;
        case REGEX -> SearchFormat.REG_EX;
        default -> SearchFormat.HEX;
      };
    }
  }

  public static class SearchResult {
    private final String address;
    private final byte[] bytes;
    private final int length;
    private final String searchType;

    public SearchResult(String address, byte[] bytes, int length, String searchType) {
      this.address = address;
      this.bytes = bytes;
      this.length = length;
      this.searchType = searchType;
    }

    public String getAddress() {
      return address;
    }

    public byte[] getBytes() {
      return bytes;
    }

    public int getLength() {
      return length;
    }

    public String getSearchType() {
      return searchType;
    }
  }

  /**
   * Defines the JSON input schema for memory operations.
   *
   * @return The JsonSchema defining the expected input arguments
   */
  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_READ,
                ACTION_WRITE,
                ACTION_DEFINE,
                ACTION_UNDEFINE,
                ACTION_LIST_BLOCKS,
                ACTION_SEARCH)
            .description("Memory operation to perform"));

    schemaRoot.property(
        ARG_ADDRESS,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description("Memory address for read/write operations")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_LENGTH,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
            .description("Number of bytes to read")
            .minimum(1)
            .maximum(4096));

    schemaRoot.property(
        ARG_BYTES_HEX,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description("Hexadecimal bytes to write (e.g., '4889e5')")
            .pattern("^[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_DATA_TYPE_PATH,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description(
                "Data type path to apply at address (e.g., '/MyStruct', 'int', 'char[16]')."
                    + " Used with the 'define' action."));

    schemaRoot.property(
        ARG_DATA_TYPE_ID,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
            .description("Data type ID as alternative to data_type_path for the 'define' action."));

    // list_blocks filter properties
    schemaRoot.property(
        ARG_NAME_FILTER,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description("Filter memory blocks by name (case-insensitive substring match)"));

    schemaRoot.property(
        ARG_READABLE,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.bool(mapper)
            .description("Filter by read permission"));

    schemaRoot.property(
        ARG_WRITABLE,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.bool(mapper)
            .description("Filter by write permission"));

    schemaRoot.property(
        ARG_EXECUTABLE,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.bool(mapper)
            .description("Filter by execute permission"));

    schemaRoot.property(
        ARG_MIN_SIZE,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
            .description("Minimum block size in bytes"));

    schemaRoot.property(
        ARG_MAX_SIZE,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
            .description("Maximum block size in bytes"));

    // search properties
    schemaRoot.property(
        ARG_SEARCH_TYPE,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description("Type of search to perform")
            .enumValues(SearchType.getValidValues()));

    schemaRoot.property(
        ARG_SEARCH_VALUE,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description(
                "Value to search for. Format depends on search type:\n"
                    + "- string: text to find (e.g., 'hello')\n"
                    + "- hex: space-separated hex bytes (e.g., '48 65 6c 6c 6f' for 'Hello')\n"
                    + "- binary: space-separated binary bytes (e.g., '01001000 01100101')\n"
                    + "- decimal: decimal number (e.g., '12345')\n"
                    + "- float: floating point number (e.g., '3.14159')\n"
                    + "- double: double precision number (e.g., '2.718281828')\n"
                    + "- regex: regular expression pattern"));

    schemaRoot.property(
        ARG_CASE_SENSITIVE,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.bool(mapper)
            .description("Whether string/regex searches are case sensitive (default false)"));

    // pagination properties
    schemaRoot.property(
        ARG_CURSOR,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
            .description("Pagination cursor from previous request"));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
            .description(
                "Number of results to return per page (default: "
                    + DEFAULT_PAGE_LIMIT
                    + ", max: "
                    + MAX_PAGE_LIMIT
                    + ")")
            .minimum(1)
            .maximum(MAX_PAGE_LIMIT));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_ACTION);

    // Add conditional requirements based on action (JSON Schema Draft 7)
    schemaRoot.allOf(
        // action=read requires address and length
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_READ)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_LENGTH)),
        // action=write requires address and bytes_hex
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_WRITE)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_BYTES_HEX)),
        // action=define requires address (and data_type_path or data_type_id, validated at runtime)
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_DEFINE)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)),
        // action=undefine requires address
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_UNDEFINE)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)),
        // action=search requires search_type and search_value
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_SEARCH)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SEARCH_TYPE)
                    .requiredProperty(ARG_SEARCH_VALUE)));

    return schemaRoot.build();
  }

  /**
   * Executes the memory operation.
   *
   * @param context The MCP transport context
   * @param args The tool arguments containing file_name, action, and action-specific parameters
   * @param tool The Ghidra PluginTool context
   * @return A Mono emitting the result of the memory operation
   */
  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

    return getProgram(args, tool)
        .flatMap(
            program -> {
              String action = getRequiredStringArgument(args, ARG_ACTION);

              return switch (action.toLowerCase()) {
                case ACTION_READ -> handleRead(program, args, annotation);
                case ACTION_WRITE -> handleWrite(program, args, annotation);
                case ACTION_DEFINE -> handleDefine(program, args);
                case ACTION_UNDEFINE -> handleUndefine(program, args, annotation);
                case ACTION_LIST_BLOCKS -> handleListBlocks(program, args);
                case ACTION_SEARCH -> handleSearch(program, args);
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          "action",
                          action,
                          "use: read, write, define, undefine, list_blocks, search");
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  private Mono<? extends Object> handleRead(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    int length = getRequiredIntArgument(args, ARG_LENGTH);

    return Mono.fromCallable(
        () -> {
          // Validate parameters
          if (length <= 0 || length > 4096) {
            GhidraMcpError error =
                GhidraMcpError.invalid(
                    "length", String.valueOf(length), "must be between 1 and 4096");
            throw new GhidraMcpException(error);
          }

          // Parse address
          Address address;
          try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
              throw new IllegalArgumentException("Invalid address format");
            }
          } catch (Exception e) {
            GhidraMcpError error = GhidraMcpError.parse("address", addressStr);
            throw new GhidraMcpException(error);
          }

          // Read memory
          Memory memory = program.getMemory();
          byte[] bytesRead = new byte[length];
          int actualBytesRead;

          try {
            actualBytesRead = memory.getBytes(address, bytesRead);
          } catch (MemoryAccessException e) {
            GhidraMcpError error =
                GhidraMcpError.failed(
                    "memory read", "address " + addressStr + " is not accessible");
            throw new GhidraMcpException(error);
          }

          // Trim to actual bytes read
          if (actualBytesRead < length) {
            bytesRead = Arrays.copyOf(bytesRead, actualBytesRead);
          }

          // Generate hex representation and readable ASCII
          String hexData = HexFormat.of().formatHex(bytesRead);
          String readable = generateReadableString(bytesRead);

          return new MemoryReadResult(
              address.toString(), actualBytesRead, hexData, readable, length, actualBytesRead);
        });
  }

  private Mono<? extends Object> handleWrite(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    String bytesHex = getRequiredStringArgument(args, ARG_BYTES_HEX);

    return executeInTransaction(
        program,
        "MCP - Write Memory at " + addressStr,
        () -> {
          // Validate hex format
          if (bytesHex.length() % 2 != 0) {
            GhidraMcpError error =
                GhidraMcpError.invalid("bytes_hex", bytesHex, "odd number of characters");
            throw new GhidraMcpException(error);
          }

          // Parse address
          Address address;
          try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
              throw new IllegalArgumentException("Invalid address format");
            }
          } catch (Exception e) {
            GhidraMcpError error = GhidraMcpError.parse("address", addressStr);
            throw new GhidraMcpException(error);
          }

          // Parse hex bytes
          byte[] bytes;
          try {
            bytes = HexFormat.of().parseHex(bytesHex);
          } catch (IllegalArgumentException e) {
            GhidraMcpError error = GhidraMcpError.parse("hex bytes", bytesHex);
            throw new GhidraMcpException(error);
          }

          // Write to memory
          try {
            program.getMemory().setBytes(address, bytes);
            return new MemoryWriteResult(true, address.toString(), bytes.length, bytesHex);
          } catch (MemoryAccessException e) {
            GhidraMcpError error =
                GhidraMcpError.failed("memory write", "address " + addressStr + " is not writable");
            throw new GhidraMcpException(error);
          }
        });
  }

  private Mono<? extends Object> handleDefine(Program program, Map<String, Object> args) {
    String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    String dataTypePath = getOptionalStringArgument(args, ARG_DATA_TYPE_PATH).orElse(null);
    Long dataTypeId = getOptionalLongArgument(args, ARG_DATA_TYPE_ID).orElse(null);

    if (dataTypePath == null && dataTypeId == null) {
      GhidraMcpError error =
          GhidraMcpError.validation()
              .message(
                  "Either data_type_path or data_type_id must be provided for 'define' action.")
              .build();
      return Mono.error(new GhidraMcpException(error));
    }

    return parseAddress(program, addressStr, ACTION_DEFINE)
        .flatMap(
            addressResult ->
                executeInTransaction(
                    program,
                    "MCP - Define data at " + addressStr,
                    () -> {
                      Address address = addressResult.getAddress();
                      DataTypeManager dtm = program.getDataTypeManager();

                      DataType dataType = null;
                      if (dataTypeId != null) {
                        dataType = dtm.getDataType(dataTypeId);
                        if (dataType == null) {
                          throw new GhidraMcpException(
                              GhidraMcpError.notFound("data type", "ID=" + dataTypeId));
                        }
                      } else {
                        dataType = resolveDataTypeWithFallback(dtm, dataTypePath);
                        if (dataType == null) {
                          throw new GhidraMcpException(
                              GhidraMcpError.notFound("data type", dataTypePath));
                        }
                      }

                      try {
                        DataUtilities.createData(
                            program, address, dataType, -1, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                      } catch (Exception e) {
                        throw new GhidraMcpException(
                            GhidraMcpError.failed(
                                "define data",
                                "Could not apply "
                                    + dataType.getName()
                                    + " at "
                                    + addressStr
                                    + ": "
                                    + e.getMessage()),
                            e);
                      }

                      return OperationResult.success(
                              ACTION_DEFINE,
                              address.toString(),
                              "Applied data type '"
                                  + dataType.getPathName()
                                  + "' ("
                                  + dataType.getLength()
                                  + " bytes) at "
                                  + address.toString())
                          .setMetadata(
                              Map.of(
                                  "dataType", dataType.getPathName(),
                                  "dataTypeSize", dataType.getLength()));
                    }));
  }

  private Mono<? extends Object> handleUndefine(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);

    return executeInTransaction(
        program,
        "MCP - Undefine at " + addressStr,
        () -> {
          // Parse address
          Address address;
          try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
              throw new IllegalArgumentException("Invalid address format");
            }
          } catch (Exception e) {
            GhidraMcpError error = GhidraMcpError.parse("address", addressStr);
            throw new GhidraMcpException(error);
          }

          // Clear code units at the address
          try {
            program.getListing().clearCodeUnits(address, address, false);
            return "Successfully cleared code unit definition at address " + address.toString();
          } catch (Exception e) {
            GhidraMcpError error =
                GhidraMcpError.failed("undefine", "could not clear code units at " + addressStr);
            throw new GhidraMcpException(error);
          }
        });
  }

  private Mono<? extends Object> handleListBlocks(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          Memory memory = program.getMemory();

          Optional<String> nameFilterOpt = getOptionalStringArgument(args, ARG_NAME_FILTER);
          Optional<Boolean> readableOpt = getOptionalBooleanArgument(args, ARG_READABLE);
          Optional<Boolean> writableOpt = getOptionalBooleanArgument(args, ARG_WRITABLE);
          Optional<Boolean> executableOpt = getOptionalBooleanArgument(args, ARG_EXECUTABLE);
          Optional<Long> minSizeOpt = getOptionalLongArgument(args, ARG_MIN_SIZE);
          Optional<Long> maxSizeOpt = getOptionalLongArgument(args, ARG_MAX_SIZE);
          Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
          int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

          // Get all memory blocks and apply filters
          List<MemoryBlockInfo> allMemoryBlocks =
              Arrays.stream(memory.getBlocks())
                  .filter(
                      block -> {
                        if (nameFilterOpt.isPresent() && !nameFilterOpt.get().isEmpty()) {
                          if (!block
                              .getName()
                              .toLowerCase()
                              .contains(nameFilterOpt.get().toLowerCase())) {
                            return false;
                          }
                        }

                        if (readableOpt.isPresent() && block.isRead() != readableOpt.get()) {
                          return false;
                        }

                        if (writableOpt.isPresent() && block.isWrite() != writableOpt.get()) {
                          return false;
                        }

                        if (executableOpt.isPresent() && block.isExecute() != executableOpt.get()) {
                          return false;
                        }

                        long blockSize = block.getSize();
                        if (minSizeOpt.isPresent() && blockSize < minSizeOpt.get()) {
                          return false;
                        }

                        if (maxSizeOpt.isPresent() && blockSize > maxSizeOpt.get()) {
                          return false;
                        }

                        return true;
                      })
                  .sorted(Comparator.comparing(MemoryBlock::getStart))
                  .map(MemoryBlockInfo::new)
                  .collect(Collectors.toList());

          String cursorAddress = cursorOpt.map(this::extractBlockCursorAddress).orElse(null);

          int startIndex = 0;
          if (cursorAddress != null && !cursorAddress.isBlank()) {
            boolean cursorMatched = false;
            for (int i = 0; i < allMemoryBlocks.size(); i++) {
              if (cursorAddress.equalsIgnoreCase(allMemoryBlocks.get(i).getStartAddress())) {
                startIndex = i + 1;
                cursorMatched = true;
                break;
              }
            }

            if (!cursorMatched) {
              throw new GhidraMcpException(
                  GhidraMcpError.invalid(
                      ARG_CURSOR,
                      cursorAddress,
                      "cursor is invalid or no longer present in this memory block listing"));
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
            nextCursor = OpaqueCursorCodec.encodeV1(lastItem.getStartAddress());
          }

          return new PaginatedResult<>(resultsForPage, nextCursor);
        });
  }

  private Mono<? extends Object> handleSearch(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          String searchTypeStr = getRequiredStringArgument(args, ARG_SEARCH_TYPE);
          SearchType searchType = SearchType.fromValue(searchTypeStr);

          String searchValue = getRequiredStringArgument(args, ARG_SEARCH_VALUE);
          boolean caseSensitive =
              getOptionalBooleanArgument(args, ARG_CASE_SENSITIVE).orElse(false);
          Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
          int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

          if (searchValue.trim().isEmpty()) {
            throw new GhidraMcpException(
                GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Search value cannot be empty")
                    .context(
                        new GhidraMcpError.ErrorContext(
                            getMcpName(),
                            "search value validation",
                            args,
                            Map.of(ARG_SEARCH_VALUE, searchValue),
                            Map.of("value_length", searchValue.length())))
                    .build());
          }

          // Validate hex format and provide helpful suggestions
          if (searchType == SearchType.HEX) {
            validateHexFormat(searchValue, args);
          }

          // Determine the start address for cursor-based pagination
          Address startAddress = null;
          if (cursorOpt.isPresent()) {
            String cursorAddr = extractSearchCursorAddress(cursorOpt.get());
            try {
              startAddress = program.getAddressFactory().getAddress(cursorAddr);
              if (startAddress == null) {
                throw new GhidraMcpException(
                    GhidraMcpError.invalid(
                        ARG_CURSOR, cursorOpt.get(), "cursor address is not valid"));
              }
              // Move past the cursor address to avoid returning the same match
              startAddress = startAddress.add(1);
            } catch (GhidraMcpException e) {
              throw e;
            } catch (Exception e) {
              throw new GhidraMcpException(
                  GhidraMcpError.invalid(ARG_CURSOR, cursorOpt.get(), "invalid cursor address"));
            }
          }

          SearchSettings settings = new SearchSettings();
          SearchFormat searchFormat = searchType.getSearchFormat();
          settings.withSearchFormat(searchFormat);
          settings.withBigEndian(program.getMemory().isBigEndian());
          settings.withCaseSensitive(caseSensitive);

          ByteMatcher matcher = searchFormat.parse(searchValue, settings);

          if (!matcher.isValidSearch()) {
            throw new GhidraMcpException(
                GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message(
                        "Invalid search value for the given search type: "
                            + matcher.getDescription())
                    .build());
          }

          ProgramByteSource byteSource = new ProgramByteSource(program);
          AddressSetView fullAddressSet = program.getMemory().getLoadedAndInitializedAddressSet();

          if (fullAddressSet.isEmpty()) {
            throw new GhidraMcpException(
                GhidraMcpError.searchNoResults()
                    .errorCode(GhidraMcpError.ErrorCode.NO_SEARCH_RESULTS)
                    .message("No initialized memory regions found in the program")
                    .context(
                        new GhidraMcpError.ErrorContext(
                            getMcpName(),
                            "memory region check",
                            Map.of(
                                "search_value", searchValue, "search_type", searchType.getValue()),
                            Map.of("address_set_size", fullAddressSet.getNumAddresses()),
                            Map.of("program_name", program.getName())))
                    .build());
          }

          // If we have a cursor, restrict the search to addresses after the cursor
          AddressSetView searchAddressSet = fullAddressSet;
          if (startAddress != null) {
            searchAddressSet =
                fullAddressSet.intersectRange(startAddress, fullAddressSet.getMaxAddress());
            if (searchAddressSet.isEmpty()) {
              // No more addresses to search — end of results
              return new PaginatedResult<>(Collections.<SearchResult>emptyList(), null);
            }
          }

          // Request one extra result to determine if there are more pages
          int searchLimit = pageSize + 1;
          MemorySearcher searcher =
              new MemorySearcher(byteSource, matcher, searchAddressSet, searchLimit);

          ListAccumulator<MemoryMatch> accumulator = new ListAccumulator<>();
          searcher.findAll(accumulator, TaskMonitor.DUMMY);

          List<SearchResult> allResults =
              accumulator.stream()
                  .map(
                      match ->
                          new SearchResult(
                              match.getAddress().toString(),
                              match.getBytes(),
                              match.getLength(),
                              searchType.getValue()))
                  .collect(Collectors.toList());

          if (allResults.isEmpty()) {
            throw new GhidraMcpException(
                GhidraMcpError.searchNoResults()
                    .errorCode(GhidraMcpError.ErrorCode.NO_SEARCH_RESULTS)
                    .message("No matches found for the search pattern")
                    .context(
                        new GhidraMcpError.ErrorContext(
                            getMcpName(),
                            "search execution",
                            Map.of(
                                "search_value", searchValue, "search_type", searchType.getValue()),
                            Map.of(
                                "address_set_size",
                                fullAddressSet.getNumAddresses(),
                                "page_size",
                                pageSize),
                            Map.of(
                                "program_name",
                                program.getName(),
                                "endianness",
                                program.getMemory().isBigEndian() ? "big" : "little")))
                    .suggestions(
                        List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Try different search patterns",
                                "Consider trying different hex patterns or search types",
                                List.of(
                                    "Try with spaces: '38 8c 36 49'",
                                    "Try uppercase: '388C3649'",
                                    "Try different search type"),
                                null)))
                    .build());
          }

          boolean hasMore = allResults.size() > pageSize;
          List<SearchResult> resultsForPage =
              allResults.subList(0, Math.min(allResults.size(), pageSize));

          String nextCursor = null;
          if (hasMore && !resultsForPage.isEmpty()) {
            SearchResult lastResult = resultsForPage.get(resultsForPage.size() - 1);
            nextCursor = OpaqueCursorCodec.encodeV1(lastResult.getAddress());
          }

          return new PaginatedResult<>(resultsForPage, nextCursor);
        });
  }

  private String extractBlockCursorAddress(String cursor) {
    if (cursor == null || cursor.isBlank()) {
      return "";
    }
    String decodedAddress =
        decodeOpaqueCursorSingleV1(cursor, ARG_CURSOR, "v1:<base64url_block_start_address>");
    if (!decodedAddress.matches("^(0x)?[0-9a-fA-F]+$")) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, cursor, "cursor must be a valid memory address"));
    }
    return decodedAddress;
  }

  private String extractSearchCursorAddress(String cursor) {
    if (cursor == null || cursor.isBlank()) {
      return "";
    }
    String decodedAddress =
        decodeOpaqueCursorSingleV1(cursor, ARG_CURSOR, "v1:<base64url_match_address>");
    if (!decodedAddress.matches("^(0x)?[0-9a-fA-F]+$")) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, cursor, "cursor must be a valid memory address"));
    }
    return decodedAddress;
  }

  /** Validates hex format and provides helpful suggestions for common format issues. */
  private void validateHexFormat(String searchValue, Map<String, Object> args)
      throws GhidraMcpException {
    String trimmed = searchValue.trim();

    if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
      String withoutPrefix = trimmed.substring(2);
      String suggested = formatHexWithSpaces(withoutPrefix);
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message(
                  "Hex values should not include '0x' prefix. Use space-separated format instead.")
              .context(
                  new GhidraMcpError.ErrorContext(
                      getMcpName(),
                      "hex format validation",
                      args,
                      Map.of(ARG_SEARCH_VALUE, searchValue),
                      Map.of("detected_prefix", "0x", "suggested_format", suggested)))
              .suggestions(
                  List.of(
                      new GhidraMcpError.ErrorSuggestion(
                          GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                          "Use space-separated hex format",
                          "Remove '0x' prefix and add spaces between bytes",
                          List.of(suggested),
                          null)))
              .build());
    }

    if (trimmed.matches("^[0-9a-fA-F]+$") && trimmed.length() > 2 && !trimmed.contains(" ")) {
      String suggested = formatHexWithSpaces(trimmed);
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message("Hex values should be space-separated for proper byte interpretation.")
              .context(
                  new GhidraMcpError.ErrorContext(
                      getMcpName(),
                      "hex format validation",
                      args,
                      Map.of(ARG_SEARCH_VALUE, searchValue),
                      Map.of("detected_format", "continuous", "suggested_format", suggested)))
              .suggestions(
                  List.of(
                      new GhidraMcpError.ErrorSuggestion(
                          GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                          "Add spaces between hex bytes",
                          "Separate each two-digit hex value with a space",
                          List.of(suggested),
                          null)))
              .build());
    }
  }

  /** Formats a continuous hex string into space-separated bytes. */
  private String formatHexWithSpaces(String hexString) {
    if (hexString.length() % 2 != 0) {
      hexString = "0" + hexString;
    }

    StringBuilder result = new StringBuilder();
    for (int i = 0; i < hexString.length(); i += 2) {
      if (result.length() > 0) {
        result.append(" ");
      }
      result.append(hexString.substring(i, i + 2));
    }
    return result.toString();
  }

  private String getPermissionString(MemoryBlock block) {
    return String.format(
        "%s%s%s",
        block.isRead() ? "r" : "-", block.isWrite() ? "w" : "-", block.isExecute() ? "x" : "-");
  }

  private String generateReadableString(byte[] bytes) {
    return IntStream.range(0, bytes.length)
        .mapToObj(
            i -> {
              byte b = bytes[i];
              return (b >= 32 && b <= 126) ? String.valueOf((char) b) : ".";
            })
        .collect(Collectors.joining());
  }
}
