package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.MemoryReadResult;
import com.themixednuts.models.MemorySegmentAnalysisResult;
import com.themixednuts.models.MemorySegmentInfo;
import com.themixednuts.models.MemorySegmentsOverview;
import com.themixednuts.models.MemoryWriteResult;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Manage Memory",
    description =
        "Memory CRUD operations: read, write, undefine code units, list segments, and analyze"
            + " memory segment details.",
    mcpName = "manage_memory",
    mcpDescription =
        """
        <use_case>
        Memory operations for reverse engineering. Read and write bytes, define data types at
        addresses, undefine code units, list and analyze memory segments. Essential for understanding
        program structure, applying structs/vtables, patching code, and clearing incorrect disassembly.
        </use_case>

        <important_notes>
        - Read/write operations validate memory accessibility and permissions
        - Memory modifications are transactional and reversible
        - Use SearchMemoryTool for pattern searching
        - Use FindReferencesTool for cross-reference analysis
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

        List memory segments:
        {
          "file_name": "program.exe",
          "action": "list_segments"
        }
        </examples>
        """)
public class ManageMemoryTool extends BaseMcpTool {

  public static final String ARG_BYTES_HEX = "bytes_hex";

  private static final String ACTION_READ = "read";
  private static final String ACTION_WRITE = "write";
  private static final String ACTION_DEFINE = "define";
  private static final String ACTION_UNDEFINE = "undefine";
  private static final String ACTION_LIST_SEGMENTS = "list_segments";
  private static final String ACTION_ANALYZE_SEGMENT = "analyze_segment";

  /**
   * Defines the JSON input schema for memory management operations.
   *
   * @return The JsonSchema defining the expected input arguments
   */
  @Override
  public JsonSchema schema() {
    // Use Draft 7 builder for conditional support
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
                ACTION_LIST_SEGMENTS,
                ACTION_ANALYZE_SEGMENT)
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
        // action=analyze_segment requires address
        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                            .constValue(ACTION_ANALYZE_SEGMENT)),
                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)));

    return schemaRoot.build();
  }

  /**
   * Executes the memory management operation.
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
                case ACTION_LIST_SEGMENTS -> handleListSegments(program, args, annotation);
                case ACTION_ANALYZE_SEGMENT -> handleAnalyzeSegment(program, args, annotation);
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          "action",
                          action,
                          "use: read, write, undefine, list_segments, analyze_segment");
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

  private Mono<? extends Object> handleListSegments(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    return Mono.fromCallable(
        () -> {
          MemoryBlock[] blocks = program.getMemory().getBlocks();
          List<MemorySegmentInfo> segments =
              Arrays.stream(blocks)
                  .map(
                      block ->
                          new MemorySegmentInfo(
                              block.getName(),
                              block.getStart().toString(),
                              block.getEnd().toString(),
                              block.getSize(),
                              getPermissionString(block),
                              block.getType().toString(),
                              block.isInitialized(),
                              block.getComment() != null ? block.getComment() : ""))
                  .sorted(Comparator.comparing(MemorySegmentInfo::getStartAddress))
                  .collect(Collectors.toList());

          return new MemorySegmentsOverview(segments);
        });
  }

  private Mono<? extends Object> handleAnalyzeSegment(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);

    return Mono.fromCallable(
        () -> {
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

          MemoryBlock block = program.getMemory().getBlock(address);
          if (block == null) {
            GhidraMcpError error = GhidraMcpError.notFound("memory segment", addressStr);
            throw new GhidraMcpException(error);
          }

          return new MemorySegmentAnalysisResult(
              block.getName(),
              block.getStart().toString(),
              block.getEnd().toString(),
              block.getSize(),
              getPermissionString(block),
              block.getType().toString(),
              block.isInitialized(),
              block.getComment() != null ? block.getComment() : "",
              block.getSourceName() != null ? block.getSourceName() : "",
              block.isOverlay());
        });
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
              // ASCII printable range: 32-126
              return (b >= 32 && b <= 126) ? String.valueOf((char) b) : ".";
            })
        .collect(Collectors.joining());
  }
}
