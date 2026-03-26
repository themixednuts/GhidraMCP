package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.common.McpTransportContext;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import mdemangler.MDMangGhidra;
import mdemangler.MDParsableItem;
import reactor.core.publisher.Mono;

/** MCP resource template that provides RTTI class discovery for a program. */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/rtti",
    name = "Program RTTI",
    description =
        "MSVC RTTI type descriptors with class names, method names from lambda RTTI, and type"
            + " classification.",
    mimeType = "application/json",
    template = true)
public class ProgramRttiResource extends BaseMcpResource {

  private static final int MAX_CLASSES = 1000;
  private static final int MAX_RTTI_SCAN = 50000;
  private static final int MAX_STRING_LENGTH = 512;

  private static final byte[] RTTI_PATTERN = new byte[] {0x2e, 0x3f, 0x41};

  @Override
  public Mono<String> read(McpTransportContext context, String uri, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          Map<String, String> params = extractUriParams(uri);
          String programName = params.get("name");

          if (programName == null || programName.isEmpty()) {
            throw new IllegalArgumentException("Program name is required");
          }

          Program program = getProgramByName(programName);
          try {
            Memory memory = program.getMemory();

            // Map from class name to class info
            Map<String, Map<String, Object>> classMap = new TreeMap<>();
            // Map from class name to list of methods discovered via lambda RTTI
            Map<String, List<Map<String, String>>> methodMap = new LinkedHashMap<>();

            // Scan non-executable data sections (.rdata + .data) where RTTI structures live.
            // RTTI0 type descriptors are in .data (writable — the type_info vtable ptr is
            // patched at runtime), while RTTI1-4 and vtables are in .rdata (read-only).
            Address scanStart = memory.getMinAddress();
            Address scanEnd = memory.getMaxAddress();
            MemoryBlock rdataBlock = findRdataBlock(memory);
            MemoryBlock dataBlock = memory.getBlock(".data");
            if (rdataBlock != null && dataBlock != null) {
              // Scan from whichever starts first to whichever ends last
              scanStart =
                  rdataBlock.getStart().compareTo(dataBlock.getStart()) < 0
                      ? rdataBlock.getStart()
                      : dataBlock.getStart();
              scanEnd =
                  rdataBlock.getEnd().compareTo(dataBlock.getEnd()) > 0
                      ? rdataBlock.getEnd()
                      : dataBlock.getEnd();
            } else if (rdataBlock != null) {
              scanStart = rdataBlock.getStart();
              scanEnd = rdataBlock.getEnd();
            } else if (dataBlock != null) {
              scanStart = dataBlock.getStart();
              scanEnd = dataBlock.getEnd();
            }

            int scanCount = 0;
            Address searchAddr = scanStart;

            while (searchAddr != null
                && searchAddr.compareTo(scanEnd) <= 0
                && scanCount < MAX_RTTI_SCAN
                && classMap.size() < MAX_CLASSES) {
              Address found = memory.findBytes(searchAddr, RTTI_PATTERN, null, true, null);
              if (found == null || found.compareTo(scanEnd) > 0) {
                break;
              }
              scanCount++;

              String mangledName = readCString(memory, found, MAX_STRING_LENGTH);
              if (mangledName == null || mangledName.length() < 4) {
                searchAddr = safeNextAddress(found);
                continue;
              }

              // Validate prefix
              String typeKind = classifyTypeKind(mangledName);
              if (typeKind == null) {
                searchAddr = safeNextAddress(found);
                continue;
              }

              // RTTI0 base address = match_address - 16
              Address rtti0Addr;
              try {
                rtti0Addr = found.subtract(16);
              } catch (Exception e) {
                searchAddr = safeNextAddress(found);
                continue;
              }

              // Demangle the type descriptor name
              String demangled = demangle(mangledName);
              String displayName = demangled != null ? demangled : mangledName;

              // Check if this is a lambda RTTI entry
              if (mangledName.contains("<lambda") && mangledName.contains("@??")) {
                processLambdaRtti(mangledName, methodMap);
              }

              // Register the class entry
              if (!classMap.containsKey(mangledName)) {
                Map<String, Object> classInfo = new LinkedHashMap<>();
                classInfo.put("name", displayName);
                classInfo.put("mangled", mangledName);
                classInfo.put("type_kind", typeKind);
                classInfo.put("rtti0_address", rtti0Addr.toString());
                classMap.put(mangledName, classInfo);
              }

              searchAddr = safeNextAddress(found);
            }

            // Second pass: enrich with RTTI4 (Complete Object Locator) data when available
            enrichWithRtti4(program, memory, classMap);

            // Build the output class list, merging method info
            List<Map<String, Object>> classes = new ArrayList<>();
            // First, add all directly discovered classes
            for (var entry : classMap.entrySet()) {
              Map<String, Object> classInfo = new LinkedHashMap<>(entry.getValue());
              String mangledKey = entry.getKey();

              // Find methods for this class by checking the display name
              String className = extractClassNameFromMangled(mangledKey);
              List<Map<String, String>> methods = new ArrayList<>();
              if (className != null) {
                for (var methodEntry : methodMap.entrySet()) {
                  if (methodEntry.getKey().equals(className)) {
                    methods.addAll(methodEntry.getValue());
                  }
                }
              }
              classInfo.put("methods", methods);
              classes.add(classInfo);
            }

            // Add classes only discovered through lambda RTTI (not having their own RTTI0)
            for (var methodEntry : methodMap.entrySet()) {
              String className = methodEntry.getKey();
              boolean alreadyPresent = false;
              for (var entry : classMap.entrySet()) {
                String existingClassName = extractClassNameFromMangled(entry.getKey());
                if (className.equals(existingClassName)) {
                  alreadyPresent = true;
                  break;
                }
              }
              if (!alreadyPresent && classes.size() < MAX_CLASSES) {
                Map<String, Object> classInfo = new LinkedHashMap<>();
                classInfo.put("name", className);
                classInfo.put("mangled", null);
                classInfo.put("type_kind", "class");
                classInfo.put("rtti0_address", null);
                classInfo.put("methods", methodEntry.getValue());
                classes.add(classInfo);
              }
            }

            boolean hasMore = scanCount >= MAX_RTTI_SCAN || classMap.size() >= MAX_CLASSES;

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programName", programName);
            result.put("classes", classes);
            result.put("count", classes.size());
            result.put("hasMore", hasMore);

            return toJson(result);
          } finally {
            program.release(this);
          }
        });
  }

  private String classifyTypeKind(String mangledName) {
    if (mangledName.startsWith(".?AV")) {
      return "class";
    } else if (mangledName.startsWith(".?AU")) {
      return "struct";
    } else if (mangledName.startsWith(".?AT")) {
      return "union";
    } else if (mangledName.startsWith(".?AW4")) {
      return "enum";
    }
    return null;
  }

  private void processLambdaRtti(
      String mangledName, Map<String, List<Map<String, String>>> methodMap) {
    int atQQ = mangledName.indexOf("@??");
    if (atQQ < 0) {
      return;
    }

    // Everything after @?? is the enclosing function's mangled name fragment
    String fragment = mangledName.substring(atQQ + 1);
    // fragment starts with "??" followed by the mangled function name
    if (fragment.length() < 3) {
      return;
    }

    String afterQQ = fragment.substring(2); // skip the "??"

    // Extract method name: characters between start and the next '@'
    int firstAt = afterQQ.indexOf('@');
    if (firstAt <= 0) {
      return;
    }
    String methodName = afterQQ.substring(0, firstAt);

    // Extract class name: characters between that '@' and the next '@' or '@@'
    String afterMethod = afterQQ.substring(firstAt + 1);
    int nextAt = afterMethod.indexOf('@');
    String className;
    if (nextAt > 0) {
      className = afterMethod.substring(0, nextAt);
    } else {
      className = afterMethod;
    }

    // Try to demangle the enclosing function
    String enclosingMangled = "?" + fragment;
    String demangled = demangle(enclosingMangled);

    // Build namespace from class name
    String namespace = className;

    Map<String, String> methodInfo = new LinkedHashMap<>();
    methodInfo.put("name", methodName);
    methodInfo.put("class", className);
    methodInfo.put("namespace", namespace);
    if (demangled != null) {
      methodInfo.put("demangled", demangled);
    }

    methodMap.computeIfAbsent(className, k -> new ArrayList<>()).add(methodInfo);
  }

  private String extractClassNameFromMangled(String mangledName) {
    // Extract the class name from a mangled type descriptor name like .?AVWeapon@Javelin@@
    String prefix = null;
    if (mangledName.startsWith(".?AV")) {
      prefix = ".?AV";
    } else if (mangledName.startsWith(".?AU")) {
      prefix = ".?AU";
    } else if (mangledName.startsWith(".?AT")) {
      prefix = ".?AT";
    } else if (mangledName.startsWith(".?AW4")) {
      prefix = ".?AW4";
    }
    if (prefix == null) {
      return null;
    }

    String rest = mangledName.substring(prefix.length());
    // Class name is the first component before '@'
    int atIdx = rest.indexOf('@');
    if (atIdx > 0) {
      return rest.substring(0, atIdx);
    }
    return rest;
  }

  private String readCString(Memory memory, Address addr, int maxLen) {
    try {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < maxLen; i++) {
        byte b = memory.getByte(addr.add(i));
        if (b == 0) {
          break;
        }
        sb.append((char) (b & 0xff));
      }
      return sb.toString();
    } catch (Exception e) {
      return null;
    }
  }

  private String demangle(String mangled) {
    try {
      MDMangGhidra mdm = new MDMangGhidra();
      mdm.setMangledSymbol(mangled);
      MDParsableItem item = mdm.demangle();
      return item != null ? item.toString() : null;
    } catch (Exception e) {
      return null;
    }
  }

  private Address safeNextAddress(Address addr) {
    try {
      return addr.add(1);
    } catch (Exception e) {
      return null;
    }
  }

  /**
   * Enriches discovered RTTI0 class entries with RTTI4 (Complete Object Locator) data. For each
   * RTTI0 entry, searches for an RTTI4 structure that references it, then follows the RTTI3/RTTI2
   * chain to discover base class hierarchies.
   */
  @SuppressWarnings("unchecked")
  private void enrichWithRtti4(
      Program program, Memory memory, Map<String, Map<String, Object>> classMap) {
    try {
      Address imageBase = program.getImageBase();
      if (imageBase == null) {
        return;
      }

      // Find .rdata section bounds for searching
      MemoryBlock rdataBlock = findRdataBlock(memory);
      if (rdataBlock == null) {
        return;
      }
      Address rdataStart = rdataBlock.getStart();
      Address rdataEnd = rdataBlock.getEnd();

      for (Map.Entry<String, Map<String, Object>> entry : classMap.entrySet()) {
        Map<String, Object> classInfo = entry.getValue();
        String rtti0AddrStr = (String) classInfo.get("rtti0_address");
        if (rtti0AddrStr == null) {
          continue;
        }

        try {
          Address rtti0Addr = program.getAddressFactory().getAddress(rtti0AddrStr);
          if (rtti0Addr == null) {
            continue;
          }

          long rtti0Rva = rtti0Addr.subtract(imageBase);
          byte[] rvaBytes = intToLittleEndianBytes((int) rtti0Rva);

          // Search for this RVA in .rdata — it should appear at offset +12 of an RTTI4
          Address match = memory.findBytes(rdataStart, rdataEnd, rvaBytes, null, true, null);
          while (match != null) {
            try {
              // Candidate RTTI4 starts 12 bytes before the match
              Address rtti4Start = match.subtract(12);

              // Validate signature == 1 (x64 MSVC RTTI4)
              int signature = memory.getInt(rtti4Start);
              if (signature == 1) {
                // Validate pSelf RVA at offset +20 points back to rtti4Start
                int selfRva = memory.getInt(rtti4Start.add(20));
                Address selfAddr = imageBase.add(Integer.toUnsignedLong(selfRva));
                if (selfAddr.equals(rtti4Start)) {
                  // Valid RTTI4 found
                  int vtableOffset = memory.getInt(rtti4Start.add(4));
                  classInfo.put("rtti4_address", rtti4Start.toString());
                  classInfo.put("vtable_offset", vtableOffset);

                  // Follow RTTI3 (Class Hierarchy Descriptor)
                  List<String> baseClasses = readBaseClassHierarchy(memory, imageBase, rtti4Start);
                  if (baseClasses != null && !baseClasses.isEmpty()) {
                    classInfo.put("base_classes", baseClasses);
                  }
                  break;
                }
              }
            } catch (Exception e) {
              // Skip invalid candidate
            }

            match = memory.findBytes(match.add(1), rdataEnd, rvaBytes, null, true, null);
          }
        } catch (Exception e) {
          // Skip this class entry on error
        }
      }
    } catch (Exception e) {
      // RTTI4 enrichment is optional; silently skip on failure
    }
  }

  /** Finds the .rdata memory block, falling back to any read-only initialized data block. */
  private MemoryBlock findRdataBlock(Memory memory) {
    MemoryBlock block = memory.getBlock(".rdata");
    if (block != null) {
      return block;
    }
    // Fallback: look for any block with a name containing "rdata"
    for (MemoryBlock b : memory.getBlocks()) {
      if (b.getName().toLowerCase().contains("rdata") && b.isInitialized()) {
        return b;
      }
    }
    return null;
  }

  /**
   * Reads the base class hierarchy from an RTTI4 structure by following the RTTI3 -> RTTI2 -> RTTI1
   * chain.
   */
  private List<String> readBaseClassHierarchy(
      Memory memory, Address imageBase, Address rtti4Start) {
    try {
      int rtti3Rva = memory.getInt(rtti4Start.add(16));
      Address rtti3Addr = imageBase.add(Integer.toUnsignedLong(rtti3Rva));

      int numBases = memory.getInt(rtti3Addr.add(8));
      if (numBases <= 0 || numBases > 50) {
        return null;
      }

      int rtti2Rva = memory.getInt(rtti3Addr.add(12));
      Address rtti2Addr = imageBase.add(Integer.toUnsignedLong(rtti2Rva));

      List<String> baseClasses = new ArrayList<>();
      // Skip index 0 which is the class itself; start from 1 for base classes
      for (int i = 1; i < numBases; i++) {
        try {
          int rtti1Rva = memory.getInt(rtti2Addr.add((long) i * 4));
          Address rtti1Addr = imageBase.add(Integer.toUnsignedLong(rtti1Rva));

          int baseRtti0Rva = memory.getInt(rtti1Addr);
          Address baseRtti0Addr = imageBase.add(Integer.toUnsignedLong(baseRtti0Rva));

          // Read the type name at baseRtti0Addr + 16 (past the two vtable/spare fields)
          String baseName = readCString(memory, baseRtti0Addr.add(16), MAX_STRING_LENGTH);
          if (baseName != null && baseName.length() >= 4) {
            String baseDemangled = demangle(baseName);
            baseClasses.add(baseDemangled != null ? baseDemangled : baseName);
          }
        } catch (Exception e) {
          // Skip unreadable base class entry
        }
      }
      return baseClasses;
    } catch (Exception e) {
      return null;
    }
  }

  /** Converts an int to a 4-byte little-endian byte array. */
  private byte[] intToLittleEndianBytes(int value) {
    ByteBuffer buffer = ByteBuffer.allocate(4);
    buffer.order(ByteOrder.LITTLE_ENDIAN);
    buffer.putInt(value);
    return buffer.array();
  }
}
