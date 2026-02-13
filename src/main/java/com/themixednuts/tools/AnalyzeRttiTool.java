package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.RTTIAnalysisResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.cmd.data.rtti.VfTableModel;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.util.bin.format.golang.rtti.GoItab;
import ghidra.app.util.bin.format.golang.rtti.GoModuledata;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.golang.rtti.types.GoType;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.app.util.datatype.microsoft.RTTI0DataType;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Analyze RTTI",
    description = "Analyze RTTI at a given address and return parsed metadata.",
    mcpName = "analyze_rtti",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
            <use_case>
            Comprehensive analysis of RTTI structures at a specific address in the current program.
            Supports Microsoft ABI RTTI (RTTI0/1/3/4 and VTable) and Itanium C++ ABI RTTI
            (__class_type_info, __si_class_type_info, __vmi_class_type_info, and vtable),
            plus Go runtime RTTI metadata (runtime._type and runtime.itab).
            Returns detailed information about RTTI validity, relationships, pointers,
            mangled and demangled names, and class hierarchy metadata where available.
            </use_case>

            <parameters_summary>
            - file_name: The program file to analyze (required)
            - address: Address string (e.g., 0x401000) to probe for RTTI structures
            - backend: Backend adapter to use (auto|microsoft|itanium|go), default: auto
            - validate_referred_to_data: Microsoft-only: recursively validate references (default: false)
            - ignore_instructions: Microsoft-only: ignore existing instructions during validation (default: true)
            - ignore_defined_data: Microsoft-only: ignore existing defined data during validation (default: true)
            </parameters_summary>

            <return_value_summary>
            Returns an RTTIAnalysisResult object with comprehensive RTTI analysis including:
            - Detected RTTI type across supported ABIs
            - Validity status and validation details
            - VTable/typeinfo pointers and related addresses
            - Mangled and demangled class names
            - Class hierarchy information where available
            </return_value_summary>

            <important_notes>
            - Microsoft RTTI uses Ghidra's official RTTI model classes
            - Itanium RTTI uses ABI-defined memory layout parsing and symbol/demangler cues
            - Go RTTI uses Ghidra's GoRttiMapper and GoTypeManager APIs
            - Backend adapters are swappable and can be selected explicitly via backend
            - Validation options tune Microsoft model strictness; Itanium parsing ignores them
            </important_notes>
        """)
public class AnalyzeRttiTool extends BaseMcpTool {

  private static final String ARG_VALIDATE_REFERRED_TO_DATA = "validate_referred_to_data";
  private static final String ARG_IGNORE_INSTRUCTIONS = "ignore_instructions";
  private static final String ARG_IGNORE_DEFINED_DATA = "ignore_defined_data";
  private static final String ARG_BACKEND = "backend";

  private static final String BACKEND_AUTO = "auto";
  private static final String BACKEND_MICROSOFT = "microsoft";
  private static final String BACKEND_ITANIUM = "itanium";
  private static final String BACKEND_GO = "go";

  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME,
        SchemaBuilder.string(mapper).description("The name of the Ghidra program file to analyze"));

    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Address (e.g., 0x401000) where RTTI is expected")
            .pattern("^([A-Za-z_][A-Za-z0-9_]*:)?(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_BACKEND,
        SchemaBuilder.string(mapper)
            .description("Backend adapter to use: auto, microsoft, itanium, or go")
            .enumValues(BACKEND_AUTO, BACKEND_MICROSOFT, BACKEND_ITANIUM, BACKEND_GO)
            .defaultValue(BACKEND_AUTO));

    schemaRoot.property(
        ARG_VALIDATE_REFERRED_TO_DATA,
        SchemaBuilder.bool(mapper)
            .description(
                "Whether to recursively validate referenced RTTI structures for stricter matching")
            .defaultValue(false));

    schemaRoot.property(
        ARG_IGNORE_INSTRUCTIONS,
        SchemaBuilder.bool(mapper)
            .description(
                "Whether existing instructions should be ignored during RTTI structure validation")
            .defaultValue(true));

    schemaRoot.property(
        ARG_IGNORE_DEFINED_DATA,
        SchemaBuilder.bool(mapper)
            .description(
                "Whether existing defined data should be ignored during RTTI structure validation")
            .defaultValue(true));

    schemaRoot.requiredProperty(ARG_FILE_NAME);
    schemaRoot.requiredProperty(ARG_ADDRESS);

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return getProgram(args, tool)
        .flatMap(
            program ->
                Mono.fromCallable(
                    () -> {
                      String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
                      return analyzeRTTIAtAddress(program, addressStr, args);
                    }));
  }

  private RTTIAnalysisResult analyzeRTTIAtAddress(
      Program program, String addressStr, Map<String, Object> args)
      throws GhidraMcpException {
    try {
      Address address = program.getAddressFactory().getAddress(addressStr);
      if (address == null) {
        throw new GhidraMcpException(
            GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Invalid address: " + addressStr)
                .build());
      }

      String requestedBackend =
          getOptionalStringArgument(args, ARG_BACKEND).orElse(BACKEND_AUTO).toLowerCase(Locale.ROOT);
      List<RttiBackend> backends = selectBackends(requestedBackend);
      boolean forceSelectedBackend = !BACKEND_AUTO.equals(requestedBackend);

      Map<String, String> backendFailures = new LinkedHashMap<>();
      for (RttiBackend backend : backends) {
        if (!forceSelectedBackend && !backend.canAnalyzeProgram(program)) {
          backendFailures.put(backend.id(), "backend not applicable for current program");
          continue;
        }

        try {
          RTTIAnalysisResult result = backend.analyzeAtAddress(program, address, addressStr, args);
          if (result != null && result.isValid()) {
            return result;
          }
          backendFailures.put(backend.id(), extractInvalidReason(result));
        } catch (Exception e) {
          backendFailures.put(backend.id(), safeMessage(e));
        }
      }

      return RTTIAnalysisResult.invalid(
          RTTIAnalysisResult.RttiType.UNKNOWN,
          addressStr,
          buildBackendFailureSummary(backendFailures));

    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to analyze RTTI at address: " + safeMessage(e))
              .build());
    }
  }

  private List<RttiBackend> selectBackends(String requestedBackend) throws GhidraMcpException {
    RttiBackend microsoft = new MicrosoftRttiBackend();
    RttiBackend itanium = new ItaniumRttiBackend();
    RttiBackend go = new GoRttiBackend();

    return switch (requestedBackend) {
      case BACKEND_AUTO -> List.of(go, microsoft, itanium);
      case BACKEND_GO -> List.of(go);
      case BACKEND_MICROSOFT -> List.of(microsoft);
      case BACKEND_ITANIUM -> List.of(itanium);
      default ->
          throw new GhidraMcpException(
              GhidraMcpError.invalid(
                  ARG_BACKEND,
                  requestedBackend,
                  "must be one of: auto, microsoft, itanium, go"));
    };
  }

  private String extractInvalidReason(RTTIAnalysisResult result) {
    if (result instanceof RTTIAnalysisResult.InvalidResult invalid) {
      return safeMessage(new RuntimeException(invalid.error()));
    }
    return "no matching RTTI structure found";
  }

  private String buildBackendFailureSummary(Map<String, String> failures) {
    if (failures == null || failures.isEmpty()) {
      return "No valid RTTI structure found at address";
    }
    StringBuilder summary = new StringBuilder("No valid RTTI structure found at address. Backends: ");
    boolean first = true;
    for (Map.Entry<String, String> entry : failures.entrySet()) {
      if (!first) {
        summary.append("; ");
      }
      summary
          .append(entry.getKey())
          .append('=')
          .append(entry.getValue() == null || entry.getValue().isBlank() ? "unknown error" : entry.getValue());
      first = false;
    }
    return summary.toString();
  }

  private RTTIAnalysisResult analyzeMicrosoftRttiAtAddress(
      Program program, Address address, String addressStr, Map<String, Object> args)
      throws Exception {
    DataValidationOptions validationOptions = buildValidationOptions(args);
    Map<RTTIAnalysisResult.RttiType, String> failureReasons = new LinkedHashMap<>();

    RTTIAnalysisResult result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.RTTI4,
            addressStr,
            failureReasons,
            () -> {
              Rtti4Model model = new Rtti4Model(program, address, validationOptions);
              model.validate();
              return RTTIAnalysisResult.from(model, address);
            });
    if (result.isValid()) {
      return result;
    }

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.RTTI3,
            addressStr,
            failureReasons,
            () -> {
              Rtti3Model model = new Rtti3Model(program, address, validationOptions);
              model.validate();
              return RTTIAnalysisResult.from(model, address);
            });
    if (result.isValid()) {
      return result;
    }

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.RTTI1,
            addressStr,
            failureReasons,
            () -> {
              Rtti1Model model = new Rtti1Model(program, address, validationOptions);
              model.validate();
              return RTTIAnalysisResult.from(model, address);
            });
    if (result.isValid()) {
      return result;
    }

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.RTTI0,
            addressStr,
            failureReasons,
            () -> {
              DataTypeManager dtm = program.getDataTypeManager();
              TypeDescriptorModel typeDescriptorModel =
                  new TypeDescriptorModel(program, address, validationOptions);
              typeDescriptorModel.validate();
              RTTI0DataType rtti0 = new RTTI0DataType(dtm);
              return RTTIAnalysisResult.from(rtti0, program, address);
            });
    if (result.isValid()) {
      return result;
    }

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.VFTABLE,
            addressStr,
            failureReasons,
            () -> {
              VfTableModel model = new VfTableModel(program, address, validationOptions);
              model.validate();
              return RTTIAnalysisResult.from(model, address);
            });
    if (result.isValid()) {
      return result;
    }

    return RTTIAnalysisResult.invalid(
        RTTIAnalysisResult.RttiType.UNKNOWN, addressStr, buildFailureSummary(failureReasons));
  }

  private RTTIAnalysisResult analyzeItaniumRttiAtAddress(
      Program program, Address address, String addressStr) {
    Map<RTTIAnalysisResult.RttiType, String> failureReasons = new LinkedHashMap<>();

    RTTIAnalysisResult result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.ITANIUM_VTABLE,
            addressStr,
            failureReasons,
            () -> analyzeItaniumVtable(program, address));
    if (result.isValid()) {
      return result;
    }

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.ITANIUM_VMI_CLASS_TYPEINFO,
            addressStr,
            failureReasons,
            () ->
                analyzeItaniumTypeInfoAtAddress(
                    program, address, RTTIAnalysisResult.RttiType.ITANIUM_VMI_CLASS_TYPEINFO));
    if (result.isValid()) {
      return result;
    }

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.ITANIUM_SI_CLASS_TYPEINFO,
            addressStr,
            failureReasons,
            () ->
                analyzeItaniumTypeInfoAtAddress(
                    program, address, RTTIAnalysisResult.RttiType.ITANIUM_SI_CLASS_TYPEINFO));
    if (result.isValid()) {
      return result;
    }

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO,
            addressStr,
            failureReasons,
            () ->
                analyzeItaniumTypeInfoAtAddress(
                    program, address, RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO));
    if (result.isValid()) {
      return result;
    }

    return RTTIAnalysisResult.invalid(
        RTTIAnalysisResult.RttiType.UNKNOWN, addressStr, buildFailureSummary(failureReasons));
  }

  private RTTIAnalysisResult analyzeGoRttiAtAddress(Program program, Address address, String addressStr)
      throws Exception {
    GoRttiMapper goBinary = GoRttiMapper.getGoBinary(program, TaskMonitor.DUMMY);
    if (goBinary == null) {
      throw new IllegalArgumentException("program does not appear to contain Go RTTI metadata");
    }

    try {
      goBinary.init(TaskMonitor.DUMMY);

      Map<RTTIAnalysisResult.RttiType, String> failureReasons = new LinkedHashMap<>();
      RTTIAnalysisResult result =
          tryAnalyze(
              RTTIAnalysisResult.RttiType.GO_TYPE,
              addressStr,
              failureReasons,
              () -> analyzeGoType(goBinary, address));
      if (result.isValid()) {
        return result;
      }

      result =
          tryAnalyze(
              RTTIAnalysisResult.RttiType.GO_ITAB,
              addressStr,
              failureReasons,
              () -> analyzeGoItab(goBinary, address));
      if (result.isValid()) {
        return result;
      }

      return RTTIAnalysisResult.invalid(
          RTTIAnalysisResult.RttiType.UNKNOWN, addressStr, buildFailureSummary(failureReasons));
    } finally {
      goBinary.close();
    }
  }

  private RTTIAnalysisResult analyzeGoType(GoRttiMapper goBinary, Address address) throws Exception {
    GoType goType = goBinary.getGoTypes().getType(address.getOffset(), false);
    if (goType == null) {
      throw new IllegalArgumentException("address is not a Go runtime._type structure");
    }

    Address typeAddress = goType.getStructureContext().getStructureAddress();
    RTTIAnalysisResult.GoTypeInfo data =
        new RTTIAnalysisResult.GoTypeInfo(
            safeString(goType.getName()),
            safeString(goType.getFullyQualifiedName()),
            goType.getClass().getSimpleName(),
            goType.getClass().getName(),
            typeAddress != null ? typeAddress.toString() : address.toString(),
            goType.getTypeOffset(),
            optionalNonBlank(goType.getPackagePathString()),
            optionalNonBlank(goType.toString()),
            optionalNonBlank(goBinary.getGoVer() != null ? goBinary.getGoVer().toString() : null));

    return RTTIAnalysisResult.from(data, address);
  }

  private RTTIAnalysisResult analyzeGoItab(GoRttiMapper goBinary, Address address) throws Exception {
    GoItab targetItab = findGoItabAtAddress(goBinary, address);
    if (targetItab == null) {
      throw new IllegalArgumentException("address is not a Go runtime.itab structure");
    }

    RTTIAnalysisResult.GoItabInfo data =
        new RTTIAnalysisResult.GoItabInfo(
            address.toString(),
            Optional.ofNullable(targetItab.getType()).map(GoType::getFullyQualifiedName),
            Optional.ofNullable(targetItab.getInterfaceType()).map(GoType::getFullyQualifiedName),
            Optional.of(targetItab.getFuncCount()),
            optionalNonBlank(goBinary.getGoVer() != null ? goBinary.getGoVer().toString() : null));

    return RTTIAnalysisResult.from(data, address);
  }

  private GoItab findGoItabAtAddress(GoRttiMapper goBinary, Address address) throws Exception {
    for (GoModuledata module : goBinary.getModules()) {
      for (GoItab itab : module.getItabs()) {
        Address itabAddress = itab.getStructureContext().getStructureAddress();
        if (itabAddress != null && itabAddress.equals(address)) {
          return itab;
        }
      }
    }
    return null;
  }

  private RTTIAnalysisResult analyzeItaniumTypeInfoAtAddress(
      Program program, Address address, RTTIAnalysisResult.RttiType expectedKind) throws Exception {
    Symbol typeInfoSymbol = getPrimaryOrFirstSymbol(program, address);
    String symbolName = typeInfoSymbol != null ? typeInfoSymbol.getName() : "";
    Optional<String> demangledSymbol = tryDemangleSymbol(program, symbolName, address);

    if (!looksLikeItaniumTypeInfoSymbol(symbolName)
        && demangledSymbol.filter(AnalyzeRttiTool::looksLikeItaniumTypeInfoDemangled).isEmpty()) {
      throw new IllegalArgumentException("address does not look like an Itanium typeinfo symbol");
    }

    int pointerSize = program.getDefaultPointerSize();
    Address classTypeInfoVtableAddress = readPointerAddress(program, address);
    if (classTypeInfoVtableAddress == null) {
      throw new IllegalArgumentException("typeinfo vtable pointer is null");
    }

    Optional<Address> typeNameAddress = Optional.ofNullable(readPointerAddress(program, address.add(pointerSize)));
    Optional<String> representedType =
        extractTypeFromDemangledTypeInfo(demangledSymbol)
            .or(() -> typeNameAddress.flatMap(addr -> readCString(program, addr, 512)));

    Symbol classTypeInfoVtableSymbol = findClassTypeInfoVtableSymbol(program, classTypeInfoVtableAddress);
    String vtableSymbolName = classTypeInfoVtableSymbol != null ? classTypeInfoVtableSymbol.getName() : "";
    Optional<String> demangledVtableSymbol =
        tryDemangleSymbol(program, vtableSymbolName, classTypeInfoVtableAddress);
    RTTIAnalysisResult.RttiType detectedKind =
        classifyItaniumTypeInfoKind(vtableSymbolName, demangledVtableSymbol.orElse(""));
    if (detectedKind == RTTIAnalysisResult.RttiType.UNKNOWN) {
      detectedKind = RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO;
    }

    if (detectedKind != expectedKind) {
      throw new IllegalArgumentException(
          "detected " + detectedKind.name() + " but expected " + expectedKind.name());
    }

    Optional<String> typeNameAddressStr = typeNameAddress.map(Address::toString);
    Optional<String> classTypeInfoVtableAddressStr = Optional.of(classTypeInfoVtableAddress.toString());

    if (detectedKind == RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO) {
      RTTIAnalysisResult.ItaniumClassTypeInfo data =
          new RTTIAnalysisResult.ItaniumClassTypeInfo(
              symbolName,
              demangledSymbol,
              representedType,
              typeNameAddressStr,
              classTypeInfoVtableAddressStr);
      return RTTIAnalysisResult.from(data, address);
    }

    if (detectedKind == RTTIAnalysisResult.RttiType.ITANIUM_SI_CLASS_TYPEINFO) {
      Address baseTypeInfoAddress = readPointerAddress(program, address.add(pointerSize * 2L));
      RTTIAnalysisResult.ItaniumSiClassTypeInfo data =
          new RTTIAnalysisResult.ItaniumSiClassTypeInfo(
              symbolName,
              demangledSymbol,
              representedType,
              typeNameAddressStr,
              classTypeInfoVtableAddressStr,
              Optional.ofNullable(baseTypeInfoAddress).map(Address::toString));
      return RTTIAnalysisResult.from(data, address);
    }

    if (detectedKind != RTTIAnalysisResult.RttiType.ITANIUM_VMI_CLASS_TYPEINFO) {
      throw new IllegalArgumentException("unsupported Itanium typeinfo layout");
    }

    long flags = readUnsignedInt(program, address.add(pointerSize * 2L));
    int numBaseClasses = (int) readUnsignedInt(program, address.add(pointerSize * 2L + 4));
    if (numBaseClasses < 0 || numBaseClasses > 512) {
      throw new IllegalArgumentException("invalid __vmi_class_type_info base count: " + numBaseClasses);
    }

    List<RTTIAnalysisResult.ItaniumVmiBaseClass> baseClasses = new ArrayList<>();
    Address baseArrayAddress = address.add(pointerSize * 2L + 8);
    long baseEntrySize = pointerSize * 2L;

    for (int i = 0; i < numBaseClasses; i++) {
      Address baseEntryAddress = baseArrayAddress.add(baseEntrySize * i);
      Address baseTypeInfoAddress = readPointerAddress(program, baseEntryAddress);
      long offsetFlags = readPointerUnsignedValue(program, baseEntryAddress.add(pointerSize));
      boolean isVirtual = (offsetFlags & 0x1L) != 0;
      boolean isPublic = (offsetFlags & 0x2L) != 0;
      long offset = decodeItaniumBaseOffset(offsetFlags, pointerSize);

      baseClasses.add(
          new RTTIAnalysisResult.ItaniumVmiBaseClass(
              i,
              Optional.ofNullable(baseTypeInfoAddress).map(Address::toString),
              isVirtual,
              isPublic,
              offset));
    }

    RTTIAnalysisResult.ItaniumVmiClassTypeInfo data =
        new RTTIAnalysisResult.ItaniumVmiClassTypeInfo(
            symbolName,
            demangledSymbol,
            representedType,
            typeNameAddressStr,
            classTypeInfoVtableAddressStr,
            flags,
            numBaseClasses,
            baseClasses);
    return RTTIAnalysisResult.from(data, address);
  }

  private RTTIAnalysisResult analyzeItaniumVtable(Program program, Address address) throws Exception {
    Symbol vtableSymbol = getPrimaryOrFirstSymbol(program, address);
    String symbolName = vtableSymbol != null ? vtableSymbol.getName() : "";
    Optional<String> demangledSymbol = tryDemangleSymbol(program, symbolName, address);
    if (!looksLikeItaniumVtableSymbol(symbolName)
        && demangledSymbol.filter(AnalyzeRttiTool::looksLikeItaniumVtableDemangled).isEmpty()) {
      throw new IllegalArgumentException("address does not look like an Itanium vtable symbol");
    }

    int pointerSize = program.getDefaultPointerSize();
    long offsetToTop = readPointerSignedValue(program, address);
    Address typeInfoAddress = readPointerAddress(program, address.add(pointerSize));

    Map<Integer, String> virtualFunctionPointers = new LinkedHashMap<>();
    Address firstFunctionPointerAddress = address.add(pointerSize * 2L);
    for (int i = 0; i < 128; i++) {
      Address currentPointerAddress = firstFunctionPointerAddress.add((long) i * pointerSize);
      Address functionPointer = readPointerAddress(program, currentPointerAddress);
      if (functionPointer == null || !isLoadedAndInitializedAddress(program, functionPointer)) {
        break;
      }
      virtualFunctionPointers.put(i, functionPointer.toString());
    }

    RTTIAnalysisResult.ItaniumVtable data =
        new RTTIAnalysisResult.ItaniumVtable(
            symbolName,
            demangledSymbol,
            Optional.of(offsetToTop),
            Optional.ofNullable(typeInfoAddress).map(Address::toString),
            virtualFunctionPointers);
    return RTTIAnalysisResult.from(data, address);
  }

  static RTTIAnalysisResult.RttiType classifyItaniumTypeInfoKind(
      String vtableSymbolName, String demangledVtableName) {
    String combined = (vtableSymbolName + " " + demangledVtableName).toLowerCase();
    if (combined.contains("__vmi_class_type_info")) {
      return RTTIAnalysisResult.RttiType.ITANIUM_VMI_CLASS_TYPEINFO;
    }
    if (combined.contains("__si_class_type_info")) {
      return RTTIAnalysisResult.RttiType.ITANIUM_SI_CLASS_TYPEINFO;
    }
    if (combined.contains("__class_type_info")) {
      return RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO;
    }
    return RTTIAnalysisResult.RttiType.UNKNOWN;
  }

  static boolean looksLikeItaniumTypeInfoSymbol(String symbolName) {
    return symbolName != null && (symbolName.startsWith("_ZTI") || symbolName.startsWith("__ZTI"));
  }

  static boolean looksLikeItaniumVtableSymbol(String symbolName) {
    return symbolName != null && (symbolName.startsWith("_ZTV") || symbolName.startsWith("__ZTV"));
  }

  static boolean looksLikeItaniumTypeInfoDemangled(String demangledName) {
    return demangledName != null && demangledName.toLowerCase().startsWith("typeinfo for ");
  }

  static boolean looksLikeItaniumVtableDemangled(String demangledName) {
    return demangledName != null && demangledName.toLowerCase().startsWith("vtable for ");
  }

  static Optional<String> extractTypeFromDemangledTypeInfo(Optional<String> demangledName) {
    if (demangledName.isEmpty()) {
      return Optional.empty();
    }
    String value = demangledName.get();
    String prefix = "typeinfo for ";
    if (!value.toLowerCase().startsWith(prefix)) {
      return Optional.empty();
    }
    String typeName = value.substring(prefix.length()).trim();
    return typeName.isEmpty() ? Optional.empty() : Optional.of(typeName);
  }

  private Symbol findClassTypeInfoVtableSymbol(Program program, Address vtableAddress) {
    int pointerSize = program.getDefaultPointerSize();
    Symbol symbol = getPrimaryOrFirstSymbol(program, vtableAddress);
    if (symbol != null) {
      return symbol;
    }

    try {
      Address previous = vtableAddress.subtractNoWrap(pointerSize);
      symbol = getPrimaryOrFirstSymbol(program, previous);
      if (symbol != null) {
        return symbol;
      }
    } catch (AddressOverflowException ignored) {
      // ignored
    }

    try {
      Address twoBack = vtableAddress.subtractNoWrap(pointerSize * 2L);
      return getPrimaryOrFirstSymbol(program, twoBack);
    } catch (AddressOverflowException ignored) {
      return null;
    }
  }

  private Symbol getPrimaryOrFirstSymbol(Program program, Address address) {
    Symbol primary = program.getSymbolTable().getPrimarySymbol(address);
    if (primary != null) {
      return primary;
    }
    Symbol[] symbols = program.getSymbolTable().getSymbols(address);
    if (symbols.length > 0) {
      return symbols[0];
    }
    return null;
  }

  private Optional<String> tryDemangleSymbol(Program program, String symbolName, Address address) {
    if (symbolName == null || symbolName.isBlank()) {
      return Optional.empty();
    }
    try {
      var demangled = DemanglerUtil.demangle(program, symbolName, address);
      if (demangled == null || demangled.isEmpty() || demangled.get(0) == null) {
        return Optional.empty();
      }
      String text = demangled.get(0).toString();
      if (text == null || text.isBlank()) {
        return Optional.empty();
      }
      return Optional.of(text);
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  private Optional<String> readCString(Program program, Address address, int maxLength) {
    if (address == null || maxLength <= 0 || !isLoadedAndInitializedAddress(program, address)) {
      return Optional.empty();
    }

    StringBuilder sb = new StringBuilder();
    Memory memory = program.getMemory();
    for (int i = 0; i < maxLength; i++) {
      try {
        byte value = memory.getByte(address.add(i));
        if (value == 0) {
          break;
        }
        int unsigned = Byte.toUnsignedInt(value);
        if (unsigned < 0x20 || unsigned > 0x7e) {
          return Optional.empty();
        }
        sb.append((char) unsigned);
      } catch (Exception e) {
        return Optional.empty();
      }
    }

    String text = sb.toString().trim();
    return text.isEmpty() ? Optional.empty() : Optional.of(text);
  }

  private boolean isLoadedAndInitializedAddress(Program program, Address address) {
    if (address == null) {
      return false;
    }
    return program.getMemory().getLoadedAndInitializedAddressSet().contains(address);
  }

  private Address readPointerAddress(Program program, Address address)
      throws MemoryAccessException, AddressOutOfBoundsException {
    long value = readPointerUnsignedValue(program, address);
    if (value == 0) {
      return null;
    }
    return toDefaultAddress(program, value);
  }

  private long readPointerUnsignedValue(Program program, Address address)
      throws MemoryAccessException, AddressOutOfBoundsException {
    int pointerSize = program.getDefaultPointerSize();
    Memory memory = program.getMemory();
    if (pointerSize == 8) {
      return memory.getLong(address);
    }
    if (pointerSize == 4) {
      return Integer.toUnsignedLong(memory.getInt(address));
    }
    throw new IllegalArgumentException("unsupported pointer size: " + pointerSize);
  }

  private long readPointerSignedValue(Program program, Address address)
      throws MemoryAccessException, AddressOutOfBoundsException {
    int pointerSize = program.getDefaultPointerSize();
    Memory memory = program.getMemory();
    if (pointerSize == 8) {
      return memory.getLong(address);
    }
    if (pointerSize == 4) {
      return memory.getInt(address);
    }
    throw new IllegalArgumentException("unsupported pointer size: " + pointerSize);
  }

  private long readUnsignedInt(Program program, Address address)
      throws MemoryAccessException, AddressOutOfBoundsException {
    return Integer.toUnsignedLong(program.getMemory().getInt(address));
  }

  private Address toDefaultAddress(Program program, long offset) {
    AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
    try {
      return defaultSpace.getAddress(offset);
    } catch (Exception e) {
      return null;
    }
  }

  private long decodeItaniumBaseOffset(long offsetFlags, int pointerSize) {
    if (pointerSize == 4) {
      int signed = (int) (offsetFlags & 0xffff_ffffL);
      return signed >> 8;
    }
    return offsetFlags >> 8;
  }

  private String safeString(String value) {
    return value == null ? "" : value;
  }

  private Optional<String> optionalNonBlank(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(value);
  }

  private boolean hasGoProgramSignal(Program program) {
    if (GoRttiMapper.isGolangProgram(program)) {
      return true;
    }
    List<String> sectionNames =
        Arrays.stream(program.getMemory().getBlocks()).map(MemoryBlock::getName).toList();
    return GoRttiMapper.hasGolangSections(sectionNames);
  }

  private interface RttiBackend {
    String id();

    boolean canAnalyzeProgram(Program program);

    RTTIAnalysisResult analyzeAtAddress(
        Program program, Address address, String addressStr, Map<String, Object> args)
        throws Exception;
  }

  private final class MicrosoftRttiBackend implements RttiBackend {
    @Override
    public String id() {
      return BACKEND_MICROSOFT;
    }

    @Override
    public boolean canAnalyzeProgram(Program program) {
      return PEUtil.isVisualStudioOrClangPe(program);
    }

    @Override
    public RTTIAnalysisResult analyzeAtAddress(
        Program program, Address address, String addressStr, Map<String, Object> args)
        throws Exception {
      return analyzeMicrosoftRttiAtAddress(program, address, addressStr, args);
    }
  }

  private final class ItaniumRttiBackend implements RttiBackend {
    @Override
    public String id() {
      return BACKEND_ITANIUM;
    }

    @Override
    public boolean canAnalyzeProgram(Program program) {
      return !PEUtil.isVisualStudioOrClangPe(program) && !hasGoProgramSignal(program);
    }

    @Override
    public RTTIAnalysisResult analyzeAtAddress(
        Program program, Address address, String addressStr, Map<String, Object> args) {
      return analyzeItaniumRttiAtAddress(program, address, addressStr);
    }
  }

  private final class GoRttiBackend implements RttiBackend {
    @Override
    public String id() {
      return BACKEND_GO;
    }

    @Override
    public boolean canAnalyzeProgram(Program program) {
      return hasGoProgramSignal(program);
    }

    @Override
    public RTTIAnalysisResult analyzeAtAddress(
        Program program, Address address, String addressStr, Map<String, Object> args)
        throws Exception {
      return analyzeGoRttiAtAddress(program, address, addressStr);
    }
  }

  static String buildFailureSummary(Map<RTTIAnalysisResult.RttiType, String> failureReasons) {
    if (failureReasons == null || failureReasons.isEmpty()) {
      return "No valid RTTI structure found at address";
    }

    StringBuilder summary = new StringBuilder("No valid RTTI structure found at address. Attempts: ");
    boolean first = true;
    for (Map.Entry<RTTIAnalysisResult.RttiType, String> entry : failureReasons.entrySet()) {
      if (!first) {
        summary.append("; ");
      }
      summary
          .append(entry.getKey().name())
          .append('=')
          .append(entry.getValue() == null || entry.getValue().isBlank() ? "unknown error" : entry.getValue());
      first = false;
    }
    return summary.toString();
  }

  private String safeMessage(Throwable t) {
    if (t == null || t.getMessage() == null || t.getMessage().isBlank()) {
      return "unknown error";
    }
    return t.getMessage();
  }

  private DataValidationOptions buildValidationOptions(Map<String, Object> args) {
    DataValidationOptions options = new DataValidationOptions();
    options.setValidateReferredToData(
        getOptionalBooleanArgument(args, ARG_VALIDATE_REFERRED_TO_DATA).orElse(false));
    options.setIgnoreInstructions(
        getOptionalBooleanArgument(args, ARG_IGNORE_INSTRUCTIONS).orElse(true));
    options.setIgnoreDefinedData(
        getOptionalBooleanArgument(args, ARG_IGNORE_DEFINED_DATA).orElse(true));
    return options;
  }

  private RTTIAnalysisResult tryAnalyze(
      RTTIAnalysisResult.RttiType attemptedType,
      String addressStr,
      Map<RTTIAnalysisResult.RttiType, String> failureReasons,
      RttiAnalyzer analyzer) {
    try {
      return analyzer.analyze();
    } catch (Exception e) {
      String message = safeMessage(e);
      failureReasons.putIfAbsent(attemptedType, message);
      return RTTIAnalysisResult.invalid(attemptedType, addressStr, message);
    }
  }

  @FunctionalInterface
  private interface RttiAnalyzer {
    RTTIAnalysisResult analyze() throws Exception;
  }
}
