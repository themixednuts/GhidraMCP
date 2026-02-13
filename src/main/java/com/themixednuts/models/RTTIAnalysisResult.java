package com.themixednuts.models;

import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti2Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.cmd.data.rtti.VfTableModel;
import ghidra.app.util.datatype.microsoft.RTTI0DataType;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;
import ghidra.app.util.demangler.microsoft.MicrosoftDemanglerOptions;
import ghidra.app.util.demangler.microsoft.MicrosoftMangledContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBufferImpl;
import java.util.*;

/**
 * Result of RTTI analysis using sealed interface pattern (Rust-style enum with variants). Each
 * variant (Rtti0Result, Rtti1Result, etc.) holds its specific data.
 */
public sealed interface RTTIAnalysisResult
    permits RTTIAnalysisResult.Rtti0Result,
        RTTIAnalysisResult.Rtti1Result,
        RTTIAnalysisResult.Rtti2Result,
        RTTIAnalysisResult.Rtti3Result,
        RTTIAnalysisResult.Rtti4Result,
        RTTIAnalysisResult.VfTableResult,
        RTTIAnalysisResult.ItaniumClassTypeInfoResult,
        RTTIAnalysisResult.ItaniumSiClassTypeInfoResult,
        RTTIAnalysisResult.ItaniumVmiClassTypeInfoResult,
        RTTIAnalysisResult.ItaniumVtableResult,
        RTTIAnalysisResult.GoTypeResult,
        RTTIAnalysisResult.GoItabResult,
        RTTIAnalysisResult.InvalidResult {

  String address();

  boolean isValid();

  RttiType rttiType();

  enum RttiType {
    RTTI0,
    RTTI1,
    RTTI2,
    RTTI3,
    RTTI4,
    VFTABLE,
    ITANIUM_CLASS_TYPEINFO,
    ITANIUM_SI_CLASS_TYPEINFO,
    ITANIUM_VMI_CLASS_TYPEINFO,
    ITANIUM_VTABLE,
    GO_TYPE,
    GO_ITAB,
    UNKNOWN
  }

  // Factory methods
  static Rtti0Result from(RTTI0DataType rtti0, Program program, Address address)
      throws InvalidDataTypeException {
    Memory memory = program.getMemory();
    int length = rtti0.getLength(memory, address);
    Optional<String> vfTableAddress =
        Optional.ofNullable(rtti0.getVFTableAddress(memory, address)).map(Address::toString);
    Optional<String> spareDataAddress =
        Optional.ofNullable(rtti0.getSpareDataAddress(memory, address)).map(Address::toString);

    MemBuffer memBuffer = new MemoryBufferImpl(memory, address);
    String vfTableName = rtti0.getVFTableName(memBuffer);
    Optional<String> mangledName = Optional.ofNullable(vfTableName);

    Optional<String> demangledName =
        mangledName.flatMap(
            symbol ->
                tryStandardDemangler(program, symbol)
                    .or(() -> tryMicrosoftDemangler(program, symbol, address))
                    .map(DemangledObject::toString));

    Rtti0 data =
        new Rtti0(
            rtti0.getName(),
            rtti0.getDescription(),
            rtti0.getMnemonic(null),
            rtti0.getDefaultLabelPrefix(),
            length,
            rtti0.getClass().getSimpleName(),
            vfTableAddress,
            spareDataAddress,
            Optional.ofNullable(vfTableName),
            mangledName,
            demangledName);

    return new Rtti0Result(address.toString(), data);
  }

  static Rtti1Result from(Rtti1Model model, Address address) throws InvalidDataTypeException {
    Rtti1 data =
        new Rtti1(
            model.getName(),
            model.getDataType().getName(),
            model.getDataType().getLength(),
            Optional.ofNullable(model.getRtti0Address()).map(Address::toString),
            Optional.of(model.getNumBases()),
            Optional.of(model.getMDisp()),
            Optional.of(model.getPDisp()),
            Optional.of(model.getVDisp()),
            Optional.of(model.getAttributes()),
            Optional.ofNullable(model.getRtti3Address()).map(Address::toString));

    return new Rtti1Result(address.toString(), data);
  }

  static Rtti2Result from(Rtti2Model model, Address address) throws InvalidDataTypeException {
    List<String> baseClassTypes = model.getBaseClassTypes();
    Map<Integer, String> rtti1Addresses = new HashMap<>();
    for (int i = 0; i < baseClassTypes.size(); i++) {
      Address rtti1Addr = model.getRtti1Address(i);
      if (rtti1Addr != null) {
        rtti1Addresses.put(i, rtti1Addr.toString());
      }
    }

    Rtti2 data =
        new Rtti2(
            model.getName(),
            model.getDataType().getName(),
            model.getDataType().getLength(),
            baseClassTypes.size(),
            baseClassTypes,
            Optional.ofNullable(model.getRtti0Model()).map(m -> m.getAddress().toString()),
            rtti1Addresses);

    return new Rtti2Result(address.toString(), data);
  }

  static Rtti3Result from(Rtti3Model model, Address address) throws InvalidDataTypeException {
    Rtti3 data =
        new Rtti3(
            model.getName(),
            model.getDataType().getName(),
            model.getDataType().getLength(),
            Optional.of(model.getSignature()),
            Optional.of(model.getAttributes()),
            Optional.of(model.getRtti1Count()),
            Optional.ofNullable(model.getRtti2Address()).map(Address::toString),
            model.getBaseClassTypes(),
            Optional.ofNullable(model.getRtti0Model()).map(m -> m.getAddress().toString()));

    return new Rtti3Result(address.toString(), data);
  }

  static Rtti4Result from(Rtti4Model model, Address address) throws InvalidDataTypeException {
    Rtti4 data =
        new Rtti4(
            model.getName(),
            model.getDataType().getName(),
            model.getDataType().getLength(),
            Optional.of(model.getSignature()),
            Optional.of(model.getVbTableOffset()),
            Optional.of(model.getConstructorOffset()),
            Optional.ofNullable(model.getRtti0Address()).map(Address::toString),
            Optional.ofNullable(model.getRtti3Address()).map(Address::toString),
            Optional.ofNullable(model.getRtti0FieldAddress()).map(Address::toString),
            Optional.ofNullable(model.getRtti3FieldAddress()).map(Address::toString),
            model.getBaseClassTypes());

    return new Rtti4Result(address.toString(), data);
  }

  static VfTableResult from(VfTableModel model, Address address) throws InvalidDataTypeException {
    Map<Integer, String> virtualFunctionPointers = new HashMap<>();
    int elementCount = model.getElementCount();
    for (int i = 0; i < elementCount; i++) {
      Address funcPtr = model.getVirtualFunctionPointer(i);
      if (funcPtr != null) {
        virtualFunctionPointers.put(i, funcPtr.toString());
      }
    }

    VfTable data =
        new VfTable(
            model.getName(),
            model.getDataType() != null ? model.getDataType().getName() : "vftable",
            model.getDataType() != null ? model.getDataType().getLength() : 0,
            elementCount,
            Optional.ofNullable(model.getRtti0Model()).map(m -> m.getAddress().toString()),
            virtualFunctionPointers);

    return new VfTableResult(address.toString(), data);
  }

  static ItaniumClassTypeInfoResult from(ItaniumClassTypeInfo data, Address address) {
    return new ItaniumClassTypeInfoResult(address.toString(), data);
  }

  static ItaniumSiClassTypeInfoResult from(ItaniumSiClassTypeInfo data, Address address) {
    return new ItaniumSiClassTypeInfoResult(address.toString(), data);
  }

  static ItaniumVmiClassTypeInfoResult from(ItaniumVmiClassTypeInfo data, Address address) {
    return new ItaniumVmiClassTypeInfoResult(address.toString(), data);
  }

  static ItaniumVtableResult from(ItaniumVtable data, Address address) {
    return new ItaniumVtableResult(address.toString(), data);
  }

  static GoTypeResult from(GoTypeInfo data, Address address) {
    return new GoTypeResult(address.toString(), data);
  }

  static GoItabResult from(GoItabInfo data, Address address) {
    return new GoItabResult(address.toString(), data);
  }

  static InvalidResult invalid(RttiType type, String address, String errorMessage) {
    return new InvalidResult(type, address, errorMessage);
  }

  // Demangling helpers
  private static Optional<DemangledObject> tryStandardDemangler(
      Program program, String mangledSymbol) {
    if (mangledSymbol == null || mangledSymbol.trim().isEmpty()) {
      return Optional.empty();
    }
    try {
      var demangledList = DemanglerUtil.demangle(program, mangledSymbol, null);
      return Optional.ofNullable(demangledList)
          .filter(list -> !list.isEmpty())
          .map(list -> list.get(0))
          .filter(obj -> obj instanceof DemangledObject)
          .map(obj -> (DemangledObject) obj);
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  private static Optional<DemangledObject> tryMicrosoftDemangler(
      Program program, String mangledSymbol, Address address) {
    if (mangledSymbol == null || mangledSymbol.trim().isEmpty()) {
      return Optional.empty();
    }
    try {
      MicrosoftDemangler demangler = new MicrosoftDemangler();
      if (!demangler.canDemangle(program)) {
        return Optional.empty();
      }
      MicrosoftDemanglerOptions options = demangler.createDefaultOptions();
      MicrosoftMangledContext context =
          new MicrosoftMangledContext(program, options, mangledSymbol, address);
      var demangledObject = demangler.demangle(context);
      return Optional.ofNullable(demangledObject)
          .filter(obj -> obj instanceof DemangledObject)
          .map(obj -> (DemangledObject) obj);
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  // Sealed variant implementations
  record Rtti0Result(String address, Rtti0 data) implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.RTTI0;
    }
  }

  record Rtti1Result(String address, Rtti1 data) implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.RTTI1;
    }
  }

  record Rtti2Result(String address, Rtti2 data) implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.RTTI2;
    }
  }

  record Rtti3Result(String address, Rtti3 data) implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.RTTI3;
    }
  }

  record Rtti4Result(String address, Rtti4 data) implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.RTTI4;
    }
  }

  record VfTableResult(String address, VfTable data) implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.VFTABLE;
    }
  }

  record ItaniumClassTypeInfoResult(String address, ItaniumClassTypeInfo data)
      implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.ITANIUM_CLASS_TYPEINFO;
    }
  }

  record ItaniumSiClassTypeInfoResult(String address, ItaniumSiClassTypeInfo data)
      implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.ITANIUM_SI_CLASS_TYPEINFO;
    }
  }

  record ItaniumVmiClassTypeInfoResult(String address, ItaniumVmiClassTypeInfo data)
      implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.ITANIUM_VMI_CLASS_TYPEINFO;
    }
  }

  record ItaniumVtableResult(String address, ItaniumVtable data) implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.ITANIUM_VTABLE;
    }
  }

  record GoTypeResult(String address, GoTypeInfo data) implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.GO_TYPE;
    }
  }

  record GoItabResult(String address, GoItabInfo data) implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return data != null;
    }

    @Override
    public RttiType rttiType() {
      return RttiType.GO_ITAB;
    }
  }

  record InvalidResult(RttiType attemptedType, String address, String error)
      implements RTTIAnalysisResult {
    @Override
    public boolean isValid() {
      return false;
    }

    @Override
    public RttiType rttiType() {
      return attemptedType;
    }
  }

  // RTTI Data Records

  // RTTI0 - Type Descriptor (from RTTI0DataType API)
  record Rtti0(
      String name,
      String description,
      String mnemonic,
      String defaultLabelPrefix,
      int length,
      String dataTypeName,
      Optional<String> vfTableAddress,
      Optional<String> spareDataAddress,
      Optional<String> vfTableName,
      Optional<String> mangledName,
      Optional<String> demangledName) {}

  // RTTI1 - Base Class Descriptor (from Rtti1Model API)
  record Rtti1(
      String name,
      String dataTypeName,
      int length,
      Optional<String> rtti0Address,
      Optional<Integer> numBases,
      Optional<Integer> mDisp,
      Optional<Integer> pDisp,
      Optional<Integer> vDisp,
      Optional<Integer> attributes,
      Optional<String> rtti3Address) {}

  // RTTI2 - Base Class Array (from Rtti2Model API)
  record Rtti2(
      String name,
      String dataTypeName,
      int length,
      int numEntries,
      List<String> baseClassTypes,
      Optional<String> rtti0Address,
      Map<Integer, String> rtti1Addresses) {}

  // RTTI3 - Class Hierarchy Descriptor (from Rtti3Model API)
  record Rtti3(
      String name,
      String dataTypeName,
      int length,
      Optional<Integer> signature,
      Optional<Integer> attributes,
      Optional<Integer> rtti1Count,
      Optional<String> rtti2Address,
      List<String> baseClassTypes,
      Optional<String> rtti0Address) {}

  // RTTI4 - Complete Object Locator (from Rtti4Model API)
  record Rtti4(
      String name,
      String dataTypeName,
      int length,
      Optional<Integer> signature,
      Optional<Integer> vbTableOffset,
      Optional<Integer> constructorOffset,
      Optional<String> rtti0Address,
      Optional<String> rtti3Address,
      Optional<String> rtti0FieldAddress,
      Optional<String> rtti3FieldAddress,
      List<String> baseClassTypes) {}

  // Itanium ABI RTTI - __class_type_info
  record ItaniumClassTypeInfo(
      String symbolName,
      Optional<String> demangledSymbol,
      Optional<String> representedType,
      Optional<String> typeNameAddress,
      Optional<String> classTypeInfoVtableAddress) {}

  // Itanium ABI RTTI - __si_class_type_info
  record ItaniumSiClassTypeInfo(
      String symbolName,
      Optional<String> demangledSymbol,
      Optional<String> representedType,
      Optional<String> typeNameAddress,
      Optional<String> classTypeInfoVtableAddress,
      Optional<String> baseTypeInfoAddress) {}

  // Itanium ABI RTTI - __vmi_class_type_info
  record ItaniumVmiClassTypeInfo(
      String symbolName,
      Optional<String> demangledSymbol,
      Optional<String> representedType,
      Optional<String> typeNameAddress,
      Optional<String> classTypeInfoVtableAddress,
      long flags,
      int numBaseClasses,
      List<ItaniumVmiBaseClass> baseClasses) {}

  record ItaniumVmiBaseClass(
      int index,
      Optional<String> baseTypeInfoAddress,
      boolean isVirtual,
      boolean isPublic,
      long offset) {}

  // Itanium ABI RTTI - vtable object
  record ItaniumVtable(
      String symbolName,
      Optional<String> demangledSymbol,
      Optional<Long> offsetToTop,
      Optional<String> typeInfoAddress,
      Map<Integer, String> virtualFunctionPointers) {}

  // Go RTTI - runtime._type structure
  record GoTypeInfo(
      String name,
      String fullyQualifiedName,
      String kind,
      String runtimeTypeClass,
      String typeAddress,
      long typeOffset,
      Optional<String> packagePath,
      Optional<String> declaration,
      Optional<String> goVersion) {}

  // Go RTTI - runtime.itab structure
  record GoItabInfo(
      String itabAddress,
      Optional<String> concreteType,
      Optional<String> interfaceType,
      Optional<Long> functionCount,
      Optional<String> goVersion) {}

  // VfTable - Virtual Function Table (from VfTableModel API)
  record VfTable(
      String name,
      String dataTypeName,
      int length,
      int elementCount,
      Optional<String> rtti0Address,
      Map<Integer, String> virtualFunctionPointers) {}
}
