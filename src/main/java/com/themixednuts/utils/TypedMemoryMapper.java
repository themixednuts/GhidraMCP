package com.themixednuts.utils;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.TypedMemoryField;
import com.themixednuts.models.TypedMemoryResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

public final class TypedMemoryMapper {

  private TypedMemoryMapper() {}

  public static CursorDataResult<TypedMemoryResult> applyAndMap(
      Program program, Address address, DataType dataType, int maxFields, int fieldOffset)
      throws GhidraMcpException {
    if (maxFields <= 0) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid("max_fields", maxFields, "must be greater than zero"));
    }
    if (fieldOffset < 0) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid("cursor", fieldOffset, "field cursor must be non-negative"));
    }

    Data data = applyDataType(program, address, dataType);
    int length = data != null ? data.getLength() : dataType.getLength();
    if (length <= 0) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "map data type",
              "data type " + dataType.getPathName() + " has dynamic or unknown length"));
    }

    byte[] bytes = readBytes(program, address, length);
    List<TypedMemoryField> fields = new ArrayList<>();
    FieldCounter counter = new FieldCounter();
    collectFields(data, "value", bytes, fieldOffset, maxFields + 1, counter, fields);

    String nextCursor = null;
    if (fields.size() > maxFields) {
      fields = new ArrayList<>(fields.subList(0, maxFields));
      nextCursor = OpaqueCursorCodec.encodeV1(String.valueOf(fieldOffset + maxFields));
    }

    TypedMemoryResult result =
        new TypedMemoryResult(
            address.toString(),
            dataType.getDisplayName(),
            dataType.getPathName(),
            dataType.getClass().getSimpleName(),
            length,
            HexFormat.of().formatHex(bytes),
            Boolean.TRUE,
            fieldOffset,
            fields.size(),
            fields);
    return new CursorDataResult<>(result, nextCursor);
  }

  private static Data applyDataType(Program program, Address address, DataType dataType)
      throws GhidraMcpException {
    try {
      Data data =
          DataUtilities.createData(
              program, address, dataType, -1, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
      if (data != null) {
        return data;
      }
      return program.getListing().getDataAt(address);
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "map data type",
              "could not apply "
                  + dataType.getPathName()
                  + " at "
                  + address
                  + ": "
                  + e.getMessage()),
          e);
    }
  }

  private static byte[] readBytes(Program program, Address address, int length)
      throws GhidraMcpException {
    byte[] bytes = new byte[length];
    try {
      int bytesRead = program.getMemory().getBytes(address, bytes);
      return bytesRead == length ? bytes : Arrays.copyOf(bytes, Math.max(0, bytesRead));
    } catch (MemoryAccessException e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("read typed memory", "address " + address + " is not accessible"),
          e);
    }
  }

  private static void collectFields(
      Data data,
      String path,
      byte[] rootBytes,
      int startIndex,
      int maxFields,
      FieldCounter counter,
      List<TypedMemoryField> fields) {
    if (data == null || fields.size() >= maxFields) {
      return;
    }

    if (data.getNumComponents() <= 0) {
      addFieldIfInPage(data, path, rootBytes, startIndex, maxFields, counter, fields);
      return;
    }

    collectComponents(data, path, rootBytes, startIndex, maxFields, counter, fields);
  }

  private static void collectComponents(
      Data data,
      String path,
      byte[] rootBytes,
      int startIndex,
      int maxFields,
      FieldCounter counter,
      List<TypedMemoryField> fields) {
    int componentCount = data.getNumComponents();
    for (int i = 0; i < componentCount && fields.size() < maxFields; i++) {
      Data component = data.getComponent(i);
      if (component == null) {
        continue;
      }
      String componentPath = childPath(path, component, i);
      addFieldIfInPage(component, componentPath, rootBytes, startIndex, maxFields, counter, fields);
      if (component.getNumComponents() > 0 && fields.size() < maxFields) {
        collectComponents(
            component, componentPath, rootBytes, startIndex, maxFields, counter, fields);
      }
    }
  }

  private static void addFieldIfInPage(
      Data data,
      String path,
      byte[] rootBytes,
      int startIndex,
      int maxFields,
      FieldCounter counter,
      List<TypedMemoryField> fields) {
    int index = counter.next();
    if (index < startIndex || fields.size() >= maxFields) {
      return;
    }

    int offset = Math.max(0, data.getRootOffset());
    int length = Math.max(0, data.getLength());
    fields.add(
        new TypedMemoryField(
            path,
            data.getFieldName(),
            data.getDataType() != null ? data.getDataType().getDisplayName() : null,
            offset,
            length,
            data.getMinAddress() != null ? data.getMinAddress().toString() : null,
            hexSlice(rootBytes, offset, length),
            valueString(data)));
  }

  private static String childPath(String parentPath, Data component, int index) {
    String name = component.getFieldName();
    String child = name == null || name.isBlank() ? "[" + index + "]" : name;
    return parentPath == null || parentPath.isBlank() ? child : parentPath + "." + child;
  }

  private static String hexSlice(byte[] bytes, int offset, int length) {
    if (bytes == null || offset >= bytes.length || length <= 0) {
      return null;
    }
    int end = Math.min(bytes.length, offset + length);
    if (end <= offset) {
      return null;
    }
    return HexFormat.of().formatHex(Arrays.copyOfRange(bytes, offset, end));
  }

  private static String valueString(Data data) {
    try {
      String representation = data.getDefaultValueRepresentation();
      if (representation != null && !representation.isBlank()) {
        return representation;
      }
    } catch (Exception ignored) {
      // Fall back to raw value below.
    }

    try {
      Object value = data.getValue();
      return value != null ? String.valueOf(value) : null;
    } catch (Exception e) {
      return null;
    }
  }

  private static final class FieldCounter {
    private int value;

    int next() {
      return value++;
    }
  }
}
