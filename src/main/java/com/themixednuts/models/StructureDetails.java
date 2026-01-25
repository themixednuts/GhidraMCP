package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Model representing the detailed definition of a Structure data type. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class StructureDetails extends BaseDataTypeDetails {

  private final int numComponents;

  private final List<ComponentMemberInfo> members;

  public StructureDetails(Structure struct) {
    super(
        DataTypeKind.STRUCTURE,
        struct.getPathName(),
        struct.getName(),
        struct.getCategoryPath().getPath(),
        struct.getLength(),
        struct.getAlignment(),
        Optional.ofNullable(struct.getDescription()).orElse(""));
    this.numComponents = struct.getNumComponents();

    List<ComponentMemberInfo> memberInfos = new ArrayList<>();
    for (DataTypeComponent component : struct.getDefinedComponents()) {
      memberInfos.add(new ComponentMemberInfo(component, true));
    }
    this.members = memberInfos;
  }

  @JsonProperty("num_components")
  public int getNumComponents() {
    return numComponents;
  }

  @JsonProperty("members")
  public List<ComponentMemberInfo> getMembers() {
    return members;
  }
}
