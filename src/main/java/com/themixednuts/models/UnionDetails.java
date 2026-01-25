package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Union;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Model representing the detailed definition of a Union data type. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UnionDetails extends BaseDataTypeDetails {

  private final int numComponents;
  private final List<ComponentMemberInfo> members;

  public UnionDetails(Union unionDt) {
    super(
        DataTypeKind.UNION,
        unionDt.getPathName(),
        unionDt.getName(),
        unionDt.getCategoryPath().getPath(),
        unionDt.getLength(),
        unionDt.getAlignment(),
        Optional.ofNullable(unionDt.getDescription()).orElse(""));
    this.numComponents = unionDt.getNumComponents();

    List<ComponentMemberInfo> memberInfos = new ArrayList<>();
    for (DataTypeComponent component : unionDt.getComponents()) {
      memberInfos.add(new ComponentMemberInfo(component, false));
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
