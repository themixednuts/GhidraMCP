package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.List;

@JsonPropertyOrder({
  "name",
  "mangled",
  "type_kind",
  "rtti0_address",
  "method_count",
  "base_class_count",
  "custom_tags",
  "is_lambda",
  "enclosing_method_name",
  "enclosing_method_class",
  "enclosing_method_namespace",
  "enclosing_method_demangled",
  "enclosing_method_address",
  "enclosing_method_candidate_addresses"
})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RttiListEntry {

  private final String name;
  private final String mangled;
  private final String typeKind;
  private final String rtti0Address;
  private final Integer methodCount;
  private final Integer baseClassCount;
  private final List<String> customTags;
  private final Boolean isLambda;
  private final String enclosingMethodName;
  private final String enclosingMethodClass;
  private final String enclosingMethodNamespace;
  private final String enclosingMethodDemangled;
  private final String enclosingMethodAddress;
  private final String enclosingMethodCandidateAddresses;

  public RttiListEntry(
      String name,
      String mangled,
      String typeKind,
      String rtti0Address,
      Integer methodCount,
      Integer baseClassCount,
      List<String> customTags,
      Boolean isLambda,
      String enclosingMethodName,
      String enclosingMethodClass,
      String enclosingMethodNamespace,
      String enclosingMethodDemangled,
      String enclosingMethodAddress,
      String enclosingMethodCandidateAddresses) {
    this.name = name;
    this.mangled = mangled;
    this.typeKind = typeKind;
    this.rtti0Address = rtti0Address;
    this.methodCount = methodCount;
    this.baseClassCount = baseClassCount;
    this.customTags = customTags;
    this.isLambda = isLambda;
    this.enclosingMethodName = enclosingMethodName;
    this.enclosingMethodClass = enclosingMethodClass;
    this.enclosingMethodNamespace = enclosingMethodNamespace;
    this.enclosingMethodDemangled = enclosingMethodDemangled;
    this.enclosingMethodAddress = enclosingMethodAddress;
    this.enclosingMethodCandidateAddresses = enclosingMethodCandidateAddresses;
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("mangled")
  public String getMangled() {
    return mangled;
  }

  @JsonProperty("type_kind")
  public String getTypeKind() {
    return typeKind;
  }

  @JsonProperty("rtti0_address")
  public String getRtti0Address() {
    return rtti0Address;
  }

  @JsonProperty("method_count")
  public Integer getMethodCount() {
    return methodCount;
  }

  @JsonProperty("base_class_count")
  public Integer getBaseClassCount() {
    return baseClassCount;
  }

  @JsonProperty("custom_tags")
  public List<String> getCustomTags() {
    return customTags;
  }

  @JsonProperty("is_lambda")
  public Boolean getIsLambda() {
    return isLambda;
  }

  @JsonProperty("enclosing_method_name")
  public String getEnclosingMethodName() {
    return enclosingMethodName;
  }

  @JsonProperty("enclosing_method_class")
  public String getEnclosingMethodClass() {
    return enclosingMethodClass;
  }

  @JsonProperty("enclosing_method_namespace")
  public String getEnclosingMethodNamespace() {
    return enclosingMethodNamespace;
  }

  @JsonProperty("enclosing_method_demangled")
  public String getEnclosingMethodDemangled() {
    return enclosingMethodDemangled;
  }

  @JsonProperty("enclosing_method_address")
  public String getEnclosingMethodAddress() {
    return enclosingMethodAddress;
  }

  @JsonProperty("enclosing_method_candidate_addresses")
  public String getEnclosingMethodCandidateAddresses() {
    return enclosingMethodCandidateAddresses;
  }
}
