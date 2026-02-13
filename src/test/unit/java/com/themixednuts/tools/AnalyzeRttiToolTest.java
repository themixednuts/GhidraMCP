package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.models.RTTIAnalysisResult;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AnalyzeRttiToolTest {

  @Test
  void buildFailureSummaryReturnsDefaultWhenNoFailuresProvided() {
    assertEquals(
        "No valid RTTI structure found at address", AnalyzeRttiTool.buildFailureSummary(Map.of()));
  }

  @Test
  void buildFailureSummaryIncludesAttemptOrderAndReasons() {
    Map<RTTIAnalysisResult.RttiType, String> reasons = new LinkedHashMap<>();
    reasons.put(RTTIAnalysisResult.RttiType.RTTI4, "invalid signature");
    reasons.put(RTTIAnalysisResult.RttiType.RTTI3, "missing reference");

    String summary = AnalyzeRttiTool.buildFailureSummary(reasons);

    assertTrue(summary.contains("RTTI4=invalid signature"));
    assertTrue(summary.contains("RTTI3=missing reference"));
    assertTrue(summary.indexOf("RTTI4=invalid signature") < summary.indexOf("RTTI3=missing reference"));
  }

  @Test
  void classifyItaniumTypeInfoKindDetectsSpecialTypeInfoKinds() {
    assertEquals(
        RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO,
        AnalyzeRttiTool.classifyItaniumTypeInfoKind(
            "_ZTVN10__cxxabiv117__class_type_infoE",
            "vtable for __cxxabiv1::__class_type_info"));
    assertEquals(
        RTTIAnalysisResult.RttiType.ITANIUM_SI_CLASS_TYPEINFO,
        AnalyzeRttiTool.classifyItaniumTypeInfoKind(
            "_ZTVN10__cxxabiv120__si_class_type_infoE",
            "vtable for __cxxabiv1::__si_class_type_info"));
    assertEquals(
        RTTIAnalysisResult.RttiType.ITANIUM_VMI_CLASS_TYPEINFO,
        AnalyzeRttiTool.classifyItaniumTypeInfoKind(
            "_ZTVN10__cxxabiv121__vmi_class_type_infoE",
            "vtable for __cxxabiv1::__vmi_class_type_info"));
  }

  @Test
  void itaniumSymbolHeuristicsMatchMangledPrefixes() {
    assertTrue(AnalyzeRttiTool.looksLikeItaniumTypeInfoSymbol("_ZTI3Foo"));
    assertTrue(AnalyzeRttiTool.looksLikeItaniumVtableSymbol("_ZTV3Foo"));
    assertTrue(AnalyzeRttiTool.looksLikeItaniumTypeInfoDemangled("typeinfo for Foo"));
    assertTrue(AnalyzeRttiTool.looksLikeItaniumVtableDemangled("vtable for Foo"));
  }

  @Test
  void extractTypeFromDemangledTypeInfoReturnsTypeNameOnly() {
    assertEquals(
        "std::vector<int>",
        AnalyzeRttiTool.extractTypeFromDemangledTypeInfo(
                java.util.Optional.of("typeinfo for std::vector<int>"))
            .orElseThrow());
  }
}
