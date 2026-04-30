package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Pure-data coverage of {@link AnalyzeTool#applyCustomTags} and {@link
 * AnalyzeTool#getCustomTagsForMangled}. The earlier implementation looked tags up by a re-derived
 * inner-class name and silently dropped them when the lookup-side and storage-side names didn't
 * round-trip identically through MDMang. These tests pin the fixed behavior — substring match on
 * the mangled name itself, tag attached to the matching row's mangled key — so the regression can't
 * sneak back unnoticed.
 */
class AnalyzeToolCustomTagsTest {

  private AnalyzeTool tool;
  private Map<String, Set<String>> mangledCustomTags;

  @BeforeEach
  void setUp() {
    tool = new AnalyzeTool();
    mangledCustomTags = new LinkedHashMap<>();
  }

  @Nested
  @DisplayName("applyCustomTags")
  class ApplyCustomTags {

    @Test
    @DisplayName("tags the matching mangled name when the template substring is present")
    void tagsWrapperWhenTemplateMatches() {
      Map<String, String> templateToTag = Map.of("InstallRegistrationHook", "registered_type");
      String mangled = ".?AV?$InstallRegistrationHook@VGridManagerActor@Aoi@@@@";

      tool.applyCustomTags(mangled, templateToTag, mangledCustomTags);

      assertEquals(Set.of("registered_type"), mangledCustomTags.get(mangled));
    }

    @Test
    @DisplayName("does not tag entries whose mangled name lacks the template substring")
    void leavesUnrelatedEntriesAlone() {
      Map<String, String> templateToTag = Map.of("InstallRegistrationHook", "registered_type");
      String mangled = ".?AVUnrelatedClass@@";

      tool.applyCustomTags(mangled, templateToTag, mangledCustomTags);

      assertTrue(mangledCustomTags.isEmpty());
    }

    @Test
    @DisplayName("attaches multiple tags from multiple matching templates to one row")
    void mergesTagsFromOverlappingTemplates() {
      Map<String, String> templateToTag = new LinkedHashMap<>();
      templateToTag.put("InstallRegistrationHook", "registered_type");
      templateToTag.put("ContractsComponent", "contracts_component");
      String mangled = ".?AV?$InstallRegistrationHook@V?$ContractsComponent@VFoo@@@@@@";

      tool.applyCustomTags(mangled, templateToTag, mangledCustomTags);

      assertEquals(
          Set.of("registered_type", "contracts_component"), mangledCustomTags.get(mangled));
    }

    @Test
    @DisplayName("dedupes when the same template appears across multiple invocations")
    void dedupesRepeatedApplication() {
      Map<String, String> templateToTag = Map.of("InstallRegistrationHook", "registered_type");
      String mangled = ".?AV?$InstallRegistrationHook@VGridManagerActor@Aoi@@@@";

      tool.applyCustomTags(mangled, templateToTag, mangledCustomTags);
      tool.applyCustomTags(mangled, templateToTag, mangledCustomTags);

      assertEquals(1, mangledCustomTags.get(mangled).size());
    }

    @Test
    @DisplayName("namespaced inner classes still tag the wrapper row exactly once")
    void namespacedInnerClassesDoNotConfuseLookup() {
      // Pre-fix bug: applyCustomTags ran MDMang on the inner type-arg and stored under the bare
      // class name; the row builder looked up by the wrapper's class name, so the tag never
      // surfaced. The fix keys on the full mangled name so the namespace inside the template arg
      // is irrelevant.
      Map<String, String> templateToTag = Map.of("InstallRegistrationHook", "registered_type");
      String mangled = ".?AV?$InstallRegistrationHook@VGridManagerActor@Aoi@@@@";

      tool.applyCustomTags(mangled, templateToTag, mangledCustomTags);

      assertEquals(Set.of("registered_type"), mangledCustomTags.get(mangled));
      assertEquals(1, mangledCustomTags.size(), "tag should land on the wrapper, not a 2nd row");
    }

    @Test
    @DisplayName("null and empty mangled names are no-ops")
    void nullOrEmptyMangledIsNoOp() {
      Map<String, String> templateToTag = Map.of("X", "y");

      tool.applyCustomTags(null, templateToTag, mangledCustomTags);
      tool.applyCustomTags("", templateToTag, mangledCustomTags);

      assertTrue(mangledCustomTags.isEmpty());
    }

    @Test
    @DisplayName("empty templateToTag map leaves the accumulator untouched")
    void emptyTemplateMapIsNoOp() {
      tool.applyCustomTags(".?AVAnything@@", Map.of(), mangledCustomTags);

      assertTrue(mangledCustomTags.isEmpty());
    }
  }

  @Nested
  @DisplayName("getCustomTagsForMangled")
  class GetCustomTagsForMangled {

    @Test
    @DisplayName("returns the tags associated with a mangled key in stable insertion order")
    void returnsStoredTagsInOrder() {
      String mangled = ".?AV?$InstallRegistrationHook@VFoo@@@@";
      Set<String> tags = new LinkedHashSet<>();
      tags.add("registered_type");
      tags.add("contracts_component");
      mangledCustomTags.put(mangled, tags);

      List<String> result = tool.getCustomTagsForMangled(mangledCustomTags, mangled);

      assertEquals(List.of("registered_type", "contracts_component"), result);
    }

    @Test
    @DisplayName("returns an empty list (not null) when the mangled name is absent")
    void missingMangledReturnsEmptyList() {
      List<String> result = tool.getCustomTagsForMangled(mangledCustomTags, ".?AVNoTag@@");

      assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("returns an empty list when the mangled name argument is null")
    void nullMangledReturnsEmptyList() {
      List<String> result = tool.getCustomTagsForMangled(mangledCustomTags, null);

      assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("returns an empty list when the stored tag set is empty")
    void emptyStoredTagSetReturnsEmptyList() {
      String mangled = ".?AVEmpty@@";
      mangledCustomTags.put(mangled, new LinkedHashSet<>());

      List<String> result = tool.getCustomTagsForMangled(mangledCustomTags, mangled);

      assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("end-to-end: apply then lookup round-trips for a wrapper entry")
    void applyThenLookupRoundTrips() {
      Map<String, String> templateToTag = Map.of("sp_ms_deleter", "smart_ptr_managed");
      String mangled = ".?AV?$sp_ms_deleter@VRefCountedThing@@@@";

      tool.applyCustomTags(mangled, templateToTag, mangledCustomTags);
      List<String> result = tool.getCustomTagsForMangled(mangledCustomTags, mangled);

      assertEquals(List.of("smart_ptr_managed"), result);
    }
  }
}
