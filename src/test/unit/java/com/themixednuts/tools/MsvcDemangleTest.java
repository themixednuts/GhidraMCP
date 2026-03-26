package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import mdemangler.MDMangGhidra;
import mdemangler.MDParsableItem;
import mdemangler.naming.MDQualification;
import mdemangler.naming.MDQualifier;
import mdemangler.object.MDObjectCPP;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for MSVC symbol demangling via MDMangGhidra/MDObjectCPP. These verify the structured
 * AST extraction used by AnalyzeTool.performDemangling and processLambdaRttiEntry without requiring
 * a Ghidra runtime.
 */
class MsvcDemangleTest {

  // ── Helpers ──────────────────────────────────────────────────────────────────

  private record DemangleResult(
      MDParsableItem item,
      MDObjectCPP cppObj,
      String demangled,
      String name,
      String className,
      String namespace,
      boolean isConstructor,
      boolean isDestructor) {}

  /**
   * Demangles via MDMangGhidra and extracts structured fields exactly as AnalyzeTool does: first
   * qualifier = className, remaining qualifiers (reversed) = namespace.
   */
  private DemangleResult demangleSymbol(String mangled) throws Exception {
    MDMangGhidra mdm = new MDMangGhidra();
    mdm.setMangledSymbol(mangled);
    MDParsableItem item = mdm.demangle();
    assertNotNull(item, "demangle returned null for: " + mangled);

    String demangled = item.toString();
    assertNotNull(demangled, "toString returned null for: " + mangled);

    String name = null;
    String className = null;
    String namespace = null;
    boolean isCtor = false;
    boolean isDtor = false;

    MDObjectCPP cppObj = null;
    if (item instanceof MDObjectCPP cpp) {
      cppObj = cpp;
      name = cppObj.getName();
      if (cppObj.getQualifiedName() != null) {
        isCtor = cppObj.getQualifiedName().isConstructor();
        isDtor = cppObj.getQualifiedName().isDestructor();
      }

      MDQualification qual = cppObj.getQualification();
      if (qual != null) {
        StringBuilder nsBuilder = new StringBuilder();
        boolean first = true;
        for (MDQualifier qualifier : qual) {
          if (first) {
            className = qualifier.toString();
            first = false;
          } else {
            if (nsBuilder.length() > 0) nsBuilder.insert(0, "::");
            nsBuilder.insert(0, qualifier.toString());
          }
        }
        namespace = nsBuilder.length() > 0 ? nsBuilder.toString() : null;
      }
    }

    return new DemangleResult(item, cppObj, demangled, name, className, namespace, isCtor, isDtor);
  }

  /**
   * Extracts the enclosing function fragment from a lambda RTTI type descriptor, using the same
   * logic as AnalyzeTool.processLambdaRttiEntry.
   */
  private String extractEnclosingFragment(String mangledName) {
    // Lambda RTTI: .?AV<lambda_N>@?<scope>@??<function>@@...@Z@
    // Find the "??" that starts the enclosing function mangled name
    int idx = mangledName.indexOf("??", mangledName.indexOf("<lambda"));
    if (idx < 0) return null;
    // The fragment starts at "??" — strip one "?" to get a valid mangled symbol
    String fragment = mangledName.substring(idx + 1);
    // Trim trailing "@" that closes the lambda scope
    if (fragment.endsWith("@")) {
      fragment = fragment.substring(0, fragment.length() - 1);
    }
    return fragment;
  }

  // ── 1. Basic method names ──────────────────────────────────────────────────

  @Nested
  class BasicMethodNames {

    @Test
    void regularMethod() throws Exception {
      DemangleResult r = demangleSymbol("?Update@Entity@@UEAAXN@Z");
      assertEquals("Update", r.name());
      assertEquals("Entity", r.className());
    }

    @Test
    void namespacedMethod() throws Exception {
      DemangleResult r = demangleSymbol("?OnTick@TickComponent@AZ@@UEAAXM@Z");
      assertEquals("OnTick", r.name());
      assertEquals("TickComponent", r.className());
      assertEquals("AZ", r.namespace());
    }

    @Test
    void deeplyNestedNamespace() throws Exception {
      DemangleResult r = demangleSymbol("?Process@Handler@Network@Javelin@@QEAAXXZ");
      assertEquals("Process", r.name());
      assertEquals("Handler", r.className());
      assertEquals("Javelin::Network", r.namespace());
    }
  }

  // ── 2. Constructors and destructors ────────────────────────────────────────

  @Nested
  class ConstructorsAndDestructors {

    @Test
    void constructor() throws Exception {
      DemangleResult r = demangleSymbol("??0JavelinCVars@@QEAA@XZ");
      assertEquals("JavelinCVars", r.className());
      assertTrue(r.isConstructor(), "Expected constructor");
    }

    @Test
    void destructor() throws Exception {
      DemangleResult r = demangleSymbol("??1JavelinCVars@@QEAA@XZ");
      assertEquals("JavelinCVars", r.className());
      assertTrue(r.isDestructor(), "Expected destructor");
      assertTrue(r.name().contains("~"), "Destructor name should contain ~");
    }

    @Test
    void virtualDestructor() throws Exception {
      DemangleResult r = demangleSymbol("??1Component@AZ@@UEAA@XZ");
      assertEquals("Component", r.className());
      assertEquals("AZ", r.namespace());
      assertTrue(r.isDestructor(), "Expected destructor");
    }
  }

  // ── 3. Operators ───────────────────────────────────────────────────────────

  @Nested
  class Operators {

    @Test
    void operatorEquals() throws Exception {
      DemangleResult r = demangleSymbol("??8Entity@@QEBA_NAEBV0@@Z");
      assertEquals("operator==", r.name());
      assertEquals("Entity", r.className());
    }

    @Test
    void operatorLeftShift() throws Exception {
      // Global operator<< (no class)
      DemangleResult r = demangleSymbol("??6@YAAEAVostream@std@@AEAV01@AEBVEntity@@@Z");
      assertEquals("operator<<", r.name());
    }

    @Test
    void operatorCallParens() throws Exception {
      DemangleResult r = demangleSymbol("??RHandler@@QEAAXXZ");
      assertEquals("operator()", r.name());
      assertEquals("Handler", r.className());
    }

    @Test
    void operatorSubscript() throws Exception {
      DemangleResult r = demangleSymbol("??AContainer@@QEAAAEAVItem@@H@Z");
      assertEquals("operator[]", r.name());
      assertEquals("Container", r.className());
    }

    @Test
    void operatorArrow() throws Exception {
      DemangleResult r = demangleSymbol("??CSmartPtr@@QEAAPEAVEntity@@XZ");
      assertEquals("operator->", r.name());
      assertEquals("SmartPtr", r.className());
    }

    @Test
    void operatorTypeCast() throws Exception {
      DemangleResult r = demangleSymbol("??BEntity@@QEAAHXZ");
      assertEquals("operator int", r.name());
      assertEquals("Entity", r.className());
    }
  }

  // ── 4. Template functions ──────────────────────────────────────────────────

  @Nested
  class TemplateFunctions {

    @Test
    void templateMethod() throws Exception {
      DemangleResult r =
          demangleSymbol(
              "??$CreateDataInterface@UHandToWeaponIKData@CharacterModuleData@Javelin@@@SlayerScriptData@Module@SlayerScript@@QEAAPEAUHandToWeaponIKData@CharacterModuleData@Javelin@@XZ");
      assertEquals(
          "CreateDataInterface<struct Javelin::CharacterModuleData::HandToWeaponIKData>", r.name());
      assertEquals("SlayerScriptData", r.className());
      assertEquals("SlayerScript::Module", r.namespace());
    }

    @Test
    void templateFreeFunction() throws Exception {
      DemangleResult r =
          demangleSymbol("??$InstallRegistrationHook@VWeapon@Javelin@@@Hub@Amazon@@YA_NXZ");
      assertEquals("InstallRegistrationHook<class Javelin::Weapon>", r.name());
      assertEquals("Hub", r.className());
      assertEquals("Amazon", r.namespace());
    }
  }

  // ── 5. RTTI type descriptors ───────────────────────────────────────────────

  @Nested
  class RttiTypeDescriptors {

    @Test
    void rttiClass() throws Exception {
      DemangleResult r = demangleSymbol(".?AVJavelinCVars@@");
      assertEquals("class JavelinCVars", r.demangled());
    }

    @Test
    void rttiNamespacedClass() throws Exception {
      DemangleResult r =
          demangleSymbol(".?AVJavelinGatewayServiceRequest@JavelinGatewayService@Aws@@");
      assertEquals("class Aws::JavelinGatewayService::JavelinGatewayServiceRequest", r.demangled());
    }

    @Test
    void rttiStruct() throws Exception {
      DemangleResult r = demangleSymbol(".?AUClientDisconnectInfo@Aoi@@");
      assertEquals("struct Aoi::ClientDisconnectInfo", r.demangled());
    }

    @Test
    void rttiEnum() throws Exception {
      DemangleResult r = demangleSymbol(".?AW4PaperdollSlotTypes@Javelin@@");
      assertEquals("enum Javelin::PaperdollSlotTypes", r.demangled());
    }

    @Test
    void rttiVtable() throws Exception {
      DemangleResult r = demangleSymbol("??_7JavelinCVars@@6B@");
      assertEquals("const JavelinCVars::`vftable'", r.demangled());
    }
  }

  // ── 6. Lambda RTTI — enclosing function extraction ─────────────────────────

  @Nested
  class LambdaEnclosingFunctions {

    @Test
    void extractMethodFromLambdaRtti() throws Exception {
      String fragment =
          "?OnPlayerDisconnected@TransmogComponentServerFacet@Javelin@@UEAAXAEBUClientDisconnectInfo@Aoi@@@Z";
      DemangleResult r = demangleSymbol(fragment);
      assertEquals("OnPlayerDisconnected", r.name());
      assertEquals("TransmogComponentServerFacet", r.className());
      assertEquals("Javelin", r.namespace());
    }

    @Test
    void extractConstructorFromLambdaScope() throws Exception {
      DemangleResult r = demangleSymbol("??0JavelinCVars@@QEAA@XZ");
      assertTrue(r.isConstructor(), "Expected constructor");
      assertEquals("JavelinCVars", r.className());
    }

    @Test
    void extractTemplateFromLambdaScope() throws Exception {
      DemangleResult r =
          demangleSymbol("??$InstallRegistrationHook@VWeapon@Javelin@@@Hub@Amazon@@YA_NXZ");
      assertTrue(
          r.name().contains("InstallRegistrationHook"),
          "Expected InstallRegistrationHook in name: " + r.name());
    }

    @Test
    void fragmentExtractionFromFullLambdaRtti() {
      String lambdaRtti =
          ".?AV<lambda_1>@?L@??OnPlayerDisconnected@TransmogComponentServerFacet@Javelin@@UEAAXAEBUClientDisconnectInfo@Aoi@@@Z@";
      String fragment = extractEnclosingFragment(lambdaRtti);
      assertNotNull(fragment, "Should extract enclosing function fragment");
      assertTrue(
          fragment.startsWith("?OnPlayerDisconnected"),
          "Fragment should start with function name: " + fragment);
    }
  }

  // ── 7. NewWorld-specific real symbols ──────────────────────────────────────

  @Nested
  class NewWorldRealSymbols {

    @Test
    void weaponInstantiate() throws Exception {
      String lambdaRtti =
          ".?AV<lambda_1>@?L@??Instantiate@Weapon@Javelin@@UEAAXAEBVLocalEntityRef@MB@@W4PaperdollSlotTypes@3@V?$function@$$A6AXVEntityId@AZ@@@Z@AZStd@@@Z@";
      String fragment = extractEnclosingFragment(lambdaRtti);
      assertNotNull(fragment, "Should extract fragment");
      DemangleResult r = demangleSymbol(fragment);
      assertEquals("Instantiate", r.name());
      assertEquals("Weapon", r.className());
      assertEquals("Javelin", r.namespace());
    }

    @Test
    void weaponAttributesToJson() throws Exception {
      String lambdaRtti =
          ".?AV<lambda_1>@?L@??AttributesToJson@Weapon@Javelin@@QEBA?AV?$GenericValue@U?$UTF8@D@rapidjson_ly@@VCrtAllocator@2@@rapidjson_ly@@XZ@";
      String fragment = extractEnclosingFragment(lambdaRtti);
      assertNotNull(fragment, "Should extract fragment");
      DemangleResult r = demangleSymbol(fragment);
      assertEquals("AttributesToJson", r.name());
      assertEquals("Weapon", r.className());
      assertEquals("Javelin", r.namespace());
    }

    @Test
    void weaponGetCoreDamageForOwner() throws Exception {
      String lambdaRtti =
          ".?AV<lambda_1>@?1??GetCoreDamageForOwner@Weapon@Javelin@@QEBAMVEntityId@AZ@@HHHH_NPEBV?$fixed_vector@H$04@AZStd@@@Z@";
      String fragment = extractEnclosingFragment(lambdaRtti);
      assertNotNull(fragment, "Should extract fragment");
      DemangleResult r = demangleSymbol(fragment);
      assertEquals("GetCoreDamageForOwner", r.name());
      assertEquals("Weapon", r.className());
      assertEquals("Javelin", r.namespace());
    }

    @Test
    void transmogOnPlayerDisconnected() throws Exception {
      String lambdaRtti =
          ".?AV<lambda_1>@?L@??OnPlayerDisconnected@TransmogComponentServerFacet@Javelin@@UEAAXAEBUClientDisconnectInfo@Aoi@@@Z@";
      String fragment = extractEnclosingFragment(lambdaRtti);
      assertNotNull(fragment, "Should extract fragment");
      DemangleResult r = demangleSymbol(fragment);
      assertEquals("OnPlayerDisconnected", r.name());
      assertEquals("TransmogComponentServerFacet", r.className());
      assertEquals("Javelin", r.namespace());
    }
  }

  // ── 8. Edge cases ──────────────────────────────────────────────────────────

  @Nested
  class EdgeCases {

    @Test
    void globalFunction() throws Exception {
      // Global function with no class: void __cdecl foo(int)
      DemangleResult r = demangleSymbol("?foo@@YAXH@Z");
      assertEquals("foo", r.name());
      // No class for global functions
    }

    @Test
    void staticMemberVariable() throws Exception {
      // Static member: int Foo::bar
      DemangleResult r = demangleSymbol("?bar@Foo@@2HA");
      assertEquals("bar", r.name());
      assertEquals("Foo", r.className());
    }

    @Test
    void demangledStringIsNonEmpty() throws Exception {
      // Verify that all test symbols produce non-empty demangled strings
      String[] symbols = {
        "?Update@Entity@@UEAAXN@Z",
        "??0JavelinCVars@@QEAA@XZ",
        "??1JavelinCVars@@QEAA@XZ",
        "??8Entity@@QEBA_NAEBV0@@Z",
        ".?AVJavelinCVars@@",
        "??_7JavelinCVars@@6B@",
      };
      for (String sym : symbols) {
        DemangleResult r = demangleSymbol(sym);
        assertNotNull(r.demangled(), "demangled should not be null for: " + sym);
        assertTrue(!r.demangled().isBlank(), "demangled should not be blank for: " + sym);
      }
    }

    @Test
    void qualificationOrderMatchesAnalyzeTool() throws Exception {
      // Verify that the qualification iteration order matches how AnalyzeTool
      // builds namespace: first = className, rest reversed = namespace
      DemangleResult r = demangleSymbol("?Process@Handler@Network@Javelin@@QEAAXXZ");
      // AnalyzeTool logic: first qualifier = Handler (class), then Network, Javelin
      // Namespace built by prepending: "Network" then "Javelin::Network"
      assertEquals("Handler", r.className());
      assertEquals("Javelin::Network", r.namespace());

      // Verify the raw qualifier list order
      MDObjectCPP cpp = r.cppObj();
      assertNotNull(cpp);
      List<String> qualNames = new ArrayList<>();
      for (MDQualifier q : cpp.getQualification()) {
        qualNames.add(q.toString());
      }
      assertEquals(List.of("Handler", "Network", "Javelin"), qualNames);
    }
  }
}
