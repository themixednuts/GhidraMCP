package com.themixednuts.tools.versiontracking;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.models.OperationResult;
import ghidra.framework.model.DomainFile;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import org.junit.jupiter.api.Test;

class ManageVTSessionToolTest {

  @Test
  void closeResultReportsSessionStillOpenByAnotherConsumer() {
    OperationResult result = ManageVTSessionTool.closeResult("analysis.vt", true);

    assertEquals("close", result.getOperation());
    assertEquals("analysis.vt", result.getTarget());
    assertTrue(result.getMessage().contains("remains open by another consumer"));
  }

  @Test
  void closeResultReportsClosedWhenNoOtherConsumer() {
    OperationResult result = ManageVTSessionTool.closeResult("analysis.vt", false);

    assertEquals("close", result.getOperation());
    assertEquals("analysis.vt", result.getTarget());
    assertEquals("Session closed successfully", result.getMessage());
  }

  @Test
  void normalizeProjectPathCanonicalizesSeparatorsAndLeadingSlash() {
    assertEquals("A/B/session.vt", ManageVTSessionTool.normalizeProjectPath("/A/B/session.vt"));
    assertEquals("A/B/session.vt", ManageVTSessionTool.normalizeProjectPath("\\A\\B\\session.vt"));
    assertEquals("A/B/session.vt", ManageVTSessionTool.normalizeProjectPath("  /A/B/session.vt  "));
  }

  @Test
  void sameDomainFilePathTreatsEquivalentPathsAsEqual() {
    DomainFile first = fakeDomainFile("/A/B/session.vt");
    DomainFile second = fakeDomainFile("\\A\\B\\session.vt");

    assertTrue(ManageVTSessionTool.sameDomainFilePath(first, second));
  }

  @Test
  void sameDomainFilePathDetectsDifferentFiles() {
    DomainFile first = fakeDomainFile("/A/B/session.vt");
    DomainFile second = fakeDomainFile("/A/C/session.vt");

    assertFalse(ManageVTSessionTool.sameDomainFilePath(first, second));
  }

  private static DomainFile fakeDomainFile(String pathname) {
    InvocationHandler handler =
        (Object proxy, Method method, Object[] args) -> {
          if ("getPathname".equals(method.getName())) {
            return pathname;
          }
          throw new UnsupportedOperationException(method.getName());
        };

    return (DomainFile)
        Proxy.newProxyInstance(
            DomainFile.class.getClassLoader(), new Class<?>[] {DomainFile.class}, handler);
  }
}
