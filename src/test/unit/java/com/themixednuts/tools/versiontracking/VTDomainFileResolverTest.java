package com.themixednuts.tools.versiontracking;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.exceptions.GhidraMcpException;
import java.util.List;
import org.junit.jupiter.api.Test;

class VTDomainFileResolverTest {

  @Test
  void resolvesSessionByExplicitPathWhenNamesDuplicate() throws Exception {
    List<VTDomainFileResolver.FileDescriptor> files =
        List.of(
            new VTDomainFileResolver.FileDescriptor("analysis.vt", "/A/analysis.vt", "VersionTracking"),
            new VTDomainFileResolver.FileDescriptor("analysis.vt", "/B/analysis.vt", "VersionTracking"));

    String selectedPath =
        VTDomainFileResolver.selectUniquePath(
            files,
            "/B/analysis.vt",
            "session_name",
            "VT session",
            "VersionTracking",
            "hint");

    assertEquals("/B/analysis.vt", selectedPath);
  }

  @Test
  void rejectsAmbiguousSessionNameWithoutPath() {
    List<VTDomainFileResolver.FileDescriptor> files =
        List.of(
            new VTDomainFileResolver.FileDescriptor("analysis.vt", "/A/analysis.vt", "VersionTracking"),
            new VTDomainFileResolver.FileDescriptor("analysis.vt", "/B/analysis.vt", "VersionTracking"));

    GhidraMcpException ex =
        assertThrows(
            GhidraMcpException.class,
            () ->
                VTDomainFileResolver.selectUniquePath(
                    files,
                    "analysis.vt",
                    "session_name",
                    "VT session",
                    "VersionTracking",
                    "Provide full path"));

    assertTrue(ex.getMessage().contains("matches multiple VT session files"));
  }

  @Test
  void acceptsVtExtensionWhenContentTypeMissing() throws Exception {
    List<VTDomainFileResolver.FileDescriptor> files =
        List.of(new VTDomainFileResolver.FileDescriptor("session.vt", "/session.vt", null));

    String selectedPath =
        VTDomainFileResolver.selectUniquePath(
            files,
            "session.vt",
            "session_name",
            "VT session",
            "VersionTracking",
            "hint");

    assertEquals("/session.vt", selectedPath);
  }
}
