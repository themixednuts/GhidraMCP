package com.themixednuts.ui;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.Swing;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/** Applies tool side effects to the active Ghidra UI. */
public final class GhidraUiCoordinator {

  private GhidraUiCoordinator() {}

  public static void applyBestEffort(
      Object logSource, PluginTool tool, List<GhidraUiEffect> effects) {
    if (effects == null || effects.isEmpty()) {
      return;
    }

    try {
      applyRequired(tool, effects);
    } catch (GhidraMcpException e) {
      Msg.warn(logSource, "Unable to apply Ghidra UI effect: " + e.getMessage());
    }
  }

  public static void applyRequired(PluginTool tool, List<GhidraUiEffect> effects)
      throws GhidraMcpException {
    if (effects == null || effects.isEmpty()) {
      return;
    }

    AtomicReference<Throwable> failure = new AtomicReference<>();
    Swing.runNow(
        () -> {
          try {
            for (GhidraUiEffect effect : effects) {
              applyOne(tool, effect);
            }
          } catch (Throwable t) {
            failure.set(t);
          }
        });

    if (failure.get() != null) {
      if (failure.get() instanceof GhidraMcpException e) {
        throw e;
      }
      throw new GhidraMcpException(
          GhidraMcpError.failed("apply UI effect", failure.get().getMessage()), failure.get());
    }
  }

  public static void applyRequired(PluginTool tool, GhidraUiEffect effect)
      throws GhidraMcpException {
    applyRequired(tool, List.of(effect));
  }

  private static void applyOne(PluginTool tool, GhidraUiEffect effect) throws GhidraMcpException {
    if (effect == null) {
      throw new GhidraMcpException(GhidraMcpError.of("UI effect must not be null."));
    }

    if (effect instanceof NavigateToAddressEffect navigate) {
      navigate(tool, navigate);
      return;
    }

    if (effect instanceof NavigateDebuggerAddressEffect navigateDebugger) {
      navigateDebugger(tool, navigateDebugger);
      return;
    }

    throw new GhidraMcpException(GhidraMcpError.of("Unsupported UI effect: " + effect.kind()));
  }

  private static void navigate(PluginTool tool, NavigateToAddressEffect effect)
      throws GhidraMcpException {
    GoToService goToService = tool != null ? tool.getService(GoToService.class) : null;
    if (goToService == null) {
      throw new GhidraMcpException(
          GhidraMcpError.of("GoToService is not available in the current tool context."));
    }

    boolean success = goToService.goTo(effect.address(), effect.program());
    if (!success) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "navigate to address " + effect.address(),
              "ensure Listing or Decompiler views are open"));
    }
  }

  private static void navigateDebugger(PluginTool tool, NavigateDebuggerAddressEffect effect)
      throws GhidraMcpException {
    DebuggerListingService listingService =
        tool != null ? tool.getService(DebuggerListingService.class) : null;
    if (listingService == null) {
      throw new GhidraMcpException(
          GhidraMcpError.of(
              "DebuggerListingService is not available in the current tool context."));
    }

    boolean success = listingService.goTo(effect.address(), effect.focus());
    if (!success) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "navigate debugger listing to address " + effect.address(),
              "ensure the Debugger listing view is open"));
    }
  }
}
