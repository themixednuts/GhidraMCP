package com.themixednuts.ui;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/** Tool payload plus UI effects that should be applied after successful execution. */
public record ToolOutcome<T>(T data, List<GhidraUiEffect> uiEffects) {

  public ToolOutcome {
    uiEffects = uiEffects == null ? List.of() : List.copyOf(uiEffects);
  }

  public static <T> ToolOutcome<T> of(T data, GhidraUiEffect... uiEffects) {
    return new ToolOutcome<>(data, uiEffects == null ? List.of() : Arrays.asList(uiEffects));
  }

  public static <T> ToolOutcome<T> of(T data, Collection<? extends GhidraUiEffect> uiEffects) {
    return new ToolOutcome<>(data, uiEffects == null ? List.of() : List.copyOf(uiEffects));
  }
}
