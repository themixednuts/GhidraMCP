package com.themixednuts.ui;

/** Marker for UI work that should be reflected in the user's active Ghidra tool. */
public interface GhidraUiEffect {
  String kind();
}
