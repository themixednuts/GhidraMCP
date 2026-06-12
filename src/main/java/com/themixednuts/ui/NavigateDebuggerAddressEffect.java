package com.themixednuts.ui;

import ghidra.program.model.address.Address;
import java.util.Objects;

/** Navigate the active Debugger listing to a trace address. */
public record NavigateDebuggerAddressEffect(Address address, boolean focus)
    implements GhidraUiEffect {

  public NavigateDebuggerAddressEffect {
    Objects.requireNonNull(address, "address");
  }

  public static NavigateDebuggerAddressEffect listing(Address address) {
    return new NavigateDebuggerAddressEffect(address, true);
  }

  @Override
  public String kind() {
    return "navigate_debugger_address";
  }
}
