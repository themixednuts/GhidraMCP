package com.themixednuts.ui;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.Objects;

/** Navigate the active Ghidra tool to a static program address. */
public record NavigateToAddressEffect(
    Program program, Address address, GhidraUiView preferredView, boolean focus)
    implements GhidraUiEffect {

  public NavigateToAddressEffect {
    Objects.requireNonNull(program, "program");
    Objects.requireNonNull(address, "address");
    if (preferredView == null) {
      preferredView = GhidraUiView.LISTING;
    }
  }

  public static NavigateToAddressEffect listing(Program program, Address address) {
    return new NavigateToAddressEffect(program, address, GhidraUiView.LISTING, true);
  }

  public static NavigateToAddressEffect decompiler(Program program, Address address) {
    return new NavigateToAddressEffect(program, address, GhidraUiView.DECOMPILER, true);
  }

  @Override
  public String kind() {
    return "navigate_to_address";
  }
}
