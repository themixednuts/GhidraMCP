package com.themixednuts.utils;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.math.BigInteger;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Shared parser for user-facing Ghidra address arguments. */
public final class GhidraAddressParser {

  public static final String ADDRESS_PATTERN =
      "^(\\+(0[xX])?[0-9a-fA-F]+|([A-Za-z_][A-Za-z0-9_]*:)?(0[xX])?[0-9a-fA-F]+)$";

  private static final Pattern IMAGE_BASE_OFFSET_PATTERN =
      Pattern.compile("^\\+(?:0[xX])?([0-9a-fA-F]+)$");

  private GhidraAddressParser() {}

  /**
   * Parses the address forms users commonly provide:
   *
   * <ul>
   *   <li>Ghidra absolute address strings, including address-space-qualified values.
   *   <li>{@code +0xNNN} / {@code +NNN} image-base-relative hex offsets.
   * </ul>
   */
  public static Address parse(Program program, String addressString, String argumentName)
      throws GhidraMcpException {
    String input = addressString == null ? "" : addressString.trim();
    if (input.isEmpty()) {
      throw parseError(argumentName, addressString);
    }

    try {
      Matcher imageBaseOffset = IMAGE_BASE_OFFSET_PATTERN.matcher(input);
      if (imageBaseOffset.matches()) {
        Address imageBase = program.getImageBase();
        if (imageBase == null) {
          throw new GhidraMcpException(
              GhidraMcpError.invalid(
                  argumentName, addressString, "program does not expose an image base"));
        }
        return imageBase.addNoWrap(new BigInteger(imageBaseOffset.group(1), 16));
      }

      Address address = program.getAddressFactory().getAddress(input);
      if (address == null) {
        throw parseError(argumentName, addressString);
      }
      return address;
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw parseError(argumentName, addressString);
    }
  }

  public static Optional<Address> tryParse(Program program, String addressString) {
    try {
      return Optional.of(parse(program, addressString, "address"));
    } catch (GhidraMcpException e) {
      return Optional.empty();
    }
  }

  private static GhidraMcpException parseError(String argumentName, String addressString) {
    return new GhidraMcpException(GhidraMcpError.parse(argumentName, addressString));
  }
}
