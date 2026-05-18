package com.themixednuts.tools.versiontracking;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.GhidraAddressParser;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.math.BigInteger;

/** Shared helpers for VT address parsing and match resolution. */
public final class VTMatchResolver {

  record ResolvedMatch(VTMatchSet matchSet, VTMatch match) {}

  private VTMatchResolver() {}

  static ResolvedMatch findMatch(
      VTSession session,
      String sourceAddrStr,
      String destAddrStr,
      String sourceArgumentName,
      String destinationArgumentName)
      throws GhidraMcpException {
    Program sourceProgram = session.getSourceProgram();
    Program destProgram = session.getDestinationProgram();

    Address sourceAddr = parseAddress(sourceProgram, sourceAddrStr, sourceArgumentName);
    Address destAddr = parseAddress(destProgram, destAddrStr, destinationArgumentName);

    for (VTMatchSet matchSet : session.getMatchSets()) {
      for (VTMatch match : matchSet.getMatches()) {
        if (match.getAssociation().getSourceAddress().equals(sourceAddr)
            && match.getAssociation().getDestinationAddress().equals(destAddr)) {
          return new ResolvedMatch(matchSet, match);
        }
      }
    }

    throw new GhidraMcpException(
        GhidraMcpError.notFound("match", sourceAddrStr + " -> " + destAddrStr));
  }

  static Address parseAddress(Program program, String addressString, String argumentName)
      throws GhidraMcpException {
    return GhidraAddressParser.parse(program, addressString, argumentName);
  }

  static int countMatchesWithStatus(VTSession session, VTAssociationStatus status) {
    int count = 0;
    for (VTMatchSet matchSet : session.getMatchSets()) {
      for (VTMatch match : matchSet.getMatches()) {
        if (match.getAssociation().getStatus() == status) {
          count++;
        }
      }
    }
    return count;
  }

  /**
   * Normalizes a Ghidra-style address string for robust equality checks.
   *
   * <p>Examples that normalize to the same value: {@code 0x401000}, {@code 00401000}, {@code
   * ram:00401000}.
   */
  public static String normalizeAddressHex(String address) {
    if (address == null) {
      return "";
    }

    String normalized = address.trim();
    int separatorIndex = normalized.indexOf(':');
    if (separatorIndex >= 0) {
      normalized = normalized.substring(separatorIndex + 1);
    }

    if (normalized.startsWith("0x") || normalized.startsWith("0X")) {
      normalized = normalized.substring(2);
    }

    try {
      return new BigInteger(normalized, 16).toString(16);
    } catch (NumberFormatException e) {
      return normalized.toLowerCase();
    }
  }
}
