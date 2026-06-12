package com.themixednuts.utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class GhidraAddressParserTest {

  @Mock private Program program;
  @Mock private AddressFactory addressFactory;
  @Mock private Address imageBase;
  @Mock private Address parsedAddress;
  @Mock private Address imageBaseRelativeAddress;

  @Test
  void addressPatternAcceptsImageBaseRelativeFormsUsedByDebuggerNotes() {
    assertTrue("+0x17B2430".matches(GhidraAddressParser.ADDRESS_PATTERN));
    assertTrue("+17B2430".matches(GhidraAddressParser.ADDRESS_PATTERN));
    assertTrue("NewWorld+0x17B2430".matches(GhidraAddressParser.ADDRESS_PATTERN));
    assertTrue("NewWorld.exe + 17B2430".matches(GhidraAddressParser.ADDRESS_PATTERN));
    assertTrue("ram:0x17B2430".matches(GhidraAddressParser.ADDRESS_PATTERN));

    assertFalse("NewWorld".matches(GhidraAddressParser.ADDRESS_PATTERN));
  }

  @Test
  void parseTreatsModulePrefixedPlusOffsetsAsImageBaseRelative() throws Exception {
    when(program.getImageBase()).thenReturn(imageBase);
    when(imageBase.addNoWrap(new BigInteger("17B2430", 16))).thenReturn(imageBaseRelativeAddress);

    Address result = GhidraAddressParser.parse(program, "NewWorld+0x17B2430", "address");

    assertSame(imageBaseRelativeAddress, result);
    verify(program, never()).getAddressFactory();
  }

  @Test
  void parseAllowsWhitespaceAroundImageBaseRelativePlus() throws Exception {
    when(program.getImageBase()).thenReturn(imageBase);
    when(imageBase.addNoWrap(new BigInteger("17B2430", 16))).thenReturn(imageBaseRelativeAddress);

    Address result = GhidraAddressParser.parse(program, "NewWorld.exe + 17B2430", "address");

    assertSame(imageBaseRelativeAddress, result);
  }

  @Test
  void parseKeepsUnprefixedNumbersAbsolute() throws Exception {
    when(program.getAddressFactory()).thenReturn(addressFactory);
    when(addressFactory.getAddress("0x17B2430")).thenReturn(parsedAddress);

    Address result = GhidraAddressParser.parse(program, "0x17B2430", "address");

    assertSame(parsedAddress, result);
    verify(program, never()).getImageBase();
  }
}
