package com.android.javacard.test;

import com.android.javacard.keymaster.KMKeyCharacteristics;

public class KMKeyCharacteristicsSet {

  private KMKeyParameterSet swEnforced;
  private KMKeyParameterSet hwEnforced;

  public KMKeyCharacteristicsSet(KMKeyParameterSet swEnforced,
      KMKeyParameterSet hwEnforced) {
    this.swEnforced = swEnforced;
    this.hwEnforced = hwEnforced;
  }

  public boolean compare(KMKeyCharacteristicsSet other) {
    if (swEnforced.compare(other.swEnforced)
        && hwEnforced.compare(other.hwEnforced)) {
      return true;
    }
    return false;
  }

  public KMKeyParameterSet getHwParameterSet() {
    return hwEnforced;
  }

  public KMKeyParameterSet getSwParameterSet() {
    return swEnforced;
  }

  public static KMKeyCharacteristicsSet decodeKeyCharacteristics(short params) {
    short hwParams = KMKeyCharacteristics.cast(params).getHardwareEnforced();
    short swParams = KMKeyCharacteristics.cast(params).getSoftwareEnforced();

    KMKeyCharacteristicsSet keyChars = new KMKeyCharacteristicsSet(
        KMKeyParameterSet.decodeKeyParameters(swParams),
        KMKeyParameterSet.decodeKeyParameters(hwParams));
    return keyChars;
  }

}
