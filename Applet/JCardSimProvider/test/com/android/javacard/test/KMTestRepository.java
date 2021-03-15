package com.android.javacard.test;

import com.android.javacard.keymaster.KMRepository;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KMTestRepository extends KMRepository {

  private static final int TEST_HEAP_SIZE = 20000;
  private byte[] testHeap = new byte[TEST_HEAP_SIZE];
  private short testHeapIndex = 0;

  public KMTestRepository(boolean isUpgrading) {
    super(isUpgrading);
  }

  public short alloc(short length) {
    if ((((short) (testHeapIndex + length)) > testHeap.length)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    testHeapIndex += length;
    return (short) (testHeapIndex - length);
  }

  public byte[] getHeap() {
    return testHeap;
  }

  public void clean() {
    super.clean();
    Util.arrayFillNonAtomic(testHeap, (short) 0, testHeapIndex, (byte) 0);
    testHeapIndex = 0;
  }

  public void setDeviceLock(boolean flag) {
  }

  public void setDeviceLockPasswordOnly(boolean flag) {
  }
}
