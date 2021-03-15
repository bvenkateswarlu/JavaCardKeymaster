package com.android.javacard.test;

import com.android.javacard.keymaster.KMByteBlob;
import javacard.framework.Util;

public class KMBuffer {

  private short bufPtr;

  public static KMBuffer KMBufferFromPtr(short ptr) {
    KMBuffer buf = new KMBuffer();
    buf.bufPtr = ptr;
    return buf;
  }

  public KMBuffer() {
    bufPtr = 0;
  }

  // Length as argument.
  public KMBuffer(short len) {
    bufPtr = KMByteBlob.instance(len);
  }

  public short size() {
    return KMByteBlob.cast(bufPtr).length();
  }

  public short getBufferPtr() {
    return bufPtr;
  }

  public byte[] clone() {
    byte[] buffer = new byte[(short) KMByteBlob.cast(bufPtr).length()];
    Util.arrayCopy(
        KMByteBlob.cast(bufPtr).getBuffer(),
        KMByteBlob.cast(bufPtr).getStartOff(),
        buffer,
        (short) 0,
        KMByteBlob.cast(bufPtr).length());
    return buffer;
  }

  public byte compare(byte[] buf, short off, short len) {
    return Util.arrayCompare(KMByteBlob.cast(bufPtr).getBuffer(),
        KMByteBlob.cast(bufPtr).getStartOff(), buf, off, len);
  }
}
