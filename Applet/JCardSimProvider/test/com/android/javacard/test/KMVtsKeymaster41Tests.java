package com.android.javacard.test;

import java.util.Random;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMJCardSimApplet;
import com.android.javacard.keymaster.KMType;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;

public class KMVtsKeymaster41Tests extends KMFunctionalBaseTest {

  public KMVtsKeymaster41Tests() {
    super();
  }

  @Before
  public void init() {
    // Create simulator
    AID appletAID = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID);
    provision();
  }

  @After
  public void finish() {
    AID appletAID = AIDUtil.create("A000000062");
    // Delete i.e. uninstall applet
    simulator.deleteApplet(appletAID);
  }

  @Test
  public void testNewKeyGeneration_Rsa() {
    KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
    KMKeyParameterSet paramSet = 
        builder.setAlgorithm(KMType.RSA)
        .setKeySize(2048)
        .setDigest(KMType.DIGEST_NONE)
        .setPadding(KMType.PADDING_NONE)
        .setPurpose(KMType.SIGN, KMType.VERIFY)
        .setRsaPubExp(65537)
        .setCreationDateTime(System.currentTimeMillis())
        .build();

    short error = GenerateKey(paramSet.getKeyParameters(), false);
    Assert.assertEquals(error, KMError.OK);

    // Copy keyCharacteristics.
    KMKeyCharacteristicsSet keyChars = KMKeyCharacteristicsSet
        .decodeKeyCharacteristics(keyCharacteristicsPtr);
    KMBuffer keyBlob = KMBuffer.KMBufferFromPtr(keyBlobPtr);

    Assert.assertTrue((keyBlob.size() > 0));
    CheckBaseParams(keyCharacteristicsPtr);

    GetCharacteristics(keyBlob.getBufferPtr(),
        new KMBuffer((short) 0).getBufferPtr(),
        new KMBuffer((short) 0).getBufferPtr());

    // Get the new keyCharacteristics and compare.
    KMKeyCharacteristicsSet keyCharsNew = KMKeyCharacteristicsSet
        .decodeKeyCharacteristics(keyCharacteristicsPtr);
    Assert.assertTrue(keyChars.compare(keyCharsNew));

    Assert.assertEquals(2048, keyCharsNew.getHwParameterSet().getKeyParameters()
        .get(KMType.KEYSIZE).integer);
    Assert.assertEquals(KMType.RSA, keyCharsNew.getHwParameterSet()
        .getKeyParameters().get(KMType.ALGORITHM).byteValue);
    Assert.assertEquals(65537, keyCharsNew.getHwParameterSet()
        .getKeyParameters().get(KMType.RSA_PUBLIC_EXPONENT).integer);
  }

  @Test
  public void testNewKeyGeneration_NoInvalidRsaSizes() {
    int[] values = InvalidKeySizes(KMType.RSA);
    if (values != null) {
      for (int keySize : values) {
        KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
        KMKeyParameterSet paramSet =
            builder.setAlgorithm(KMType.RSA)
            .setKeySize(keySize)
            .setDigest(KMType.DIGEST_NONE)
            .setPadding(KMType.PADDING_NONE)
            .setPurpose(KMType.SIGN, KMType.VERIFY)
            .setRsaPubExp(65537)
            .setCreationDateTime(System.currentTimeMillis())
            .build();

        short error = GenerateKey(paramSet.getKeyParameters(), true);
        Assert.assertEquals(error, KMError.UNSUPPORTED_KEY_SIZE);
      }
    }
  }

  @Test
  public void testNewKeyGeneration_RsaNoDefaultSize() {
    KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
    KMKeyParameterSet paramSet =
        builder.setAlgorithm(KMType.RSA)
        .setPurpose(KMType.SIGN, KMType.VERIFY)
        .setRsaPubExp(3)
        .setCreationDateTime(System.currentTimeMillis())
        .build();
    short error = GenerateKey(paramSet.getKeyParameters(), true);
    Assert.assertEquals(error, KMError.UNSUPPORTED_KEY_SIZE);
  }

  @Test
  public void testNewKeyGeneration_Ecdsa() {
    int[] keySizes = ValidKeySizes(KMType.EC);
    for (int keySize : keySizes) {
      KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
      KMKeyParameterSet paramSet =
          builder.setAlgorithm(KMType.EC)
          .setKeySize(keySize)
          .setDigest(KMType.DIGEST_NONE)
          .setPurpose(KMType.SIGN, KMType.VERIFY)
          .setCreationDateTime(System.currentTimeMillis())
          .build();
      short error = GenerateKey(paramSet.getKeyParameters(), false);
      Assert.assertEquals(error, KMError.OK);

      // Copy keyCharacteristics.
      KMKeyCharacteristicsSet keyChars = KMKeyCharacteristicsSet
          .decodeKeyCharacteristics(keyCharacteristicsPtr);
      KMBuffer keyBlob = KMBuffer.KMBufferFromPtr(keyBlobPtr);

      Assert.assertTrue((keyBlob.size() > 0));
      CheckBaseParams(keyCharacteristicsPtr);
      GetCharacteristics(keyBlob.getBufferPtr(),
          new KMBuffer((short) 0).getBufferPtr(),
          new KMBuffer((short) 0).getBufferPtr());

      // Get the new keyCharacteristics and compare.
      KMKeyCharacteristicsSet keyCharsNew = KMKeyCharacteristicsSet
          .decodeKeyCharacteristics(keyCharacteristicsPtr);
      Assert.assertTrue(keyChars.compare(keyCharsNew));

      Assert.assertEquals(keySize, keyCharsNew.getHwParameterSet()
          .getKeyParameters().get(KMType.KEYSIZE).integer);
      Assert.assertEquals(KMType.EC, keyCharsNew.getHwParameterSet()
          .getKeyParameters().get(KMType.ALGORITHM).byteValue);
    }
  }

  @Test
  public void testNewKeyGeneration_EcdsaDefaultSize() {
    KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
    KMKeyParameterSet paramSet =
        builder.setAlgorithm(KMType.EC)
        .setDigest(KMType.DIGEST_NONE)
        .setPurpose(KMType.SIGN, KMType.VERIFY)
        .setCreationDateTime(System.currentTimeMillis())
        .build();
    short error = GenerateKey(paramSet.getKeyParameters(), true);
    Assert.assertEquals(error, KMError.UNSUPPORTED_KEY_SIZE);
  }

  @Test
  public void testNewKeyGeneration_EcdsaInvalidSize() {
    int[] values = InvalidKeySizes(KMType.EC);
    if (values != null) {
      for (int keySize : values) {
        KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
        KMKeyParameterSet paramSet =
            builder.setAlgorithm(KMType.EC)
            .setKeySize(keySize)
            .setDigest(KMType.DIGEST_NONE)
            .setPurpose(KMType.SIGN, KMType.VERIFY)
            .setCreationDateTime(System.currentTimeMillis())
            .build();
        short error = GenerateKey(paramSet.getKeyParameters(), true);
        Assert.assertEquals(error, KMError.UNSUPPORTED_KEY_SIZE);
      }
    }
    KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
    KMKeyParameterSet paramSet =
        builder.setAlgorithm(KMType.EC)
        .setKeySize(190)
        .setDigest(KMType.DIGEST_NONE)
        .setPurpose(KMType.SIGN, KMType.VERIFY)
        .setCreationDateTime(System.currentTimeMillis())
        .build();
    Assert.assertEquals(KMError.UNSUPPORTED_KEY_SIZE,
        GenerateKey(paramSet.getKeyParameters(), true));
  }

  /* Skipping EcdsaMismatchKeysize in VTS. Since it is not for Strongbox */

  @Test
  public void testNewKeyGeneration_EcdsaAllValidSizes() {
    int[] keySizes = ValidKeySizes(KMType.EC);
    for (int keySize : keySizes) {
      KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
      KMKeyParameterSet paramSet =
          builder.setAlgorithm(KMType.EC)
          .setKeySize(keySize)
          .setDigest(KMType.DIGEST_NONE)
          .setPurpose(KMType.SIGN, KMType.VERIFY)
          .setCreationDateTime(System.currentTimeMillis())
          .build();
      short error = GenerateKey(paramSet.getKeyParameters(), false);
      Assert.assertEquals(error, KMError.OK);

      // Copy keyCharacteristics.
      KMKeyCharacteristicsSet keyChars = KMKeyCharacteristicsSet
          .decodeKeyCharacteristics(keyCharacteristicsPtr);

      // Copy keyblob
      KMBuffer keyBlob = KMBuffer.KMBufferFromPtr(keyBlobPtr);
      byte[] keyBlobCopy = keyBlob.clone();

      Assert.assertTrue((keyBlob.size() > 0));
      GetCharacteristics(keyBlob.getBufferPtr(),
          new KMBuffer((short) 0).getBufferPtr(),
          new KMBuffer((short) 0).getBufferPtr());

      // Get the new keyCharacteristics and compare.
      KMKeyCharacteristicsSet keyCharsNew = KMKeyCharacteristicsSet
          .decodeKeyCharacteristics(keyCharacteristicsPtr);
      Assert.assertTrue(keyChars.compare(keyCharsNew));

      CheckedDeleteKey(keyBlobCopy, (short) 0, (short) keyBlobCopy.length);
    }
  }

  @Test
  public void testNewKeyGeneration_EcdsaAllValidCurves() {
    int[] curves = ValidCurves();
    for (int curve : curves) {
      KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
      KMKeyParameterSet paramSet =
          builder.setAlgorithm(KMType.EC)
          .setCurve((byte)curve)
          .setDigest(KMType.SHA2_256)
          .setPurpose(KMType.SIGN, KMType.VERIFY)
          .setCreationDateTime(System.currentTimeMillis())
          .build();
      short error = GenerateKey(paramSet.getKeyParameters(), false);
      Assert.assertEquals(error, KMError.OK);

      // Copy keyCharacteristics.
      KMKeyCharacteristicsSet keyChars = KMKeyCharacteristicsSet
          .decodeKeyCharacteristics(keyCharacteristicsPtr);

      // Copy keyblob
      KMBuffer keyBlob = KMBuffer.KMBufferFromPtr(keyBlobPtr);
      byte[] keyBlobCopy = keyBlob.clone();

      Assert.assertTrue((keyBlob.size() > 0));
      GetCharacteristics(keyBlob.getBufferPtr(),
          new KMBuffer((short) 0).getBufferPtr(),
          new KMBuffer((short) 0).getBufferPtr());

      // Get the new keyCharacteristics and compare.
      KMKeyCharacteristicsSet keyCharsNew = KMKeyCharacteristicsSet
          .decodeKeyCharacteristics(keyCharacteristicsPtr);
      Assert.assertTrue(keyChars.compare(keyCharsNew));

      CheckedDeleteKey(keyBlobCopy, (short) 0, (short) keyBlobCopy.length);
    }
  }

  @Test
  public void testNewKeyGeneration_Hmac() {
    int[] digests = ValidDigests(false);
    for (int digest : digests) {
      int keysize = 128;
      KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
      KMKeyParameterSet paramSet =
          builder.setAlgorithm(KMType.HMAC)
          .setKeySize(keysize)
          .setDigest((byte)digest)
          .setMinMacLength(128)
          .setPurpose(KMType.SIGN, KMType.VERIFY)
          .setCreationDateTime(System.currentTimeMillis())
          .build();
      short error = GenerateKey(paramSet.getKeyParameters(), false);
      Assert.assertEquals(error, KMError.OK);

      // Copy keyCharacteristics.
      KMKeyCharacteristicsSet keyChars = KMKeyCharacteristicsSet
          .decodeKeyCharacteristics(keyCharacteristicsPtr);

      // Copy keyblob
      KMBuffer keyBlob = KMBuffer.KMBufferFromPtr(keyBlobPtr);
      byte[] keyBlobCopy = keyBlob.clone();

      Assert.assertTrue((keyBlob.size() > 0));
      GetCharacteristics(keyBlob.getBufferPtr(),
          new KMBuffer((short) 0).getBufferPtr(),
          new KMBuffer((short) 0).getBufferPtr());

      // Get the new keyCharacteristics and compare.
      KMKeyCharacteristicsSet keyCharsNew = KMKeyCharacteristicsSet
          .decodeKeyCharacteristics(keyCharacteristicsPtr);
      Assert.assertTrue(keyChars.compare(keyCharsNew));

      Assert.assertEquals(keysize, keyCharsNew.getHwParameterSet()
          .getKeyParameters().get(KMType.KEYSIZE).integer);
      Assert.assertEquals(KMType.HMAC, keyCharsNew.getHwParameterSet()
          .getKeyParameters().get(KMType.ALGORITHM).byteValue);

      CheckedDeleteKey(keyBlobCopy, (short) 0, (short) keyBlobCopy.length);
    }
  }

  @Test
  public void testNewKeyGeneration_HmacCheckKeySizes() {
    for (int key_size = 0; key_size <= 512; ++key_size) {
      KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
      KMKeyParameterSet paramSet =
          builder.setAlgorithm(KMType.HMAC)
          .setKeySize(key_size)
          .setDigest(KMType.SHA2_256)
          .setMinMacLength(256)
          .setPurpose(KMType.SIGN, KMType.VERIFY)
          .setCreationDateTime(System.currentTimeMillis())
          .build();
      if (key_size < 64 || key_size % 8 != 0) {
        long random = new Random().nextLong();
        // To keep this test from being very slow, we only test a random
        // fraction of non-byte
        // key sizes. We test only ~10% of such cases. Since there are 392 of
        // them, we expect
        // to run ~40 of them in each run.
        if (key_size % 8 == 0 || random % 10 == 0) {
          short error = GenerateKey(paramSet.getKeyParameters(), true);
          Assert.assertEquals(error, KMError.UNSUPPORTED_KEY_SIZE);
        }
      } else {
        short error = GenerateKey(paramSet.getKeyParameters(), false);
        Assert.assertEquals(error, KMError.OK);
        // Copy keyCharacteristics.
        KMKeyCharacteristicsSet keyChars = KMKeyCharacteristicsSet
            .decodeKeyCharacteristics(keyCharacteristicsPtr);

        // Copy keyblob
        KMBuffer keyBlob = KMBuffer.KMBufferFromPtr(keyBlobPtr);
        byte[] keyBlobCopy = keyBlob.clone();

        Assert.assertTrue((keyBlob.size() > 0));
        GetCharacteristics(keyBlob.getBufferPtr(),
            new KMBuffer((short) 0).getBufferPtr(),
            new KMBuffer((short) 0).getBufferPtr());

        // Get the new keyCharacteristics and compare.
        KMKeyCharacteristicsSet keyCharsNew = KMKeyCharacteristicsSet
            .decodeKeyCharacteristics(keyCharacteristicsPtr);
        Assert.assertTrue(keyChars.compare(keyCharsNew));

        CheckedDeleteKey(keyBlobCopy, (short) 0, (short) keyBlobCopy.length);
      }
    }
  }

  @Test
  public void testNewKeyGeneration_HmacCheckMinMacLengths() {
    for (int min_mac_length = 0; min_mac_length <= 256; ++min_mac_length) {
      KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
      KMKeyParameterSet paramSet =
          builder.setAlgorithm(KMType.HMAC)
          .setKeySize(128)
          .setDigest(KMType.SHA2_256)
          .setMinMacLength(min_mac_length)
          .setPurpose(KMType.SIGN, KMType.VERIFY)
          .setCreationDateTime(System.currentTimeMillis())
          .build();
      if (min_mac_length < 64 || min_mac_length % 8 != 0) {
        long random = new Random().nextLong();
        // To keep this test from being very long, we only test a random fraction of non-byte
        // lengths.  We test only ~10% of such cases. Since there are 172 of them, we expect to
        // run ~17 of them in each run.
        if (min_mac_length % 8 == 0 || random % 10 == 0) {
          short error = GenerateKey(paramSet.getKeyParameters(), true);
          Assert.assertEquals(error, KMError.UNSUPPORTED_MIN_MAC_LENGTH);
        }
      } else {
        short error = GenerateKey(paramSet.getKeyParameters(), false);
        Assert.assertEquals(error, KMError.OK);
        // Copy keyCharacteristics.
        KMKeyCharacteristicsSet keyChars = KMKeyCharacteristicsSet
            .decodeKeyCharacteristics(keyCharacteristicsPtr);

        // Copy keyblob
        KMBuffer keyBlob = KMBuffer.KMBufferFromPtr(keyBlobPtr);
        byte[] keyBlobCopy = keyBlob.clone();

        Assert.assertTrue((keyBlob.size() > 0));
        GetCharacteristics(keyBlob.getBufferPtr(),
            new KMBuffer((short) 0).getBufferPtr(),
            new KMBuffer((short) 0).getBufferPtr());

        // Get the new keyCharacteristics and compare.
        KMKeyCharacteristicsSet keyCharsNew = KMKeyCharacteristicsSet
            .decodeKeyCharacteristics(keyCharacteristicsPtr);
        Assert.assertTrue(keyChars.compare(keyCharsNew));

        CheckedDeleteKey(keyBlobCopy, (short) 0, (short) keyBlobCopy.length);
      }
    }
  }

  /* Skipping HmacMultipleDigests as this is not for Strongbox */

  @Test
  public void testNewKeyGeneration_HmacDigestNone() {
    KMKeyParameterSet.KeyParametersSetBuilder builder = new KMKeyParameterSet.KeyParametersSetBuilder();
    KMKeyParameterSet paramSet =
        builder.setAlgorithm(KMType.HMAC)
        .setKeySize(128)
        .setMinMacLength(128)
        .setPurpose(KMType.SIGN, KMType.VERIFY)
        .setCreationDateTime(System.currentTimeMillis())
        .build();
    Assert.assertEquals(KMError.UNSUPPORTED_DIGEST,
        GenerateKey(paramSet.getKeyParameters(), true));

    builder = new KMKeyParameterSet.KeyParametersSetBuilder();
    paramSet =
        builder.setAlgorithm(KMType.HMAC)
        .setKeySize(128)
        .setMinMacLength(128)
        .setDigest(KMType.DIGEST_NONE)
        .setPurpose(KMType.SIGN, KMType.VERIFY)
        .setCreationDateTime(System.currentTimeMillis())
        .build();
    Assert.assertEquals(KMError.UNSUPPORTED_DIGEST,
        GenerateKey(paramSet.getKeyParameters(), true));
  }
}
