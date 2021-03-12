package com.android.javacard.test;

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
}
