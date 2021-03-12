package com.android.javacard.test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.Assert;

import com.android.javacard.keymaster.KMArray;
import com.android.javacard.keymaster.KMBoolTag;
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMByteTag;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMEnum;
import com.android.javacard.keymaster.KMEnumArrayTag;
import com.android.javacard.keymaster.KMEnumTag;
import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMIntegerTag;
import com.android.javacard.keymaster.KMJCardSimulator;
import com.android.javacard.keymaster.KMKeyCharacteristics;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMSEProvider;
import com.android.javacard.keymaster.KMTag;
import com.android.javacard.keymaster.KMType;
import com.licel.jcardsim.smartcardio.CardSimulator;

import javacard.framework.Util;

//TODO Rename it to KMFunctionalTest.
public class KMFunctionalBaseTest {

  private static final byte INS_BEGIN_KM_CMD = 0x00;
  private static final byte INS_PROVISION_ATTESTATION_KEY_CMD = INS_BEGIN_KM_CMD + 1; //0x01
  private static final byte INS_PROVISION_ATTESTATION_CERT_CHAIN_CMD = INS_BEGIN_KM_CMD + 2; //0x02
  private static final byte INS_PROVISION_ATTESTATION_CERT_PARAMS_CMD = INS_BEGIN_KM_CMD + 3; //0x03
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_BEGIN_KM_CMD + 4; //0x04
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD = INS_BEGIN_KM_CMD + 5; //0x05
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_BEGIN_KM_CMD + 6; //0x06
  private static final byte INS_LOCK_PROVISIONING_CMD = INS_BEGIN_KM_CMD + 7; //0x07
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_BEGIN_KM_CMD + 8; //0x08
  // Top 32 commands are reserved for provisioning.
  private static final byte INS_END_KM_PROVISION_CMD = 0x20;

  private static final byte INS_GENERATE_KEY_CMD = INS_END_KM_PROVISION_CMD + 1;  //0x21
  private static final byte INS_IMPORT_KEY_CMD = INS_END_KM_PROVISION_CMD + 2;    //0x22
  private static final byte INS_IMPORT_WRAPPED_KEY_CMD = INS_END_KM_PROVISION_CMD + 3; //0x23
  private static final byte INS_EXPORT_KEY_CMD = INS_END_KM_PROVISION_CMD + 4; //0x24
  private static final byte INS_ATTEST_KEY_CMD = INS_END_KM_PROVISION_CMD + 5; //0x25
  private static final byte INS_UPGRADE_KEY_CMD = INS_END_KM_PROVISION_CMD + 6; //0x26
  private static final byte INS_DELETE_KEY_CMD = INS_END_KM_PROVISION_CMD + 7; //0x27
  private static final byte INS_DELETE_ALL_KEYS_CMD = INS_END_KM_PROVISION_CMD + 8; //0x28
  private static final byte INS_ADD_RNG_ENTROPY_CMD = INS_END_KM_PROVISION_CMD + 9; //0x29
  private static final byte INS_COMPUTE_SHARED_HMAC_CMD = INS_END_KM_PROVISION_CMD + 10; //0x2A
  private static final byte INS_DESTROY_ATT_IDS_CMD = INS_END_KM_PROVISION_CMD + 11;  //0x2B
  private static final byte INS_VERIFY_AUTHORIZATION_CMD = INS_END_KM_PROVISION_CMD + 12; //0x2C
  private static final byte INS_GET_HMAC_SHARING_PARAM_CMD = INS_END_KM_PROVISION_CMD + 13; //0x2D
  private static final byte INS_GET_KEY_CHARACTERISTICS_CMD = INS_END_KM_PROVISION_CMD + 14; //0x2E
  private static final byte INS_GET_HW_INFO_CMD = INS_END_KM_PROVISION_CMD + 15; //0x2F
  private static final byte INS_BEGIN_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 16;  //0x30
  private static final byte INS_UPDATE_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 17;  //0x31
  private static final byte INS_FINISH_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 18; //0x32
  private static final byte INS_ABORT_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 19; //0x33
  private static final byte INS_DEVICE_LOCKED_CMD = INS_END_KM_PROVISION_CMD + 20;//0x34
  private static final byte INS_EARLY_BOOT_ENDED_CMD = INS_END_KM_PROVISION_CMD + 21; //0x35
  private static final byte INS_GET_CERT_CHAIN_CMD = INS_END_KM_PROVISION_CMD + 22; //0x36
  
  public static int OS_VERSION = 1;
  public static int OS_PATCH_LEVEL = 2;
  
	public CardSimulator simulator;
	public KMEncoder encoder;
	public KMDecoder decoder;
	public KMSEProvider cryptoProvider;
	public short keyBlobPtr;
	public short keyCharacteristicsPtr;

	public KMFunctionalBaseTest() {
		cryptoProvider = new KMJCardSimulator();
		simulator = new CardSimulator();
		encoder = new KMEncoder();
		decoder = new KMDecoder();
	}

	public CommandAPDU encodeApdu(byte ins, short cmd) {
		byte[] buf = new byte[2500];
		buf[0] = (byte) 0x80;
		buf[1] = ins;
		buf[2] = (byte) 0x40;
		buf[3] = (byte) 0x00;
		buf[4] = 0;
		short len = encoder.encode(cmd, buf, (short) 7);
		Util.setShort(buf, (short) 5, len);
		byte[] apdu = new byte[7 + len];
		Util.arrayCopyNonAtomic(buf, (short) 0, apdu, (short) 0, (short) (7 + len));
		return new CommandAPDU(apdu);
	}

	public short GenerateKey(Map<Short, KMParameterValue> keyParameters,
			boolean negativeTest) {
		short tagIndex = 0;
		short byteBlob = 0;
		short type = 0;
		short arrPtr = KMArray.instance((short) keyParameters.size());
		for (Map.Entry<Short, KMParameterValue> entry : keyParameters.entrySet()) {
			switch (entry.getKey()) {
			case KMType.ALGORITHM:
				KMArray.cast(arrPtr).add(tagIndex++,
				    KMEnumTag.instance(KMType.ALGORITHM, entry.getValue().byteValue));
				break;
			case KMType.DIGEST:
			case KMType.PADDING:
			case KMType.PURPOSE:
				byteBlob = KMByteBlob
				    .instance((short) entry.getValue().byteValues.size());
				for (short i = 0; i < entry.getValue().byteValues.size(); i++) {
					KMByteBlob.cast(byteBlob).add((short) i,
					    entry.getValue().byteValues.get(i));
				}
				short val = KMEnumArrayTag.instance(entry.getKey(), byteBlob);
				KMArray.cast(arrPtr).add(tagIndex++, val);
				break;
			case KMType.KEYSIZE:
				short keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE,
				    KMInteger.uint_16((short) entry.getValue().integer));
				KMArray.cast(arrPtr).add(tagIndex++, keySize);
				break;
			case KMType.RSA_PUBLIC_EXPONENT:
				byte[] bytes = ByteBuffer.allocate(4).putInt(entry.getValue().integer)
				    .array();
				short rsaPubExpTag = KMIntegerTag.instance(KMType.ULONG_TAG,
				    KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(bytes, (short) 0));
				KMArray.cast(arrPtr).add(tagIndex++, rsaPubExpTag);
				break;
			case KMType.CREATION_DATETIME:
			case KMType.ACTIVE_DATETIME:
				byte[] datetime = ByteBuffer.allocate(8)
				    .putLong(entry.getValue().longinteger).array();
				short dateTag = KMInteger.uint_64(datetime, (short) 0);
				KMArray.cast(arrPtr).add(tagIndex++,
				    KMIntegerTag.instance(KMType.DATE_TAG, entry.getKey(), dateTag));
				break;
			case KMType.APPLICATION_DATA:
			case KMType.APPLICATION_ID:
				byte[] data = entry.getValue().buf.array();
				KMArray.cast(arrPtr).add(tagIndex++, KMByteTag.instance(entry.getKey(),
				    KMByteBlob.instance(data, (short) 0, (short) data.length)));
				break;
			case KMType.NO_AUTH_REQUIRED:
			case KMType.INCLUDE_UNIQUE_ID:
			case KMType.RESET_SINCE_ID_ROTATION:
				KMArray.cast(arrPtr).add(tagIndex++,
				    KMBoolTag.instance(entry.getKey()));
				break;
			}
		}
		short keyParams = KMKeyParameters.instance(arrPtr);
		arrPtr = KMArray.instance((short) 1);
		KMArray arg = KMArray.cast(arrPtr);
		arg.add((short) 0, keyParams);
		CommandAPDU apdu = encodeApdu((byte) INS_GENERATE_KEY_CMD, arrPtr);
		ResponseAPDU response = simulator.transmitCommand(apdu);
		if (response.getSW() == 0x9000) {
			if (negativeTest) {
				byte[] respBuf = response.getBytes();
				short len = (short) respBuf.length;
				short ret = decoder.decode(KMInteger.exp(), respBuf, (short) 0, len);
				short error = KMInteger.cast(ret).getShort();
				keyBlobPtr = KMType.INVALID_VALUE;
				keyCharacteristicsPtr = KMType.INVALID_VALUE;
				return error;
			} else {
				short ret = KMArray.instance((short) 3);
				KMArray.cast(ret).add((short) 0, KMInteger.exp());
				KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
				short inst = KMKeyCharacteristics.exp();
				KMArray.cast(ret).add((short) 2, inst);
				byte[] respBuf = response.getBytes();
				short len = (short) respBuf.length;
				ret = decoder.decode(ret, respBuf, (short) 0, len);
				keyBlobPtr = KMArray.cast(ret).get((short) 1);
				keyCharacteristicsPtr = KMArray.cast(ret).get((short) 2);
				short error = KMInteger.cast(KMArray.cast(ret).get((short) 0))
				    .getShort();
				return error;
			}
		}
		return (short) response.getSW();
	}

	public short GetCharacteristics(short keyBlobPtr, short appId,
	    short appData) {
		short arrPtr = KMArray.instance((short) 3);
		KMArray.cast(arrPtr).add((short) 0, keyBlobPtr);
		KMArray.cast(arrPtr).add((short) 1, appId);
		KMArray.cast(arrPtr).add((short) 2, appData);
		CommandAPDU apdu = encodeApdu((byte) INS_GET_KEY_CHARACTERISTICS_CMD,
		    arrPtr);
		// print(commandAPDU.getBytes());
		ResponseAPDU response = simulator.transmitCommand(apdu);
		if (response.getSW() == 0x9000) {
			short ret = KMArray.instance((short) 2);
			KMArray.cast(ret).add((short) 0, KMInteger.exp());
			short inst = KMKeyCharacteristics.exp();
			KMArray.cast(ret).add((short) 1, inst);
			byte[] respBuf = response.getBytes();
			short len = (short) respBuf.length;
			ret = decoder.decode(ret, respBuf, (short) 0, len);
			keyCharacteristicsPtr = KMArray.cast(ret).get((short) 1);
			short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
			return error;
		}
		return (short) response.getSW();
	}
	
	//Note: Only to be used by testNewKeyGeneration_*
	public void CheckBaseParams(short keyCharsPtr) {
		short hwParams = KMKeyCharacteristics.cast(keyCharacteristicsPtr).getHardwareEnforced();
		short swParams = KMKeyCharacteristics.cast(keyCharacteristicsPtr).getSoftwareEnforced();
		
		short tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, hwParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE, hwParams);
    short buf = KMEnumArrayTag.cast(tag).getValues();
    byte[] purpose = {KMType.SIGN, KMType.VERIFY };
    if ( 0 != Util.arrayCompare(purpose, (short)0, 
    		KMByteBlob.cast(buf).getBuffer(),
    		KMByteBlob.cast(buf).getStartOff(),
    		(short)purpose.length)) {
    	
    	purpose = new byte[] {KMType.VERIFY, KMType.SIGN };
    	if ( 0 != Util.arrayCompare(purpose, (short)0, 
      		KMByteBlob.cast(buf).getBuffer(),
      		KMByteBlob.cast(buf).getStartOff(),
      		(short)purpose.length)) {
    		Assert.fail("Purpose not mached.");
    	}
    }
    
    tag = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.ROOT_OF_TRUST, hwParams);
    Assert.assertEquals(tag, KMType.INVALID_VALUE);
    
    tag = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, hwParams);
    Assert.assertEquals(tag, KMType.INVALID_VALUE);
    
    tag = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, hwParams);
    Assert.assertEquals(tag, KMType.INVALID_VALUE);
    
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE, hwParams);
    buf = KMEnumArrayTag.cast(tag).getValues();
    purpose = new byte[] {KMType.ENCRYPT, KMType.DECRYPT };
    if ( 0 == Util.arrayCompare(purpose, (short)0, 
    		KMByteBlob.cast(buf).getBuffer(),
    		KMByteBlob.cast(buf).getStartOff(),
    		(short)purpose.length)) {
    	Assert.fail("Purpose not matched.");
    } else {    	
    	purpose = new byte[] {KMType.DECRYPT, KMType.ENCRYPT };
    	if ( 0 == Util.arrayCompare(purpose, (short)0, 
      		KMByteBlob.cast(buf).getBuffer(),
      		KMByteBlob.cast(buf).getStartOff(),
      		(short)purpose.length)) {
    		Assert.fail("Purpose not mached.");
    	}

    }
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.AUTH_TIMEOUT, hwParams);
    Assert.assertEquals(tag, KMType.INVALID_VALUE);
    
    tag = KMKeyParameters.findTag(KMType.DATE_TAG, KMType.CREATION_DATETIME, swParams);
    Assert.assertNotEquals(tag, KMType.INVALID_VALUE);
    
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.OS_VERSION, hwParams);
    tag = KMIntegerTag.cast(tag).getValue();
    Assert.assertEquals(KMInteger.cast(tag).getShort(), OS_VERSION);
    
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, hwParams);
    tag = KMIntegerTag.cast(tag).getValue();
    Assert.assertEquals(KMInteger.cast(tag).getShort(), OS_PATCH_LEVEL);
	}
	
	public int[] InvalidKeySizes(short algorithm) {
		switch(algorithm) {
		case KMType.RSA:
			int[] rsaArray = new int[] {3072, 4096};
			return rsaArray;
		case KMType.EC:
			int[] ecArray = new int[] {224, 384, 521};
			return ecArray;
		case KMType.AES:
			int[] aesArray = new int[] {192};
			return aesArray;
			default:
				break;
		}
		return null;
	}
	
	public int[] ValidKeySizes(short algorithm) {
		switch(algorithm) {
		case KMType.RSA:
			return new int[] {2048};
		case KMType.EC:
			return new int[] {256};
		case KMType.AES:
			return new int[] {128, 256};
		case KMType.DES:
			return new int[] {168};
		case KMType.HMAC:
			int[] values = new int[(512 - 64)/8 + 1];
			for (int i = 0; i < values.length; i++) {
				values[i] = 64 + (i * 8);
			}
			return values;
		}
		return null;
	}

	public void provision() {
		provisionSigningKey();
		provisionSigningCertificate();
		provisionCertificateParams();
		provisionSharedSecret();
		provisionAttestIds();
		// set bootup parameters
		setBootParams((short) OS_VERSION, (short) OS_PATCH_LEVEL, (short) 0, (short) 0);
		// provisionLocked(simulator);
	}

	private void setBootParams(short osVersion, short osPatchLevel,
	    short vendorPatchLevel, short bootPatchLevel) {
		// Argument 1 OS Version
		short versionPtr = KMInteger.uint_16(osVersion);
		// short versionTagPtr = KMIntegerTag.instance(KMType.UINT_TAG,
		// KMType.OS_VERSION,versionPatchPtr);
		// Argument 2 OS Patch level
		short patchPtr = KMInteger.uint_16(osPatchLevel);
		short vendorpatchPtr = KMInteger.uint_16((short) vendorPatchLevel);
		short bootpatchPtr = KMInteger.uint_16((short) bootPatchLevel);
		// Argument 3 Verified Boot Key
		byte[] bootKeyHash = "00011122233344455566677788899900".getBytes();
		short bootKeyPtr = KMByteBlob.instance(bootKeyHash, (short) 0,
		    (short) bootKeyHash.length);
		// Argument 4 Verified Boot Hash
		short bootHashPtr = KMByteBlob.instance(bootKeyHash, (short) 0,
		    (short) bootKeyHash.length);
		// Argument 5 Verified Boot State
		short bootStatePtr = KMEnum.instance(KMType.VERIFIED_BOOT_STATE,
		    KMType.VERIFIED_BOOT);
		// Argument 6 Device Locked
		short deviceLockedPtr = KMEnum.instance(KMType.DEVICE_LOCKED,
		    KMType.DEVICE_LOCKED_FALSE);
		// Arguments
		short arrPtr = KMArray.instance((short) 8);
		KMArray vals = KMArray.cast(arrPtr);
		vals.add((short) 0, versionPtr);
		vals.add((short) 1, patchPtr);
		vals.add((short) 2, vendorpatchPtr);
		vals.add((short) 3, bootpatchPtr);
		vals.add((short) 4, bootKeyPtr);
		vals.add((short) 5, bootHashPtr);
		vals.add((short) 6, bootStatePtr);
		vals.add((short) 7, deviceLockedPtr);
		CommandAPDU apdu = encodeApdu((byte) INS_SET_BOOT_PARAMS_CMD, arrPtr);
		// print(commandAPDU.getBytes());
		ResponseAPDU response = simulator.transmitCommand(apdu);
		Assert.assertEquals(0x9000, response.getSW());

	}

	private void provisionSigningCertificate() {
		short byteBlobPtr = KMByteBlob
		    .instance((short) (KMAttestationParams.kEcAttestCert.length
		        + KMAttestationParams.kEcAttestRootCert.length));
		Util.arrayCopyNonAtomic(KMAttestationParams.kEcAttestCert, (short) 0,
		    KMByteBlob.cast(byteBlobPtr).getBuffer(),
		    KMByteBlob.cast(byteBlobPtr).getStartOff(),
		    (short) KMAttestationParams.kEcAttestCert.length);
		Util.arrayCopyNonAtomic(KMAttestationParams.kEcAttestRootCert, (short) 0,
		    KMByteBlob.cast(byteBlobPtr).getBuffer(),
		    (short) (KMByteBlob.cast(byteBlobPtr).getStartOff()
		        + KMAttestationParams.kEcAttestCert.length),
		    (short) KMAttestationParams.kEcAttestRootCert.length);
		CommandAPDU apdu = encodeApdu(
		    (byte) INS_PROVISION_ATTESTATION_CERT_CHAIN_CMD, byteBlobPtr);
		// print(commandAPDU.getBytes());
		ResponseAPDU response = simulator.transmitCommand(apdu);
		Assert.assertEquals(0x9000, response.getSW());
	}

	private void provisionSigningKey() {
		// KeyParameters.
		short arrPtr = KMArray.instance((short) 4);
		short ecCurve = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
		short byteBlob = KMByteBlob.instance((short) 1);
		KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
		short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
		short byteBlob2 = KMByteBlob.instance((short) 1);
		KMByteBlob.cast(byteBlob2).add((short) 0, KMType.ATTEST_KEY);
		short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob2);
		KMArray.cast(arrPtr).add((short) 0, ecCurve);
		KMArray.cast(arrPtr).add((short) 1, digest);
		KMArray.cast(arrPtr).add((short) 2,
		    KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
		KMArray.cast(arrPtr).add((short) 3, purpose);
		short keyParams = KMKeyParameters.instance(arrPtr);
		// Note: VTS uses PKCS8 KeyFormat RAW
		short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);

		// Key
		short signKeyPtr = KMArray.instance((short) 2);
		KMArray.cast(signKeyPtr).add((short) 0,
		    KMByteBlob.instance(KMAttestationParams.kEcPrivKey, (short) 0,
		        (short) KMAttestationParams.kEcPrivKey.length));
		KMArray.cast(signKeyPtr).add((short) 1,
		    KMByteBlob.instance(KMAttestationParams.kEcPubKey, (short) 0,
		        (short) KMAttestationParams.kEcPubKey.length));
		byte[] keyBuf = new byte[120];
		short len = encoder.encode(signKeyPtr, keyBuf, (short) 0);
		short signKeyBstr = KMByteBlob.instance(keyBuf, (short) 0, len);

		short finalArrayPtr = KMArray.instance((short) 3);
		KMArray.cast(finalArrayPtr).add((short) 0, keyParams);
		KMArray.cast(finalArrayPtr).add((short) 1, keyFormatPtr);
		KMArray.cast(finalArrayPtr).add((short) 2, signKeyBstr);

		CommandAPDU apdu = encodeApdu((byte) INS_PROVISION_ATTESTATION_KEY_CMD,
		    finalArrayPtr);
		// print(commandAPDU.getBytes());
		ResponseAPDU response = simulator.transmitCommand(apdu);
		Assert.assertEquals(0x9000, response.getSW());
	}

	private void provisionCertificateParams() {

		short arrPtr = KMArray.instance((short) 2);
		short byteBlob1 = KMByteBlob.instance(KMAttestationParams.X509Issuer,
		    (short) 0, (short) KMAttestationParams.X509Issuer.length);
		KMArray.cast(arrPtr).add((short) 0, byteBlob1);
		short byteBlob2 = KMByteBlob.instance(KMAttestationParams.expiryTime,
		    (short) 0, (short) KMAttestationParams.expiryTime.length);
		KMArray.cast(arrPtr).add((short) 1, byteBlob2);

		CommandAPDU apdu = encodeApdu(
		    (byte) INS_PROVISION_ATTESTATION_CERT_PARAMS_CMD, arrPtr);
		// print(commandAPDU.getBytes());
		ResponseAPDU response = simulator.transmitCommand(apdu);
		Assert.assertEquals(0x9000, response.getSW());
	}

	private void provisionSharedSecret() {
		byte[] sharedKeySecret = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		short arrPtr = KMArray.instance((short) 1);
		short byteBlob = KMByteBlob.instance(sharedKeySecret, (short) 0,
		    (short) sharedKeySecret.length);
		KMArray.cast(arrPtr).add((short) 0, byteBlob);

		CommandAPDU apdu = encodeApdu((byte) INS_PROVISION_PRESHARED_SECRET_CMD,
		    arrPtr);
		// print(commandAPDU.getBytes());
		ResponseAPDU response = simulator.transmitCommand(apdu);
		Assert.assertEquals(0x9000, response.getSW());
	}

	private void provisionAttestIds() {
		short arrPtr = KMArray.instance((short) 8);

		byte[] buf = "Attestation Id".getBytes();

		KMArray.cast(arrPtr).add((short) 0,
		    KMByteTag.instance(KMType.ATTESTATION_ID_BRAND,
		        KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
		KMArray.cast(arrPtr).add((short) 1,
		    KMByteTag.instance(KMType.ATTESTATION_ID_PRODUCT,
		        KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
		KMArray.cast(arrPtr).add((short) 2,
		    KMByteTag.instance(KMType.ATTESTATION_ID_DEVICE,
		        KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
		KMArray.cast(arrPtr).add((short) 3,
		    KMByteTag.instance(KMType.ATTESTATION_ID_MODEL,
		        KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
		KMArray.cast(arrPtr).add((short) 4,
		    KMByteTag.instance(KMType.ATTESTATION_ID_IMEI,
		        KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
		KMArray.cast(arrPtr).add((short) 5,
		    KMByteTag.instance(KMType.ATTESTATION_ID_MEID,
		        KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
		KMArray.cast(arrPtr).add((short) 6,
		    KMByteTag.instance(KMType.ATTESTATION_ID_MANUFACTURER,
		        KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
		KMArray.cast(arrPtr).add((short) 7,
		    KMByteTag.instance(KMType.ATTESTATION_ID_SERIAL,
		        KMByteBlob.instance(buf, (short) 0, (short) buf.length)));
		short keyParams = KMKeyParameters.instance(arrPtr);
		short outerArrPtr = KMArray.instance((short) 1);
		KMArray.cast(outerArrPtr).add((short) 0, keyParams);
		CommandAPDU apdu = encodeApdu((byte) INS_PROVISION_ATTEST_IDS_CMD,
		    outerArrPtr);
		// print(commandAPDU.getBytes());
		ResponseAPDU response = simulator.transmitCommand(apdu);
		Assert.assertEquals(0x9000, response.getSW());
	}
}
