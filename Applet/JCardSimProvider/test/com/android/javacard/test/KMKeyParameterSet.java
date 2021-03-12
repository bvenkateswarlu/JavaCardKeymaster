package com.android.javacard.test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.android.javacard.keymaster.KMArray;
import com.android.javacard.keymaster.KMBoolTag;
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMByteTag;
import com.android.javacard.keymaster.KMEnumArrayTag;
import com.android.javacard.keymaster.KMEnumTag;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMIntegerTag;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMTag;
import com.android.javacard.keymaster.KMType;

public class KMKeyParameterSet {
	
	private Map<Short, KMParameterValue> keyParameters;
	
	public KMKeyParameterSet() {
		keyParameters = new HashMap<>();
	}
	
	public KMKeyParameterSet(Map<Short, KMParameterValue> params) {
		keyParameters = params;
	}
	
	public Map<Short, KMParameterValue> getKeyParameters() {
		return keyParameters;
	}
	
	public static KMKeyParameterSet decodeKeyParameters(short params) {
		Map<Short, KMParameterValue> keyParams = new HashMap<>();
		KMParameterValue val;
		short arrPtr = KMKeyParameters.cast(params).getVals();
		short length = KMKeyParameters.cast(params).length();
		KMArray vals = KMArray.cast(arrPtr);
		short obj;
		short key;
		short type;
		short index = 0;
		while (index < length) {
			obj = vals.get(index);
			key = KMTag.getKey(obj);
			type = KMTag.getTagType(obj);
			switch (type) {
			case KMType.UINT_TAG:
				short intPtr = KMIntegerTag.cast(obj).getValue();
				val = new KMParameterValue();
				val.integer = KMInteger.cast(intPtr).getShort();
				keyParams.put(key, val);
				break;
			case KMType.ENUM_ARRAY_TAG:
				ArrayList<Byte> byteVals = new ArrayList<>();
				short byteBlob = KMEnumArrayTag.cast(obj).getValues();
				for (short i = 0; i < KMByteBlob.cast(byteBlob).length(); i++) {
					byte byteVal = KMByteBlob.cast(byteBlob).get(i);
					byteVals.add(byteVal);
				}
				val = new KMParameterValue();
				val.byteValues = byteVals;
				keyParams.put(key, val);
				break;
			case KMType.ENUM_TAG:
				byte enumValue = KMEnumTag.cast(obj).getValue();
				val = new KMParameterValue();
				val.byteValue = enumValue;
				keyParams.put(key, val);
				break;
			case KMType.ULONG_TAG:
				short int32Ptr = KMIntegerTag.cast(obj).getValue();
				val = new KMParameterValue();
				ByteBuffer int32ByteBuf = ByteBuffer.allocate(8).put(
				    KMInteger.cast(int32Ptr).getBuffer(),
				    KMInteger.cast(int32Ptr).getStartOff(),
				    KMInteger.cast(int32Ptr).length());
				int32ByteBuf.rewind();
				val.integer = int32ByteBuf.getInt();
				keyParams.put(key, val);
				break;
			case KMType.DATE_TAG:
				short datePtr = KMIntegerTag.cast(obj).getValue();
				val = new KMParameterValue();
				ByteBuffer dateByteBuf = ByteBuffer.allocate(8).put(
				    KMInteger.cast(datePtr).getBuffer(),
				    KMInteger.cast(datePtr).getStartOff(),
				    KMInteger.cast(datePtr).length());
				dateByteBuf.rewind();
				val.longinteger = dateByteBuf.getLong();
				keyParams.put(key, val);
				break;
			case KMType.BYTES_TAG:
				short blobPtr = KMByteTag.cast(obj).getValue();
				ByteBuffer blobByteBuf = ByteBuffer.wrap(
				    KMByteBlob.cast(blobPtr).getBuffer(),
				    KMByteBlob.cast(blobPtr).getStartOff(),
				    KMByteBlob.cast(blobPtr).length());
				val = new KMParameterValue();
				val.buf = blobByteBuf;
				keyParams.put(key, val);
				break;
			case KMType.BOOL_TAG:
				val = new KMParameterValue();
				val.byteValue = KMBoolTag.cast(obj).getVal();
				keyParams.put(key, val);
				break;
			}

			index++;
		}
		KMKeyParameterSet paramSet = new KMKeyParameterSet(keyParams);
		return paramSet;
	}
	
	public boolean compare(KMKeyParameterSet paramSet) {
		for (Map.Entry<Short, KMParameterValue> entry : keyParameters.entrySet()) {
			Short key = entry.getKey();
			KMParameterValue val = entry.getValue();
			KMParameterValue other = paramSet.keyParameters.get(key);
			switch (key) {
			case KMType.DIGEST:
			case KMType.PURPOSE:
			case KMType.PADDING:
				if (!val.byteValues.equals(other.byteValues))
					return false;
				break;
			case KMType.RSA_PUBLIC_EXPONENT:
			case KMType.KEYSIZE:
				if (val.integer != other.integer)
					return false;
				break;
			case KMType.APPLICATION_DATA:
			case KMType.APPLICATION_ID:
				if (0 != val.buf.compareTo(other.buf))
					return false;
				break;
			case KMType.CREATION_DATETIME:
			case KMType.ACTIVE_DATETIME:
				if (val.longinteger != other.longinteger)
					return false;
				break;
			case KMType.ALGORITHM:
			case KMType.NO_AUTH_REQUIRED:
			case KMType.INCLUDE_UNIQUE_ID:
			case KMType.RESET_SINCE_ID_ROTATION:
				if (val.byteValue != other.byteValue)
					return false;
				break;
			}
		}
		return true;
	}

	public static class KeyParametersSetBuilder {
		private Map<Short, KMParameterValue> keyParameters_;
		
		public KeyParametersSetBuilder() {
			keyParameters_ = new HashMap<>();
		}

		public KeyParametersSetBuilder setKeySize(int keySize) {
			KMParameterValue val = new KMParameterValue();
			val.integer = keySize;
			keyParameters_.put(KMType.KEYSIZE, val);
			return this;
		}

		public KeyParametersSetBuilder setAlgorithm(byte algorithm) {
			KMParameterValue val = new KMParameterValue();
			val.byteValue = algorithm;
			keyParameters_.put(KMType.ALGORITHM, val);
			return this;
		}

		public KeyParametersSetBuilder setDigest(byte... digests) {
			ArrayList<Byte> list = new ArrayList<>();
			for (byte digest : digests)
				list.add(digest);
			KMParameterValue val = new KMParameterValue();
			val.byteValues = list;
			keyParameters_.put(KMType.DIGEST, val);
			return this;
		}

		public KeyParametersSetBuilder setPadding(byte... paddings) {
			ArrayList<Byte> list = new ArrayList<>();
			for (byte padding : paddings)
				list.add(padding);
			KMParameterValue val = new KMParameterValue();
			val.byteValues = list;
			keyParameters_.put(KMType.PADDING, val);
			return this;
		}

		public KeyParametersSetBuilder setPurpose(byte... purposes) {
			ArrayList<Byte> list = new ArrayList<>();
			for (byte purpose : purposes)
				list.add(purpose);
			KMParameterValue val = new KMParameterValue();
			val.byteValues = list;
			keyParameters_.put(KMType.PURPOSE, val);
			return this;
		}

		public KeyParametersSetBuilder setActiveDateTime(long time) {
			KMParameterValue val = new KMParameterValue();
			val.longinteger = time;
			keyParameters_.put(KMType.ACTIVE_DATETIME, val);
			return this;
		}

		public KeyParametersSetBuilder setCreationDateTime(long time) {
			KMParameterValue val = new KMParameterValue();
			val.longinteger = time;
			keyParameters_.put(KMType.CREATION_DATETIME, val);
			return this;
		}

		public KeyParametersSetBuilder setRsaPubExp(int pubexp) {
			KMParameterValue val = new KMParameterValue();
			val.integer = pubexp;
			keyParameters_.put(KMType.RSA_PUBLIC_EXPONENT, val);
			return this;
		}

		public KeyParametersSetBuilder setApplicationData(ByteBuffer byteBuf) {
			KMParameterValue val = new KMParameterValue();
			val.buf = byteBuf;
			keyParameters_.put(KMType.APPLICATION_DATA, val);
			return this;
		}

		public KeyParametersSetBuilder setApplicationId(ByteBuffer byteBuf) {
			KMParameterValue val = new KMParameterValue();
			val.buf = byteBuf;
			keyParameters_.put(KMType.APPLICATION_ID, val);
			return this;
		}

		public KMKeyParameterSet build() {
			KMKeyParameterSet paramSet = new KMKeyParameterSet(keyParameters_);
			return paramSet;
		}
	}

}
