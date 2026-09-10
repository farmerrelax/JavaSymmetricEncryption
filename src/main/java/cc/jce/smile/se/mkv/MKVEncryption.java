package cc.jce.smile.se.mkv;

import cc.jce.smile.Utilities;

final class MKVEncryption {
	private MKVCore core;
	private char[][] roundKeys;
	private int round;
	private int length;
	
	MKVEncryption(MKVType type) {
		core = new MKVCore(type.block);
		length = type.block;
	}
	
	final byte[] encrypt(byte[] plainText) {
		System.out.println("############################################################");
		System.out.println("ENCRYPT");
		int r = round;
		if (plainText.length != length) {
			return null;
		}
		
		char tempData[] = convertBytesToChars(plainText, length);
		
		for (int i = 0; i < r; i++) {
			System.out.println("############################################################");
			System.out.println("Vòng " + (i + 1));
			tempData = xor(tempData, roundKeys[i << 1], length);
			System.out.printf("Cộng khóa k[%d]: \t\t%s\n", (2 * i), Utilities.convertCharBytesToHexString(tempData));
			tempData = core.subCellsz(tempData, this);
			System.out.println("SubCells: \t\t" + Utilities.convertCharBytesToHexString(tempData));
			tempData = core.mixWordsz(core.convertArrayToMatrix(tempData, this), this);
			System.out.println("MixWords: \t\t" + Utilities.convertCharBytesToHexString(tempData));
			tempData = xor(tempData, roundKeys[(i << 1) + 1], length);
			System.out.printf("Cộng khóa k[%d]: \t\t%s\n", (2 * i + 1), Utilities.convertCharBytesToHexString(tempData));
			tempData = core.subCellsz(tempData, this);
			System.out.println("SubCells: \t\t" + Utilities.convertCharBytesToHexString(tempData));
			tempData = core.xWordsz(tempData, this);
			System.out.println("XWords: \t\t\t" + Utilities.convertCharBytesToHexString(tempData));
		}
		tempData = xor(tempData, roundKeys[r << 1], length);
		System.out.println("############################################################");
		System.out.printf("Cộng khóa k-post[%d]: \t\t%s\n", (2 * r), tempData);
		System.out.println("Bản mã: \t\t" + Utilities.convertCharBytesToHexString(tempData));
		System.out.println("############################################################");
		return convertCharsToBytes(tempData, length);
	}
	
	final byte[] decrypt(byte[] cipherText) {
		int r = round;
		char[] tempData = convertBytesToChars(cipherText, length);
		tempData = xor(tempData, roundKeys[r << 1], length);
		for (int i = r - 1; i > -1; i--) {
			tempData = core.xWordsz(tempData, this);
			tempData = core.invSubCellsz(tempData, this);
			tempData = xor(tempData, roundKeys[(i << 1) + 1], length);
			tempData = core.invMixWordsz(core.convertArrayToMatrix(tempData, this), this);
			tempData = core.invSubCellsz(tempData, this);
			tempData = xor(tempData, roundKeys[i << 1], length);
		}
		System.out.println("Bản rõ: \t\t" + tempData);
		return convertCharsToBytes(tempData, length);
	}
	
	final char[][] initKey(byte[] cipherKey) {
		char[] initKey = new char[length << 1];
		char[] tempKey = new char[length << 1];
		for(int i = 0; i < cipherKey.length; i++) {
			tempKey[i] = (char) cipherKey[i];
		}
		int countRow = length >> 2;
		if (cipherKey.length == length) {
			round = 7;
			for(int i = 0; i < length >> 2; i++) {
				initKey[i] = tempKey[i];
				initKey[i + countRow] = tempKey[i + countRow];
				initKey[i + countRow*2] = tempKey[i + countRow*2];
				initKey[i + countRow*3] = tempKey[i + countRow*3];
				initKey[i + countRow*4] = inversionBit(tempKey[i]);
				initKey[i + countRow*5] = inversionBit(tempKey[i + countRow]);
				initKey[i + countRow*6] = inversionBit(tempKey[i + countRow*2]);
				initKey[i + countRow*7] = inversionBit(tempKey[i + countRow*3]);
			}
		} else if(cipherKey.length == ((length * 3) >> 1)) {
			round = 8;
			for(int i = 0; i < length >> 2; i++) {
				initKey[i] = tempKey[i];
				initKey[i + countRow] = tempKey[i + countRow];
				initKey[i + countRow*2] = tempKey[i + countRow*2];
				initKey[i + countRow*3] = tempKey[i + countRow*3];
				initKey[i + countRow*4] = tempKey[i + countRow*4];
				initKey[i + countRow*5] = tempKey[i + countRow*5];
				initKey[i + countRow*6] = inversionBit(tempKey[i + countRow*2]);
				initKey[i + countRow*7] = inversionBit(tempKey[i + countRow*3]);
			}
		} else if(cipherKey.length == (length << 1)) {
			round = 9;
			for(int i = 0; i < length >> 2; i++) {
				initKey[i] = tempKey[i];
				initKey[i + countRow] = tempKey[i + countRow];
				initKey[i + countRow*2] = tempKey[i + countRow*2];
				initKey[i + countRow*3] = tempKey[i + countRow*3];
				initKey[i + countRow*4] = tempKey[i + countRow*4];
				initKey[i + countRow*5] = tempKey[i + countRow*5];
				initKey[i + countRow*6] = tempKey[i + countRow*6];
				initKey[i + countRow*7] = tempKey[i + countRow*7];
			}
		} else {
			return null;
		}
		this.roundKeys = expansionKey(initKey);
		return roundKeys;
	}
	
	private final char[][] expansionKey(char[] initKey) {
		char[] tempKey = initKey.clone();
		char[][] roundKeys = new char[(round << 1) + 1][length];
		char[] keyLeft = new char[length];
		char[] keyRight = new char[length];
		for(int i = 0; i < length; i++) {
			// K-0
			keyLeft[i] = tempKey[i];
			// K-1
			keyRight[i] = tempKey[i + length];
		}
		roundKeys[0] = keyLeft.clone();
		for (int i = 0; i < round; i++) {
			System.out.println("############################################################");
			System.out.println("i = " + i);
			System.out.println("K-1");
			keyRight = calTempKey(keyRight, (i << 1) + 2);
			System.out.println("K-0");
			keyLeft = calTempKey(keyLeft, (i << 1) + 1);
			keyLeft = xor(keyLeft, keyRight, length);
			char[] temp = keyRight.clone();
			keyRight = keyLeft.clone();
			keyLeft = temp.clone();
			roundKeys[(i << 1) + 1] = keyLeft;
			roundKeys[(i << 1) + 2] = keyRight;
			System.out.println("############################################################");
		}
		int i = 0;
		for (char[] roundKey : roundKeys) {
			System.out.printf("i = %d: %s\n", i, Utilities.convertCharBytesToHexString(roundKey));
			i++;
		}
		return roundKeys;
	}
	
	private final char[] xor(char[] str1, char[] str2, int length) {
		char[] result = new char[length];
		for(int i = 0; i < length; i++) {
			result[i] = (char) (str1[i]^str2[i]);
		}
		return result;
	}
	
	private char[] calTempKey(char[] key, int numberXor) {
		char[] tempKey = key.clone();
		tempKey[tempKey.length - 1] = (char) (tempKey[tempKey.length - 1]^numberXor);
		System.out.println("Cộng hằng số: \t" + Utilities.convertCharBytesToHexString(tempKey));
		tempKey = core.subCellsz(tempKey, this);
		System.out.println("SubCells: \t" + Utilities.convertCharBytesToHexString(tempKey));
		tempKey = core.mixWordsz(core.convertArrayToMatrix(tempKey, this), this);
		System.out.println("MixWords: \t" + Utilities.convertCharBytesToHexString(tempKey));
		tempKey = core.subCellsz(tempKey, this);
		System.out.println("SubCells: \t" + Utilities.convertCharBytesToHexString(tempKey));
		tempKey = core.xWordsz(tempKey, this);
		System.out.println("XWords: \t\t" + Utilities.convertCharBytesToHexString(tempKey));
		tempKey = core.subCellsz(tempKey, this);
		System.out.println("SubCells: \t" + Utilities.convertCharBytesToHexString(tempKey));
		tempKey = core.mixWordsz(core.convertArrayToMatrix(tempKey, this), this);
		System.out.println("MixWords: \t" + Utilities.convertCharBytesToHexString(tempKey));
		tempKey = core.subCellsz(tempKey, this);
		System.out.println("SubCells: \t" + Utilities.convertCharBytesToHexString(tempKey));
		tempKey = core.xWordsz(tempKey, this);
		System.out.println("XWords: \t\t" + Utilities.convertCharBytesToHexString(tempKey));
		return tempKey;
	}
	
	private final char[] inversion(char[] values) {
		char[] temp = new char[length];
		for(int i = 0; i < length; i++) {
			temp[i] = inversionBit(values[i]);
		}
		return temp;
	}
	
	private final char inversionBit(char value) {
		value = (char) ~value;
		value = (char) (((value >> 8) << 8)^value);
		return value;
	}
	
	private final char[] convertBytesToChars(byte[] bytes, int length) {
		char[] chars = new char[length];
		for(int i = 0; i < length; i++) {
//			chars[i] = (char) bytes[i];
			chars[i] = (char) (bytes[i] & 0xff);
		}
		return chars;
	}
	
	private final byte[] convertCharsToBytes(char[] chars, int length) {
		byte[] bytes = new byte[length];
		for(int i = 0; i < length; i++) {
			bytes[i] = (byte) (chars[i] & 0xff);
		}
		return bytes;
	}
}

