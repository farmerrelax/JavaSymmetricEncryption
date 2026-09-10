package cc.jce.smile.se.aes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AESEncryption {
	
	public static enum ModeOperation {
		ECB, CBC, CFB, OFB, CTR
	}

	// S-box
	static final Map<String, String> sBox = new HashMap<String, String>();
	static final Map<String, String> invSBox = new HashMap<String, String>();
	static final List<String> rCons = new ArrayList<String>();

	static {
		// put S-box
		// row 0
		sBox.put("00", "63");
		sBox.put("01", "7c");
		sBox.put("02", "77");
		sBox.put("03", "7b");
		sBox.put("04", "f2");
		sBox.put("05", "6b");
		sBox.put("06", "6f");
		sBox.put("07", "c5");
		sBox.put("08", "30");
		sBox.put("09", "01");
		sBox.put("0a", "67");
		sBox.put("0b", "2b");
		sBox.put("0c", "fe");
		sBox.put("0d", "d7");
		sBox.put("0e", "ab");
		sBox.put("0f", "76");

		// row 1
		sBox.put("10", "ca");
		sBox.put("11", "82");
		sBox.put("12", "c9");
		sBox.put("13", "7d");
		sBox.put("14", "fa");
		sBox.put("15", "59");
		sBox.put("16", "47");
		sBox.put("17", "f0");
		sBox.put("18", "ad");
		sBox.put("19", "d4");
		sBox.put("1a", "a2");
		sBox.put("1b", "af");
		sBox.put("1c", "9c");
		sBox.put("1d", "a4");
		sBox.put("1e", "72");
		sBox.put("1f", "c0");

		// row 2
		sBox.put("20", "b7");
		sBox.put("21", "fd");
		sBox.put("22", "93");
		sBox.put("23", "26");
		sBox.put("24", "36");
		sBox.put("25", "3f");
		sBox.put("26", "f7");
		sBox.put("27", "cc");
		sBox.put("28", "34");
		sBox.put("29", "a5");
		sBox.put("2a", "e5");
		sBox.put("2b", "f1");
		sBox.put("2c", "71");
		sBox.put("2d", "d8");
		sBox.put("2e", "31");
		sBox.put("2f", "15");

		// row 3
		sBox.put("30", "04");
		sBox.put("31", "c7");
		sBox.put("32", "23");
		sBox.put("33", "c3");
		sBox.put("34", "18");
		sBox.put("35", "96");
		sBox.put("36", "05");
		sBox.put("37", "9a");
		sBox.put("38", "07");
		sBox.put("39", "12");
		sBox.put("3a", "80");
		sBox.put("3b", "e2");
		sBox.put("3c", "eb");
		sBox.put("3d", "27");
		sBox.put("3e", "b2");
		sBox.put("3f", "75");

		// row 4
		sBox.put("40", "09");
		sBox.put("41", "83");
		sBox.put("42", "2c");
		sBox.put("43", "1a");
		sBox.put("44", "1b");
		sBox.put("45", "6e");
		sBox.put("46", "5a");
		sBox.put("47", "a0");
		sBox.put("48", "52");
		sBox.put("49", "3b");
		sBox.put("4a", "d6");
		sBox.put("4b", "b3");
		sBox.put("4c", "29");
		sBox.put("4d", "e3");
		sBox.put("4e", "2f");
		sBox.put("4f", "84");

		// row 5
		sBox.put("50", "53");
		sBox.put("51", "d1");
		sBox.put("52", "00");
		sBox.put("53", "ed");
		sBox.put("54", "20");
		sBox.put("55", "fc");
		sBox.put("56", "b1");
		sBox.put("57", "5b");
		sBox.put("58", "6a");
		sBox.put("59", "cb");
		sBox.put("5a", "be");
		sBox.put("5b", "39");
		sBox.put("5c", "4a");
		sBox.put("5d", "4c");
		sBox.put("5e", "58");
		sBox.put("5f", "cf");

		// row 6
		sBox.put("60", "d0");
		sBox.put("61", "ef");
		sBox.put("62", "aa");
		sBox.put("63", "fb");
		sBox.put("64", "43");
		sBox.put("65", "4d");
		sBox.put("66", "33");
		sBox.put("67", "85");
		sBox.put("68", "45");
		sBox.put("69", "f9");
		sBox.put("6a", "02");
		sBox.put("6b", "7f");
		sBox.put("6c", "50");
		sBox.put("6d", "3c");
		sBox.put("6e", "9f");
		sBox.put("6f", "a8");

		// row 7
		sBox.put("70", "51");
		sBox.put("71", "a3");
		sBox.put("72", "40");
		sBox.put("73", "8f");
		sBox.put("74", "92");
		sBox.put("75", "9d");
		sBox.put("76", "38");
		sBox.put("77", "f5");
		sBox.put("78", "bc");
		sBox.put("79", "b6");
		sBox.put("7a", "da");
		sBox.put("7b", "21");
		sBox.put("7c", "10");
		sBox.put("7d", "ff");
		sBox.put("7e", "f3");
		sBox.put("7f", "d2");

		// row 8
		sBox.put("80", "cd");
		sBox.put("81", "0c");
		sBox.put("82", "13");
		sBox.put("83", "ec");
		sBox.put("84", "5f");
		sBox.put("85", "97");
		sBox.put("86", "44");
		sBox.put("87", "17");
		sBox.put("88", "c4");
		sBox.put("89", "a7");
		sBox.put("8a", "7e");
		sBox.put("8b", "3d");
		sBox.put("8c", "64");
		sBox.put("8d", "5d");
		sBox.put("8e", "19");
		sBox.put("8f", "73");

		// row 9
		sBox.put("90", "60");
		sBox.put("91", "81");
		sBox.put("92", "4f");
		sBox.put("93", "dc");
		sBox.put("94", "22");
		sBox.put("95", "2a");
		sBox.put("96", "90");
		sBox.put("97", "88");
		sBox.put("98", "46");
		sBox.put("99", "ee");
		sBox.put("9a", "b8");
		sBox.put("9b", "14");
		sBox.put("9c", "de");
		sBox.put("9d", "5e");
		sBox.put("9e", "0b");
		sBox.put("9f", "db");

		// row a
		sBox.put("a0", "e0");
		sBox.put("a1", "32");
		sBox.put("a2", "3a");
		sBox.put("a3", "0a");
		sBox.put("a4", "49");
		sBox.put("a5", "06");
		sBox.put("a6", "24");
		sBox.put("a7", "5c");
		sBox.put("a8", "c2");
		sBox.put("a9", "d3");
		sBox.put("aa", "ac");
		sBox.put("ab", "62");
		sBox.put("ac", "91");
		sBox.put("ad", "95");
		sBox.put("ae", "e4");
		sBox.put("af", "79");

		// row b
		sBox.put("b0", "e7");
		sBox.put("b1", "c8");
		sBox.put("b2", "37");
		sBox.put("b3", "6d");
		sBox.put("b4", "8d");
		sBox.put("b5", "d5");
		sBox.put("b6", "4e");
		sBox.put("b7", "a9");
		sBox.put("b8", "6c");
		sBox.put("b9", "56");
		sBox.put("ba", "f4");
		sBox.put("bb", "ea");
		sBox.put("bc", "65");
		sBox.put("bd", "7a");
		sBox.put("be", "ae");
		sBox.put("bf", "08");

		// row c
		sBox.put("c0", "ba");
		sBox.put("c1", "78");
		sBox.put("c2", "25");
		sBox.put("c3", "2e");
		sBox.put("c4", "1c");
		sBox.put("c5", "a6");
		sBox.put("c6", "b4");
		sBox.put("c7", "c6");
		sBox.put("c8", "e8");
		sBox.put("c9", "dd");
		sBox.put("ca", "74");
		sBox.put("cb", "1f");
		sBox.put("cc", "4b");
		sBox.put("cd", "bd");
		sBox.put("ce", "8b");
		sBox.put("cf", "8a");

		// row d
		sBox.put("d0", "70");
		sBox.put("d1", "3e");
		sBox.put("d2", "b5");
		sBox.put("d3", "66");
		sBox.put("d4", "48");
		sBox.put("d5", "03");
		sBox.put("d6", "f6");
		sBox.put("d7", "0e");
		sBox.put("d8", "61");
		sBox.put("d9", "35");
		sBox.put("da", "57");
		sBox.put("db", "b9");
		sBox.put("dc", "86");
		sBox.put("dd", "c1");
		sBox.put("de", "1d");
		sBox.put("df", "9e");

		// row e
		sBox.put("e0", "e1");
		sBox.put("e1", "f8");
		sBox.put("e2", "98");
		sBox.put("e3", "11");
		sBox.put("e4", "69");
		sBox.put("e5", "d9");
		sBox.put("e6", "8e");
		sBox.put("e7", "94");
		sBox.put("e8", "9b");
		sBox.put("e9", "1e");
		sBox.put("ea", "87");
		sBox.put("eb", "e9");
		sBox.put("ec", "ce");
		sBox.put("ed", "55");
		sBox.put("ee", "28");
		sBox.put("ef", "df");

		// row f
		sBox.put("f0", "8c");
		sBox.put("f1", "a1");
		sBox.put("f2", "89");
		sBox.put("f3", "0d");
		sBox.put("f4", "bf");
		sBox.put("f5", "e6");
		sBox.put("f6", "42");
		sBox.put("f7", "68");
		sBox.put("f8", "41");
		sBox.put("f9", "99");
		sBox.put("fa", "2d");
		sBox.put("fb", "0f");
		sBox.put("fc", "b0");
		sBox.put("fd", "54");
		sBox.put("fe", "bb");
		sBox.put("ff", "16");

		// rcon
		rCons.add("01");
		rCons.add("02");
		rCons.add("04");
		rCons.add("08");
		rCons.add("10");
		rCons.add("20");
		rCons.add("40");
		rCons.add("80");
		rCons.add("1b");
		rCons.add("36");

		sBox.forEach((key, value) -> {
			invSBox.put(value, key);
		});
	}

	private String roundKey;

	public AESEncryption(ModeOperation mode) {

	}

	public byte[] encrypt(byte[] bytesPlainText) {
		String plainText = new BigIntegerz(bytesPlainText).toString(16);

		// input
		// addRoundKey
		String keyTemp = roundKey.substring(0, 32);
		String temp = new BigIntegerz(plainText, 16).xor(new BigIntegerz(keyTemp, 16)).toString(16);

		for (int i = 1; i <= (roundKey.length() / 32) - 1; i++) {
			while (temp.length() < 32) {
				temp = "0" + temp;
			}
			String temp2 = "";
			// SubSBox
			for (int j = 0; j < temp.length(); j = j + 2) {
				temp2 += getSBox(temp.substring(j, j + 2));
			}
			// After ShiftRows
			String[][] arr = shiftRows(temp2);
			// After MixColumns
			if (i != (roundKey.length() / 32) - 1) {
				temp = mixColums(arr);
			} else {
				temp = getMatrixToString(arr);
			}

			// Add round key
			keyTemp = roundKey.substring(32 * i, 32 * i + 32);
			temp = new BigIntegerz(temp, 16).xor(new BigIntegerz(keyTemp, 16)).toString(16);
		}
		return new BigIntegerz(temp, 16).toByteArray();
	}

	public byte[] decrypt(byte[] bytesCipherText) {
		String cipherText = new BigIntegerz(bytesCipherText).toString(16);
		while (cipherText.length() < 32) {
			cipherText = "0" + cipherText;
		}
		// input
		// addRoundKey
		String keyTemp = roundKey.substring(roundKey.length() - 32, roundKey.length());
		String temp = new BigIntegerz(cipherText, 16).xor(new BigIntegerz(keyTemp, 16)).toString(16);
		while (temp.length() < 32) {
			temp = "0" + temp;
		}

		for (int i = 1; i <= (roundKey.length() - 8) / 32; i++) {
			String temp2 = "";
			// InvSubSBox
			for (int j = 0; j < temp.length(); j = j + 2) {
				temp2 += getInvSBox(temp.substring(j, j + 2));
			}

			// After InvShiftRows
			String[][] arr = invShiftRows(temp2);

			// Add Round Key
			keyTemp = roundKey.substring(roundKey.length() - i * 32 - 32, roundKey.length() - i * 32);
			temp = getMatrixToString(arr);
			temp = new BigIntegerz(temp, 16).xor(new BigIntegerz(keyTemp, 16)).toString(16);
			// After InvMixColumns
			while (temp.length() < 32) {
				temp = "0" + temp;
			}
			arr = getStringToMatrix(temp);
			if (i != (roundKey.length() - 8) / 32) {
				temp = invMixColums(arr);
			}
		}

		return new BigIntegerz(temp, 16).toByteArray();
	}

//	public void initKey(byte[] bytesCipherKey) {
	public String initKey(byte[] bytesCipherKey) {
		String cipherKey = new BigIntegerz(bytesCipherKey).toString(16);
		if (bytesCipherKey.length < 32) {
			cipherKey = getBin(cipherKey, 32);
		} else if (bytesCipherKey.length < 48) {
			cipherKey = getBin(cipherKey, 48);
		} else if (bytesCipherKey.length < 64) {
			cipherKey = getBin(cipherKey, 64);
		}
		int roundNumber;
		if (cipherKey.length() == 32) {
			roundNumber = 10;
		} else if (cipherKey.length() == 48) {
			roundNumber = 12;
		} else if (cipherKey.length() == 64) {
			roundNumber = 14;
		} else {
			throw new RuntimeException("ERROR");
		}
		roundKey = expansionKey(cipherKey, roundNumber, cipherKey.length() / 8);
		return roundKey;
	}

	// Ci = EK(Pi)
	public static final class ECB extends AESEncryption {

		public ECB() {
			super(ModeOperation.ECB);
		}

		public byte[] encrypt(byte[] bytesPlainText) {
			List<String> plainTextBlock = super.caculatorPlainTextBlock(new BigIntegerz(bytesPlainText).toString(16));
			String cipherText = "";
			for (int count = 0; count < plainTextBlock.size(); count++) {
				String temp = new BigIntegerz(super.encrypt(new BigIntegerz(plainTextBlock.get(count), 16).toByteArray()))
						.toString(16);
				if(temp.length() < 32) {
					temp = "0" + temp;
				}
				cipherText += temp;
			}
			return new BigIntegerz(cipherText, 16).toByteArray();
		}

		public byte[] decrypt(byte[] bytesCipherText) {
			String cipherTextBlock = new BigIntegerz(bytesCipherText).toString(16);
			String plainText = "";
			for (int count = 0; count < cipherTextBlock.length(); count = count + 32) {
				plainText += new BigIntegerz(
						super.decrypt(new BigIntegerz(cipherTextBlock.substring(count, count + 32), 16).toByteArray()))
						.toString(16);
			}
			return new BigIntegerz(plainText, 16).toByteArray();
		}

	}

	// C0=IV
	// Ci = Ek(Pi xor Ci-1)
	public static final class CBC extends AESEncryption {

		private byte[] iv;

		public CBC(byte[] iv) {
			super(ModeOperation.CBC);
			this.iv = iv;
		}

		public byte[] encrypt(byte[] bytesPlainText) {
			List<String> plainTextBlock = super.caculatorPlainTextBlock(new BigIntegerz(bytesPlainText).toString(16));
			String cipherText = "";
			for (int count = 0; count < plainTextBlock.size(); count++) {
				BigIntegerz plainTextBlockTemp;
				if (count == 0) {
					plainTextBlockTemp = new BigIntegerz(iv).xor(new BigIntegerz(plainTextBlock.get(count), 16));
				} else {
					plainTextBlockTemp = new BigIntegerz(
							cipherText.substring(cipherText.length() - 32, cipherText.length()), 16)
							.xor(new BigIntegerz(plainTextBlock.get(count), 16));
				}
				cipherText += super.getBin(new BigIntegerz(super.encrypt(plainTextBlockTemp.toByteArray())).toString(16),
						32);
			}
			return new BigIntegerz(cipherText, 16).toByteArray();
		}

		public byte[] decrypt(byte[] bytesCipherText) {
			String cipherTextBlock = new BigIntegerz(bytesCipherText).toString(16);
			while (cipherTextBlock.length() % 32 != 0) {
				cipherTextBlock = "0" + cipherTextBlock;
			}
			String plainText = "";
			for (int count = 0; count < cipherTextBlock.length(); count = count + 32) {
				String plainTextTemp = new BigIntegerz(
						super.decrypt(new BigIntegerz(cipherTextBlock.substring(count, count + 32), 16).toByteArray()))
						.toString(16);
				if (count == 0) {
					plainTextTemp = new BigIntegerz(iv).xor(new BigIntegerz(plainTextTemp, 16)).toString(16);
				} else {
					plainTextTemp = new BigIntegerz(cipherTextBlock.substring(count - 32, count), 16)
							.xor(new BigIntegerz(plainTextTemp, 16)).toString(16);
				}
				plainText += plainTextTemp;

			}
			return new BigIntegerz(plainText, 16).toByteArray();
		}
	}

	// Zi=IV
	// Zi = Ek(Zi-1)
	// Ci =Zi xor Pi
	public static final class OFB extends AESEncryption {

		private byte[] iv;

		public OFB(byte[] iv) {
			super(ModeOperation.OFB);
			this.iv = iv;
		}

		public byte[] encrypt(byte[] bytesPlainText) {
			List<String> plainTextBlock = super.caculatorPlainTextBlock(new BigIntegerz(bytesPlainText).toString(16));
			String cipherText = "";
			String outputEncrypt = null;
			for (int count = 0; count < plainTextBlock.size(); count++) {
				if (count == 0) {
					outputEncrypt = super.getBin(new BigIntegerz(super.encrypt(iv)).toString(16), 32);
				} else {
					outputEncrypt = super.getBin(
							new BigIntegerz(super.encrypt(new BigIntegerz(outputEncrypt, 16).toByteArray())).toString(16),
							32);
				}
				cipherText += new BigIntegerz(outputEncrypt, 16).xor(new BigIntegerz(plainTextBlock.get(count), 16))
						.toString(16);
			}
			return new BigIntegerz(cipherText, 16).toByteArray();
		}

		public byte[] decrypt(byte[] bytesCipherText) {
			String cipherTextBlock = new BigIntegerz(bytesCipherText).toString(16);
			while (cipherTextBlock.length() % 32 != 0) {
				cipherTextBlock = "0" + cipherTextBlock;
			}
			String plainText = "";
			String outputEncrypt = null;
			for (int count = 0; count < cipherTextBlock.length(); count = count + 32) {
				if (count == 0) {
					outputEncrypt = new BigIntegerz(super.encrypt(iv)).toString(16);
				} else {
					outputEncrypt = new BigIntegerz(super.encrypt(new BigIntegerz(outputEncrypt, 16).toByteArray()))
							.toString(16);
				}
				plainText += new BigIntegerz(outputEncrypt, 16)
						.xor(new BigIntegerz(cipherTextBlock.substring(count, count + 32), 16)).toString(16);

			}
			return new BigIntegerz(plainText, 16).toByteArray();
		}
	}

	// C0 = IV
	// Ci = Ek(Ci-1) xor Pi
	public static final class CFB extends AESEncryption {

		private byte[] iv;

		public CFB(byte[] iv) {
			super(ModeOperation.CFB);
			this.iv = iv;
		}

		public byte[] encrypt(byte[] bytesPlainText) {
			List<String> plainTextBlock = super.caculatorPlainTextBlock(new BigIntegerz(bytesPlainText).toString(16));
			String cipherText = "";
			String outputEncrypt = null;
			for (int count = 0; count < plainTextBlock.size(); count++) {
				if (count == 0) {
					outputEncrypt = super.getBin(new BigIntegerz(super.encrypt(iv)).toString(16), 32);
				} else {
					outputEncrypt = super.getBin(new BigIntegerz(super.encrypt(
							new BigIntegerz(cipherText.substring(cipherText.length() - 32, cipherText.length()), 16)
									.toByteArray()))
							.toString(16), 32);
				}
				cipherText += new BigIntegerz(outputEncrypt, 16).xor(new BigIntegerz(plainTextBlock.get(count), 16))
						.toString(16);
			}
			return new BigIntegerz(cipherText, 16).toByteArray();
		}

		public byte[] decrypt(byte[] bytesCipherText) {
			String cipherTextBlock = new BigIntegerz(bytesCipherText).toString(16);
			while (cipherTextBlock.length() % 32 != 0) {
				cipherTextBlock = "0" + cipherTextBlock;
			}
			String plainText = "";
			String outputEncrypt = null;
			for (int count = 0; count < cipherTextBlock.length(); count = count + 32) {
				if (count == 0) {
					outputEncrypt = new BigIntegerz(super.encrypt(iv)).toString(16);
				} else {
					outputEncrypt = super.getBin(new BigIntegerz(super.encrypt(
							new BigIntegerz(cipherTextBlock.substring(count - 32, count), 16).toByteArray()))
							.toString(16), 32);
				}
				plainText += super.getBin(
						new BigIntegerz(outputEncrypt, 16)
								.xor(new BigIntegerz(cipherTextBlock.substring(count, count + 32), 16)).toString(16),
						32);

			}
			return new BigIntegerz(plainText, 16).toByteArray();
		}
	}

	public static final class CTR extends AESEncryption {

		private byte[] iv;

		public CTR(byte[] iv) {
			super(ModeOperation.CTR);
			this.iv = iv;
		}

		public byte[] encrypt(byte[] bytesPlainText) {
			BigInteger counterTemp = new BigInteger(iv);
			List<String> plainTextBlock = super.caculatorPlainTextBlock(new BigIntegerz(bytesPlainText).toString(16));
			String cipherText = "";
			String outputEncrypt = null;
			for (int count = 0; count < plainTextBlock.size(); count++) {
				outputEncrypt = super.getBin(new BigIntegerz(super.encrypt(counterTemp.toByteArray())).toString(16), 32);
				cipherText += new BigIntegerz(outputEncrypt, 16).xor(new BigIntegerz(plainTextBlock.get(count), 16))
						.toString(16);
				counterTemp = counterTemp.add(BigIntegerz.valueOf(1));
			}
			return new BigIntegerz(cipherText, 16).toByteArray();
		}

		public byte[] decrypt(byte[] bytesCipherText) {
			BigInteger counterTemp = new BigInteger(iv);
			String cipherTextBlock = new BigIntegerz(bytesCipherText).toString(16);
			while (cipherTextBlock.length() % 32 != 0) {
				cipherTextBlock = "0" + cipherTextBlock;
			}
			String plainText = "";
			String outputEncrypt = null;
			for (int count = 0; count < cipherTextBlock.length(); count = count + 32) {
				outputEncrypt = new BigIntegerz(super.encrypt(counterTemp.toByteArray())).toString(16);
				plainText += super.getBin(
						new BigIntegerz(outputEncrypt, 16)
								.xor(new BigIntegerz(cipherTextBlock.substring(count, count + 32), 16)).toString(16),
						32);
				counterTemp = counterTemp.add(BigIntegerz.valueOf(1));
			}
			return new BigIntegerz(plainText, 16).toByteArray();
		}
	}

	private List<String> caculatorPlainTextBlock(String plainText) {
		List<String> plainTextBlock = new ArrayList<String>();
		if (plainText.length() == 32) {
			plainTextBlock.add(plainText);
		}
//		if (plainText.length() < 32) {
		else if (plainText.length() < 32) {
			String padding = BigIntegerz.valueOf((32 - plainText.length()) / 2).toString(16);
			padding = padding.length() == 1 ? "0" + padding : padding;
			while (plainText.length() < 32) {
				plainText += padding;
			}
			plainTextBlock.add(plainText);
		} else {
//		} else if(plainText.length() > 32) {
			int paddingLength = (32 - (plainText.length() % 32)) / 2;
			int i = 0;
			String temp = "";
			while (i < plainText.length() + paddingLength * 2) {
				if (i < (plainText.length() / 32) * 32) {
					plainTextBlock.add(plainText.substring(i, i + 32));
					i = i + 32;
				} else if (i < (plainText.length() / 32) * 32 + paddingLength * 2) {
					temp = plainText.substring(i, i + 32 - paddingLength * 2);
					i = i + 32 - paddingLength * 2;
				} else {
					temp += getBin(BigIntegerz.valueOf(paddingLength).toString(16), 2);
					i = i + 2;
				}
			}
			plainTextBlock.add(temp);
		}
		return plainTextBlock;
	}

	private String rotWord(String w) {
		w = w.substring(2) + w.substring(0, 2);
		return w;
	}

	private String subWord(String wTemp) {
		wTemp.substring(6, 8);
		return getSBox(wTemp.substring(0, 2)) + getSBox(wTemp.substring(2, 4)) + getSBox(wTemp.substring(4, 6))
				+ getSBox(wTemp.substring(6, 8));
	}

	private String xorRCon(String wTemp, String rCon) {
		String temp = new BigIntegerz(wTemp.substring(0, 2), 16).xor(new BigIntegerz(rCon.substring(0, 2), 16))
				.toString(16);
		temp = temp.length() == 1 ? "0" + temp : temp;
		return temp + wTemp.substring(2, 8);
	}

	private String xorWPrevious(String wTemp, String wPrevious) {
		String temp = new BigIntegerz(wTemp, 16).xor(new BigIntegerz(wPrevious, 16)).toString(16);
		while (temp.length() < 8) {
			temp = "0" + temp;
		}
		return temp;
	}

	private String expansionKey(String cipherKey, int roundNumber, int Nk) {
		String roundKeyStr = "";
		List<String> roundKey = new ArrayList<String>();

		for (int i = 0; i < cipherKey.length() / 8; i++) {
			String wTemp = cipherKey.substring(i * 8, i * 8 + 8);
			roundKey.add(wTemp);
			roundKeyStr += wTemp;
		}

		for (int i = Nk; i < roundNumber * 4 + 4; i++) {
			String wTemp = roundKey.get(i - 1);
			if (i % Nk == 0) {
				// dịch trái 1 byte - RotWord(w[i - 1])
				wTemp = rotWord(wTemp);

				// thay thế 1 byte từ hộp S - SubWord(RotWord(w[i - 1]))
				wTemp = subWord(wTemp);

				// XOR với hằng số Rcon[j] - SubWord(RotWord(w[i - 1])) xor Rcon[j],j = i/4
//				System.out.println("i: " + i);
				String rConValue = rCons.get((i / Nk) - 1);
				wTemp = xorRCon(wTemp, rConValue);
			} else if (i % 4 == 0 && Nk > 6) {
				wTemp = subWord(wTemp);
			}
			wTemp = xorWPrevious(wTemp, roundKey.get(i - Nk));
			roundKey.add(wTemp);
			roundKeyStr += wTemp;
		}
		return roundKeyStr;
	}

	private String subBytes(String temp) {
		String temp2 = "";
		for (int i = 0; i < temp.length(); i = i + 2) {
			temp2 += getSBox(temp.substring(i, i + 2));
		}
		return temp2;
	}

	private String[][] shiftRows(String temp) {
		String[][] arr = new String[4][4];
		int count = 0;
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				arr[j][i] = temp.substring(count, count + 2);
				count += 2;
			}
		}
		for (int i = 0; i < 4; i++) {
			if (i == 1) {
				String tmp = arr[i][0];
				arr[i][0] = arr[i][1];
				arr[i][1] = arr[i][2];
				arr[i][2] = arr[i][3];
				arr[i][3] = tmp;
			} else if (i == 2) {
				String tmp = arr[i][0];
				arr[i][0] = arr[i][1];
				arr[i][1] = arr[i][2];
				arr[i][2] = arr[i][3];
				arr[i][3] = tmp;

				tmp = arr[i][0];
				arr[i][0] = arr[i][1];
				arr[i][1] = arr[i][2];
				arr[i][2] = arr[i][3];
				arr[i][3] = tmp;
			} else if (i == 3) {
				String tmp = arr[i][0];
				arr[i][0] = arr[i][1];
				arr[i][1] = arr[i][2];
				arr[i][2] = arr[i][3];
				arr[i][3] = tmp;

				tmp = arr[i][0];
				arr[i][0] = arr[i][1];
				arr[i][1] = arr[i][2];
				arr[i][2] = arr[i][3];
				arr[i][3] = tmp;

				tmp = arr[i][0];
				arr[i][0] = arr[i][1];
				arr[i][1] = arr[i][2];
				arr[i][2] = arr[i][3];
				arr[i][3] = tmp;
			}
		}

		return arr;
	}

	private String[][] invShiftRows(String temp) {
		String[][] arr = new String[4][4];
		int count = 0;
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				arr[j][i] = temp.substring(count, count + 2);
				count += 2;
			}
		}
		for (int i = 0; i < 4; i++) {
			if (i == 1) {
				String tmp = arr[i][3];
				arr[i][3] = arr[i][2];
				arr[i][2] = arr[i][1];
				arr[i][1] = arr[i][0];
				arr[i][0] = tmp;
			} else if (i == 2) {
				String tmp = arr[i][3];
				arr[i][3] = arr[i][2];
				arr[i][2] = arr[i][1];
				arr[i][1] = arr[i][0];
				arr[i][0] = tmp;

				tmp = arr[i][3];
				arr[i][3] = arr[i][2];
				arr[i][2] = arr[i][1];
				arr[i][1] = arr[i][0];
				arr[i][0] = tmp;
			} else if (i == 3) {
				String tmp = arr[i][3];
				arr[i][3] = arr[i][2];
				arr[i][2] = arr[i][1];
				arr[i][1] = arr[i][0];
				arr[i][0] = tmp;

				tmp = arr[i][3];
				arr[i][3] = arr[i][2];
				arr[i][2] = arr[i][1];
				arr[i][1] = arr[i][0];
				arr[i][0] = tmp;

				tmp = arr[i][3];
				arr[i][3] = arr[i][2];
				arr[i][2] = arr[i][1];
				arr[i][1] = arr[i][0];
				arr[i][0] = tmp;
			}
		}

		return arr;
	}

	private String mixColums(String[][] arr) {
		String[][] cx = { { "02", "03", "01", "01" }, { "01", "02", "03", "01" }, { "01", "01", "02", "03" },
				{ "03", "01", "01", "02" } };
		String[][] result = new String[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				BigInteger temp = BigInteger.valueOf(0);
				for (int k = 0; k < 4; k++) {
					temp = new BigIntegerz(multiply(arr[k][j], cx[i][k]), 16).xor(temp);
				}
				result[i][j] = temp.toString(16).length() == 1 ? "0" + temp.toString(16) : temp.toString(16);
			}
		}

		String temp = "";
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				temp += result[j][i];
			}
		}
		return temp;
	}

	private String invMixColums(String[][] arr) {
		String[][] cx = { { "0e", "0b", "0d", "09" }, { "09", "0e", "0b", "0d" }, { "0d", "09", "0e", "0b" },
				{ "0b", "0d", "09", "0e" } };
		String[][] result = new String[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				BigInteger temp = BigInteger.valueOf(0);
				for (int k = 0; k < 4; k++) {
					temp = new BigIntegerz(multiply(arr[k][j], cx[i][k]), 16).xor(temp);
				}
				result[i][j] = temp.toString(16).length() == 1 ? "0" + temp.toString(16) : temp.toString(16);
			}
		}

		String temp = "";
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				temp += result[j][i];
			}
		}
		return temp;
	}

	private String multiply(String number1, String number2) {
		int count = 8 - new BigIntegerz(number2, 16).toString(2).indexOf("1");
		List<String> xtimeValues = new ArrayList<String>();
		xtimeValues.add(number1);
		String temp = number1;
		for (int i = 1; i < count; i++) {
			xtimeValues.add(xtime(xtimeValues.get(i - 1)));
			if (getBin(number2).charAt(7 - i) == '1') {
				if (i == 1 && getBin(number2).charAt(7) == '0') {
					temp = xtime(xtimeValues.get(i - 1));
				} else {
					temp = new BigIntegerz(temp, 16).xor(new BigIntegerz(xtime(xtimeValues.get(i - 1)), 16)).toString(16);
				}
			}
		}
		return temp;
	}

	private String xtime(String number1) {
		String temp = getBin(number1) + "0";
		String temp2 = new BigIntegerz(temp.substring(1, temp.length()), 2).toString(16);
		if (temp.substring(0, 1).equals("1")) {
			temp2 = new BigIntegerz(temp2, 16).xor(new BigIntegerz("1b", 16)).toString(16);
		}
		return temp2.length() == 1 ? "0" + temp2 : temp2;
	}

	private String getBin(String hex) {
		String result = new BigIntegerz(hex, 16).toString(2);
		while (result.length() < 8) {
			result = "0" + result;
		}
		return result;
	}

	private String getBin(String hex, int length) {
		while (hex.length() < length) {
			hex = "0" + hex;
		}
		return hex;
	}

	private String getSBox(String key) {
		return sBox.get(key);
	}

	private String getInvSBox(String key) {
		return invSBox.get(key);
	}
	
	private String getMatrixToString(String[][] arr) {
		String temp = "";
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				temp += arr[j][i];
			}
		}
		return temp;
	}

	private String[][] getStringToMatrix(String temp) {
		String[][] arr = new String[4][4];
		int count = 0;
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				arr[j][i] = temp.substring(count, count + 2);
				count += 2;
			}
		}
		return arr;
	}
}


