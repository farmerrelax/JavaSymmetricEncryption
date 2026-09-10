package cc.jce.smile;

public class Utilities {
	public static char convertHexStringToHexByte(String str) {
		char value1 = str.charAt(0);
		char value2 = str.charAt(1);
		value1 = (char) (value1 < 0x3a ? value1 - 0x30 : value1 - 0x57);
		value2 = (char) (value2 < 0x3a ? value2 - 0x30 : value2 - 0x57);
		char value = value1;
		value = (char) (value1 << 4);
		value += value2;
		return value;
	}
	
	public static char[] convertHexStringToHexBytes(String str, int offset, int length) {
		char[] result = new char[length/2];
		int count = offset;
		for(int i = offset; i < offset + length; i += 2) {
			result[count++] = convertHexStringToHexByte(str.substring(i, i + 2).toLowerCase());
		}
		return result;
	}
	
	public static char[] convertHexStringToHexBytes(String str) {
		return convertHexStringToHexBytes(str, 0, str.length());
	}
	
	public static byte[] convertHexStringBytes(String str) {
		char[] chars = convertHexStringToHexBytes(str, 0, str.length());
		byte[] results = new byte[chars.length];
		for(int i = 0; i < results.length; i++) {
			results[i] = (byte) chars[i];
		}
		return results;
	}
	
	public static String convertCharBytesToHexString(char[] chars) {
		String result = "";
		for(int i = 0; i < chars.length; i++) {
			String hex = String.format("%x", (int) chars[i]);
			result += hex.length() == 1 ? ("0" + hex) : hex;
		}
		return result;
	}
}

