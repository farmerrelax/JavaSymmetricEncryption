package cc.jce.smile.se.aes;

import java.math.BigInteger;

public class BigIntegerz extends BigInteger {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 7049209512830038646L;

	public BigIntegerz(String val, int radix) {
		super(val, radix);
	}
	
	public BigIntegerz(byte[] bytes) {
		super(bytes);
	}
	
	public BigIntegerz(BigInteger val) {
		super(val.toString(16), 16);
	}
	
	public String toString(int radix) {
		String result = super.toString(radix);
			
		if(result.length() < 2 && result.length() % 2 != 0) {
			while(result.length() % 2 != 0) {
				result = "0" + result;
			}
		} else if(result.length() < 4 && result.length() > 2 && result.length() % 4 != 0) {
			while(result.length() % 4 != 0) {
				result = "0" + result;
			}
		} else if(result.length() < 8 && result.length() > 4 && result.length() % 8 != 0) {
			while(result.length() % 8 != 0) {
				result = "0" + result;
			}
		} else if(result.length() < 16 && result.length() > 8 && result.length() % 16 != 0) {
			while(result.length() % 16 != 0) {
				result = "0" + result;
			}
		} else if(result.length() < 24 && result.length() > 16 && result.length() % 24 != 0) {
			while(result.length() % 24 != 0) {
				result = "0" + result;
			}
		} else if(result.length() < 32 && result.length() > 24 && result.length() % 32 != 0) {
			while(result.length() % 32 != 0) {
				result = "0" + result;
			}
		} else if(result.length() < 48 && result.length() > 32 && result.length() % 48 != 0) {
			while(result.length() % 48 != 0) {
				result = "0" + result;
			}
		} else if(result.length() < 64 && result.length() > 48 && result.length() % 64 != 0) {
			while(result.length() % 64 != 0) {
				result = "0" + result;
			}
		} else if(result.length() < 96 && result.length() > 64 && result.length() % 96 != 0) {
			while(result.length() % 96 != 0) {
				result = "0" + result;
			}
		} else if(result.length() < 128 && result.length() > 96 && result.length() % 128 != 0) {
			while(result.length() % 128 != 0) {
				result = "0" + result;
			}
		}
		return result;
	}
	
	public BigIntegerz xor(BigInteger val) {
		return new BigIntegerz(super.xor(val));
	}
}
