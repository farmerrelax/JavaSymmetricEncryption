package cc.jce.smile.se.mkv;

public enum MKVType {
	MKV_128(16), 
	MKV_256(32),
	;
	
	int block;
	MKVType(int block) {
		this.block = block;
	}
}

