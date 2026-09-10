package cc.jce.smile.se.mkv;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Before;
import org.junit.Test;

import cc.jce.smile.Utilities;

public class MKVEncryptionTest {
	
	MKVEncryption mkve128;
	MKVEncryption mkve256;
	
	private String[] inputKey128 = { 
			"0102030405060708090A0B0C0D0E0F11",
			"0102030405060708090A0B0C0D0E0F111213141516171819",
			"0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2223",
	};
	
	private String[][] outputKey128 = {
			{	"0102030405060708090a0b0c0d0e0f11",
				"0d96e3d196326ac68315ef293437ab0a",
				"056f4b9a9533ca5b6ddc9b6a7ece62a7",
				"d626ad4628c71bb914e5a95b4b6440e1",
				"bbbe38effae90380b8b89eb00ab59342",
				"6cb17b9e1f7cc4af123b73d3e43613cf",
				"aebf06ac43f1151ea1f4e527db9969fd",
				"1a6d2563a632390294d0c623616ba9cc",
				"b9e540fcf10f0de0cff7d7020d64df79",
				"3e45290ef047e0b7c2c06d4856fb7674",
				"ba7f689f5612f6c4499827ab9a63fe29",
				"2b4dfa6128cc1d7ea8ba0ce2fedcf7ae",
				"5b40a6bf1250b1e89a894f39f4f45b9d",
				"106c2567a743ee1e9e320fbdbdeb474e",
				"f583771b15edd47667b60729e48132c4",
			},
			{

				"0102030405060708090a0b0c0d0e0f11",
				"7b3a4e097ba0dc30de75fe233f0775e3",
				"73c3e64278a17cad30bc8a6075febc4e",
				"7696766bf7d5b7ce8efb2d0cf584712a",
				"a0ad2da4b6eaeb644263338828396ba4",
				"5009d3c24b0bb1000a4cd284de148466",
				"1d2013f8e0b2ad3b8b72da16edeefe1f",
				"de800aa5d31288224ea8c8319b4c7b4d",
				"04520d51101c4f0928585048651b9986",
				"126cb63953b2b48e250715c1a634a9a1",
				"87c186c2c266357c7adeb499de97b10d",
				"6b70a745f9177b7e9989ccc76bd8ef23",
				"b07c4c8209cae70f6588d89b522cb44d",
				"7e71ebb8da067cb0f937f8917ab58bf8",
				"8aea8ba10e51226e2db465a1485bd1f8",
				"435eb3b12bb2d3d796c49b0670021710",
				"dc62d1c1ab6a3a36d9a249eb5ac7d0af",
			},
			{
				"0102030405060708090a0b0c0d0e0f11",
				"1e5ef1988ba629b74d70aa1bd7cdcfde",
				"16a759d388a7892aa3b9de589d340673",
				"47b9ae3a79d632269d71cc3056c715c7",
				"5ee7eda3890a36c18e0cb34381defa91",
				"931cbcaf6866cdbe5bccc76415bc9589",
				"cd7d1dad6d24980a146b6309824a165b",
				"6d711fe39b9ae849c92eeae5c1eb3262",
				"d72f9ff32a5f63da4b2fc7244da849b0",
				"4fd5b7171ad68202d5eb1395927504e1",
				"fdd6e393b072059c16af32e51292f507",
				"24b9a90a33155725944eb625ad550e42",
				"7e0b4a70998d2530667531ad0f68c72f",
				"b00ae0dd45be535d4ad6e4f3bcd14836",
				"47d3b982120cabeabac09c68a221559c",
				"9f1d7c455bec4a1461026bbdbbd7e66b",
				"917360dd13664e1f9b42d3038b9dff81",
				"0e81dd04b049b5a7cb6eb18868d1a8bb",
				"8e4bdbc03419454643c4807d780de121",
			},
	};
	
	private String[] inputKey256 = { 
		"0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2223",
		"0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F22230102030405060708090A0B0C0D0E0F11",
		"0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F22230102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2223",
	};
	
	private String[][] outputKey256 = {
		{
			"0102030405060708090a0b0c0d0e0f1112131415161718191a1b1c1d1e1f2223",
			"76368c1bc3ddc4f2bcf2a54a3c85118a97d64bb3cf850b8515981001ca34b469",
			"f32be9c6475d22b2abe501737966f40b002f89ccb4dca01a1cb7f556c57c71b0",
			"0c80ce24ab11d29c98c111711f2cbe1a28dac73f740672043954d9c85cd9b195",
			"3ef30a853f19cda61bda23fecf5d7580f954305623ca4514a669d1f27509881c",
			"89bd87e8f6aa9f7a29d0d39505510fddd35bd355094250154add5d348575ec82",
			"f84b92dd2cb4b952d036b5906df690fbd01fcbcd24871df6e021d5a70f43ad30",
			"af50d62b5d2dfd0580a20b34f6573f85978a8367d0ecd62c4d447b39fa984c86",
			"8ffa10e8fbb876119c943352cb28c29eccca0f1183d8c2d48cb4e240a74d6c0d",
			"ed6736e666cf9a4b730832133114d2c18997e45cb31d3880cf8fd7d0d96de0a5",
			"f491bbb533f98ded821e128baa65ade0d075b3269d7119eaf24ddea519d8b0ae",
			"c6a15e895edd3a088e0352ecd36606038e34c5219b93cf45012b9c7e9cee241e",
			"0604fb69603202363d4deaec1e7da30cb865e2557a210ef064ed3eca3cfc65c3",
			"497c8a2e5087fa49bc78ce3906573cf91f43ba972f63681c59e541f57e5aa13e",
			"f3986bb445f72306ccc56c070aebadd0b884e0d178226f6f0c228a8f2a31afde",

		},
		{
			"0102030405060708090a0b0c0d0e0f1112131415161718191a1b1c1d1e1f2223",
			"35f234e762094bef7f90057ba12e56db20433885f9b4ad6f4c21be29ef6f297d",
			"b0ef513ae689adaf6887a142e4cdb35ab7bafafa82ed06f0450e5b7ee027eca4",
			"2c4c07a264be2819a215173cf2ce25e75089327a607ce3fb2a0abaaaac3d3bdc",
			"a0b4380abd7e8aeecb1b822e89f5a29e2c120e5d73846e855425ac84617f4e11",
			"5a0b2120d46402b490f893e0dfb9c510ca5dd633e336bf798292cc653f96ad40",
			"072c7ac69a1e9f1f060a5104ee5f6b92fc3ff8df0a2e895a8cfd616b8be38dd5",
			"e95745d944897593ccd2a65a38ce7e717475cde189a2b24b253ddc387baf2955",
			"440362c7663017e46bc67a10f0ae315a42555efba21ed097eab6a18bb97dbd41",
			"91d39f3ea84c23ea105a504b3a99542d5221a1478562401a75c4d374c615a2c9",
			"1f99b21a7e4e43de1eb130a4764c1d57b62d2a5c4e4549ca8fc1138993ad0052",
			"30b1180c9fb294b5011cbbb5725847afc90efa5a1c13a52ae3998a369ef0b31a",
			"44176bbc496077bffb06ffebdca009c85cbe4fe3478982430f13fec2d8baf0fd",
			"71b03957a4c3fc8e51a59be7572aa8ba004bec9eb81588496c270fc7e7a96f8f",
			"33daa26c488f2c679f520a4abe8d86ab7cb1237403703c5b5338c97ebe42f97f",
			"5c66e0c4a9bb98caa44b47c746a78166ec2684f2e6071c9ca124345ef18f74c3",
			"fe553a5597f8fe21efb8aca3c02031a80646e1eb9f1b845cb9f4dbd18717ebe6",

		},
		{
			"0102030405060708090a0b0c0d0e0f1112131415161718191a1b1c1d1e1f2223",
			"0dfa1afcf24d9ea6b8474cef0ce50882b04e558844923e7aa7345c12635f0fda",
			"88e77f2176cd78e6af50e8d64906ed0327b797f73fcb95e5ae1bb9456c17ca03",
			"fadf391182528bda63d44334982f1c8f1662cbd79c2e80604988d1eac0883849",
			"82f06ba656b8e8bfbd4872135b02fcba87220a3d363de740f0479a7995945a84",
			"25836b891df51dd69e785dd16f94755d6c218481e5bbd08f198171c762dcde7f",
			"af71c99cad941146323bc475f55f60dfbb0f3e64bd2cc2c30ebdbddf04903c15",
			"3cef690af2854ab37a3dc5555fd46d2f5f0317e4cca38f3430b422f765069b41",
			"0193618b0f9951a56f606764733ff303e7782e20ab39386fe69ec472b8518398",
			"7f1bf79313c8d09acbb887d89f7e089a5bd630c3ae236155c7b085bd647aac3a",
			"1e1efea70626c728c704c66a16093572cf3a0dfed543e93df76da4860c77d161",
			"14c16e06f4b2201e95c46cc5109fd24f59b1a0afb2f9151196ec27ecb80f1309",
			"bc10eb16e662d7d75b9d7558ad3512b898e08432289b258cced26e04e85a9cf4",
			"5357bb918766ee5dd44eb514c5a982031fea67afb2bfe9b005f07f9e0cdce853",
			"c47b3abd145394edf720ad2b74636f1f8033c7d5b59a0b1394280d4bfc871f82",
			"2ca2c80d745dbf608d6a1c0b50b978498718fcfa35a128301e94dfdef182eedc",
			"780c0c2578e27fe79523dfd66cc414da21a81fb050a370c9e4f2e4364de3d644",
			"4065b8f3bed79dff8c0d93569ef656caa83827c830ce833d8e555eb94091ed5a",
			"0c68d3aba85abffe963df919fe0cd02b1976f16b73d80726077a000ddd5d6492",

		},
	};
	
	private String[] inputEncrypt128 = { 
		"112233445566778899aabbccddeeff00",
		"112233445566778899aabbccddeeff00",
		"112233445566778899aabbccddeeff00",
	};
	
	private String[] outputEncrypt128 = { 
		"1cc614ed63924a0f171a5aa4c9c2b120",
		"a134c786f6e77485433b2d7caafd7a97",
		"8a6f9bbc745bfee7005f04054dd1ff8e",
	};
	
	private String[] inputEncrypt256 = { 
			"112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
			"112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
			"112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
	};
		
	private String[] outputEncrypt256 = { 
			"3e6359590dc566d8e79629607d5872a6a7c9adf74bf0d2df00eaf76ff7c129c3",
			"515d487a2cc34d8a68beff4371be4df4aaf458b4ab540f394f72747bd9d9dfdb",
			"5e6fd5f88b7924e0e24f070c8e3f3fbc264350bf06a169f55167c51521b7cfa4",
	};
	
	@Before
	public void before() {
		mkve128 = new MKVEncryption(MKVType.MKV_128);
		mkve256 = new MKVEncryption(MKVType.MKV_256);
	}
	
	@Test
	public void testInitKey() {
		for(int i = 0; i < inputKey128.length; i++) {
			byte[] masterKey = Utilities.convertHexStringBytes(inputKey128[i]);
			String[] roundKeys = outputKey128[i];
			char[][] results = mkve128.initKey(masterKey);
			for(int j = 0; j < roundKeys.length; j++) {
				char[] roundKey = Utilities.convertHexStringToHexBytes(outputKey128[i][j]);
				assertArrayEquals(roundKey, results[j]);
			}
		}
		
		for(int i = 0; i < inputKey256.length; i++) {
			byte[] masterKey = Utilities.convertHexStringBytes(inputKey256[i]);
			String[] roundKeys = outputKey256[i];
			char[][] results = mkve256.initKey(masterKey);
			for(int j = 0; j < roundKeys.length; j++) {
				char[] roundKey = Utilities.convertHexStringToHexBytes(outputKey256[i][j]);
				assertArrayEquals(roundKey, results[j]);
			}
		}
	}
	
	@Test
	public void testEncrypt() {
		for(int i = 0; i < inputEncrypt128.length; i++) {
			byte[] masterKey = Utilities.convertHexStringBytes(inputKey128[i]);
			mkve128.initKey(masterKey);
			byte[] plainBytes = Utilities.convertHexStringBytes(inputEncrypt128[i]);
			byte[] result = mkve128.encrypt(plainBytes);
			byte[] output = Utilities.convertHexStringBytes(outputEncrypt128[i]);
			assertArrayEquals(result, output);
		}
		
		for(int i = 0; i < inputEncrypt256.length; i++) {
			byte[] masterKey = Utilities.convertHexStringBytes(inputKey256[i]);
			mkve256.initKey(masterKey);
			byte[] plainBytes = Utilities.convertHexStringBytes(inputEncrypt256[i]);
			byte[] result = mkve256.encrypt(plainBytes);
			byte[] output = Utilities.convertHexStringBytes(outputEncrypt256[i]);
			assertArrayEquals(result, output);
		}
	}
	
	@Test
	public void testDecrypt() {
		for(int i = 0; i < inputEncrypt128.length; i++) {
			byte[] masterKey = Utilities.convertHexStringBytes(inputKey128[i]);
			mkve128.initKey(masterKey);
			byte[] encryptBytes = Utilities.convertHexStringBytes(outputEncrypt128[i]);
			byte[] result = mkve128.decrypt(encryptBytes);
			byte[] output = Utilities.convertHexStringBytes(inputEncrypt128[i]);
			assertArrayEquals(result, output);
		}
		
		for(int i = 0; i < inputEncrypt256.length; i++) {
			byte[] masterKey = Utilities.convertHexStringBytes(inputKey256[i]);
			mkve256.initKey(masterKey);
			byte[] encryptBytes = Utilities.convertHexStringBytes(outputEncrypt256[i]);
			byte[] result = mkve256.decrypt(encryptBytes);
			byte[] output = Utilities.convertHexStringBytes(inputEncrypt256[i]);
			assertArrayEquals(result, output);
		}
	}
}

