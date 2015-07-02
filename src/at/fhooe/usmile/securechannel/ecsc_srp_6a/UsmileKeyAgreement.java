package at.fhooe.usmile.securechannel.ecsc_srp_6a;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

import com.nxp.id.jcopx.ECPoint;
import com.nxp.id.jcopx.ECPointBuilder;
import com.nxp.id.jcopx.KeyAgreementX;

public class UsmileKeyAgreement {

	/**
	 * size of the SRP modulus
	 */
	private final static short LENGTH_MODULUS = (short) 0x18;
	private final static short OUTPUT_OFFSET_REDP = (short) 0x100;
	private final static short OUTPUT_OFFSET_1 = (short) 0x140;
	private final static short OUTPUT_OFFSET_2 = (short) 0x180;

	private MessageDigest msgDigest_SHA256;
	private final static short LENGTH_MESSAGE_DIGEST = 0x20;

	private static final short LENGTH_PADDING_FOR_SQUARE_MULT = 20;
	private static final short LENGTH_SQUARE_MULT_MODULUS = 64;
	
	private final static short LENGTH_IV = (short) 0x10;
	private final static short OFFSET_IV = (short) 0x20;
	private RandomData rng;

	private Cipher rsaCipher;
//	 private RSAPublicKey rsaPublicKey;
	private RSAPublicKey rsaPublicKey_forSquareMul;
	private RSAPublicKey rsaPublicKey_forModPow;

	// Elliptic Curve
//	ECPrivateKey ecPrivate;
//	ECPublicKey ecPublic;

	private ECPoint ecPublic;
	private ECPrivateKey ecPrivate;

	byte[] tempBuffer;
	private short vPilen;
	private static byte[] kv;
	private static byte[] v_Pi;
	private static byte[] salt;
	// a temporary storage for public parameter of the card
	private static byte[] B;

	private static final short OFFSET_u = 0x300;
	private static final short OFFSET_b = 0x320;
//	static final byte g = 0x02;
//	private static final byte[] N = new byte[] { (byte) 0xAC, (byte) 0x6B,
//			(byte) 0xDB, (byte) 0x41, (byte) 0x32, (byte) 0x4A, (byte) 0x9A,
//			(byte) 0x9B, (byte) 0xF1, (byte) 0x66, (byte) 0xDE, (byte) 0x5E,
//			(byte) 0x13, (byte) 0x89, (byte) 0x58, (byte) 0x2F, (byte) 0xAF,
//			(byte) 0x72, (byte) 0xB6, (byte) 0x65, (byte) 0x19, (byte) 0x87,
//			(byte) 0xEE, (byte) 0x07, (byte) 0xFC, (byte) 0x31, (byte) 0x92,
//			(byte) 0x94, (byte) 0x3D, (byte) 0xB5, (byte) 0x60, (byte) 0x50,
//			(byte) 0xA3, (byte) 0x73, (byte) 0x29, (byte) 0xCB, (byte) 0xB4,
//			(byte) 0xA0, (byte) 0x99, (byte) 0xED, (byte) 0x81, (byte) 0x93,
//			(byte) 0xE0, (byte) 0x75, (byte) 0x77, (byte) 0x67, (byte) 0xA1,
//			(byte) 0x3D, (byte) 0xD5, (byte) 0x23, (byte) 0x12, (byte) 0xAB,
//			(byte) 0x4B, (byte) 0x03, (byte) 0x31, (byte) 0x0D, (byte) 0xCD,
//			(byte) 0x7F, (byte) 0x48, (byte) 0xA9, (byte) 0xDA, (byte) 0x04,
//			(byte) 0xFD, (byte) 0x50, (byte) 0xE8, (byte) 0x08, (byte) 0x39,
//			(byte) 0x69, (byte) 0xED, (byte) 0xB7, (byte) 0x67, (byte) 0xB0,
//			(byte) 0xCF, (byte) 0x60, (byte) 0x95, (byte) 0x17, (byte) 0x9A,
//			(byte) 0x16, (byte) 0x3A, (byte) 0xB3, (byte) 0x66, (byte) 0x1A,
//			(byte) 0x05, (byte) 0xFB, (byte) 0xD5, (byte) 0xFA, (byte) 0xAA,
//			(byte) 0xE8, (byte) 0x29, (byte) 0x18, (byte) 0xA9, (byte) 0x96,
//			(byte) 0x2F, (byte) 0x0B, (byte) 0x93, (byte) 0xB8, (byte) 0x55,
//			(byte) 0xF9, (byte) 0x79, (byte) 0x93, (byte) 0xEC, (byte) 0x97,
//			(byte) 0x5E, (byte) 0xEA, (byte) 0xA8, (byte) 0x0D, (byte) 0x74,
//			(byte) 0x0A, (byte) 0xDB, (byte) 0xF4, (byte) 0xFF, (byte) 0x74,
//			(byte) 0x73, (byte) 0x59, (byte) 0xD0, (byte) 0x41, (byte) 0xD5,
//			(byte) 0xC3, (byte) 0x3E, (byte) 0xA7, (byte) 0x1D, (byte) 0x28,
//			(byte) 0x1E, (byte) 0x44, (byte) 0x6B, (byte) 0x14, (byte) 0x77,
//			(byte) 0x3B, (byte) 0xCA, (byte) 0x97, (byte) 0xB4, (byte) 0x3A,
//			(byte) 0x23, (byte) 0xFB, (byte) 0x80, (byte) 0x16, (byte) 0x76,
//			(byte) 0xBD, (byte) 0x20, (byte) 0x7A, (byte) 0x43, (byte) 0x6C,
//			(byte) 0x64, (byte) 0x81, (byte) 0xF1, (byte) 0xD2, (byte) 0xB9,
//			(byte) 0x07, (byte) 0x87, (byte) 0x17, (byte) 0x46, (byte) 0x1A,
//			(byte) 0x5B, (byte) 0x9D, (byte) 0x32, (byte) 0xE6, (byte) 0x88,
//			(byte) 0xF8, (byte) 0x77, (byte) 0x48, (byte) 0x54, (byte) 0x45,
//			(byte) 0x23, (byte) 0xB5, (byte) 0x24, (byte) 0xB0, (byte) 0xD5,
//			(byte) 0x7D, (byte) 0x5E, (byte) 0xA7, (byte) 0x7A, (byte) 0x27,
//			(byte) 0x75, (byte) 0xD2, (byte) 0xEC, (byte) 0xFA, (byte) 0x03,
//			(byte) 0x2C, (byte) 0xFB, (byte) 0xDB, (byte) 0xF5, (byte) 0x2F,
//			(byte) 0xB3, (byte) 0x78, (byte) 0x61, (byte) 0x60, (byte) 0x27,
//			(byte) 0x90, (byte) 0x04, (byte) 0xE5, (byte) 0x7A, (byte) 0xE6,
//			(byte) 0xAF, (byte) 0x87, (byte) 0x4E, (byte) 0x73, (byte) 0x03,
//			(byte) 0xCE, (byte) 0x53, (byte) 0x29, (byte) 0x9C, (byte) 0xCC,
//			(byte) 0x04, (byte) 0x1C, (byte) 0x7B, (byte) 0xC3, (byte) 0x08,
//			(byte) 0xD8, (byte) 0x2A, (byte) 0x56, (byte) 0x98, (byte) 0xF3,
//			(byte) 0xA8, (byte) 0xD0, (byte) 0xC3, (byte) 0x82, (byte) 0x71,
//			(byte) 0xAE, (byte) 0x35, (byte) 0xF8, (byte) 0xE9, (byte) 0xDB,
//			(byte) 0xFB, (byte) 0xB6, (byte) 0x94, (byte) 0xB5, (byte) 0xC8,
//			(byte) 0x03, (byte) 0xD8, (byte) 0x9F, (byte) 0x7A, (byte) 0xE4,
//			(byte) 0x35, (byte) 0xDE, (byte) 0x23, (byte) 0x6D, (byte) 0x52,
//			(byte) 0x5F, (byte) 0x54, (byte) 0x75, (byte) 0x9B, (byte) 0x65,
//			(byte) 0xE3, (byte) 0x72, (byte) 0xFC, (byte) 0xD6, (byte) 0x8E,
//			(byte) 0xF2, (byte) 0x0F, (byte) 0xA7, (byte) 0x11, (byte) 0x1F,
//			(byte) 0x9E, (byte) 0x4A, (byte) 0xFF, (byte) 0x73 };

	final static byte[] SecP192r1_P = { // 24
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFE,(byte) 0xFF,(byte) 0xFF,
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF };
	final static byte[] SecP192r1_A = { // 24
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFE,(byte) 0xFF,(byte) 0xFF,
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFC };
	final static byte[] SecP192r1_B = { // 24
		(byte) 0x64,(byte) 0x21,(byte) 0x05,(byte) 0x19,(byte) 0xE5,(byte) 0x9C,
		(byte) 0x80,(byte) 0xE7,(byte) 0x0F,(byte) 0xA7,(byte) 0xE9,(byte) 0xAB,
		(byte) 0x72,(byte) 0x24,(byte) 0x30,(byte) 0x49,(byte) 0xFE,(byte) 0xB8,
		(byte) 0xDE,(byte) 0xEC,(byte) 0xC1,(byte) 0x46,(byte) 0xB9,(byte) 0xB1 };
	final static byte[] SecP192r1_S = { // 20
		(byte) 0x30,(byte) 0x45,(byte) 0xAE,(byte) 0x6F,(byte) 0xC8,(byte) 0x42,
		(byte) 0x2F,(byte) 0x64,(byte) 0xED,(byte) 0x57,(byte) 0x95,(byte) 0x28,
		(byte) 0xD3,(byte) 0x81,(byte) 0x20,(byte) 0xEA,(byte) 0xE1,(byte) 0x21,
		(byte) 0x96,(byte) 0xD5 };
//	final static byte[] SecP192r1_G = { // 25
//	(byte) 0x12, (byte) 0x10, (byte) 0xFF, (byte) 0x82, (byte) 0xFD,
//			(byte) 0x0A, (byte) 0xFF, (byte) 0xF4, (byte) 0x00, (byte) 0x88,
//			(byte) 0xA1, (byte) 0x43, (byte) 0xEB, (byte) 0x20, (byte) 0xBF,
//			(byte) 0x7C, (byte) 0xF6, (byte) 0x90, (byte) 0x30, (byte) 0xB0,
//			(byte) 0x0E, (byte) 0xA8, (byte) 0x8D, (byte) 0x18, (byte) 0x03 };
	final static byte[] SecP192r1_G = { // 49
		(byte) 0x04,(byte) 0x18,(byte) 0x8D,(byte) 0xA8,(byte) 0x0E,(byte) 0xB0,
		(byte) 0x30,(byte) 0x90,(byte) 0xF6,(byte) 0x7C,(byte) 0xBF,(byte) 0x20,
		(byte) 0xEB,(byte) 0x43,(byte) 0xA1,(byte) 0x88,(byte) 0x00,(byte) 0xF4,
		(byte) 0xFF,(byte) 0x0A,(byte) 0xFD,(byte) 0x82,(byte) 0xFF,(byte) 0x10,
		(byte) 0x12,(byte) 0x07,(byte) 0x19,(byte) 0x2B,(byte) 0x95,(byte) 0xFF,
		(byte) 0xC8,(byte) 0xDA,(byte) 0x78,(byte) 0x63,(byte) 0x10,(byte) 0x11,
		(byte) 0xED,(byte) 0x6B,(byte) 0x24,(byte) 0xCD,(byte) 0xD5,(byte) 0x73,
		(byte) 0xF9,(byte) 0x77,(byte) 0xA1,(byte) 0x1E,(byte) 0x79,(byte) 0x48,
		(byte) 0x11};

	final static byte[] SecP192r1_N = { // 24
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,
		(byte) 0x99,(byte) 0xDE,(byte) 0xF8,(byte) 0x36,(byte) 0x14,(byte) 0x6B,
		(byte) 0xC9,(byte) 0xB1,(byte) 0xB4,(byte) 0xD2,(byte) 0x28,(byte) 0x31 };
	final static byte[] SecP192r1_P_ForRSA = { // 64
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFE,(byte) 0xFF,(byte) 0xFF,
		(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,
		(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,
		(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,
		(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,
		(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,
		(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,
		(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,
		(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00, };
	
	final static short SecP192r1_H = 1;

	final static byte KEYLENGTH = 0x18;
	final static byte POINTLENGTH = KEYLENGTH*2 + 1;
	
	final static short BAS = 0;
	private final static byte LENGTH_SALT = 0x10;

	final static byte[] squareExponent = new byte[] { 0x02 };
	final static byte[] modulosExponent = new byte[] { 0x01 };

	/**
	 * Constructors
	 * 
	 * <p>
	 * Performs necessary initialization and memory allocations
	 * 
	 * @param initBuffer
	 *            initialization byte array buffer, contains identity':'password
	 * 
	 */
	public UsmileKeyAgreement(byte[] initBuffer, short length) {

		tempBuffer = initBuffer;

		/**
		 * init messageDigest
		 */
		msgDigest_SHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256,
				false);
		/**
		 * init random data generator
		 */
		rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

		// rsaPublicKey = (RSAPublicKey) KeyBuilder.buildKey(
		// KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);

		rsaPublicKey_forSquareMul = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		rsaPublicKey_forModPow = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);

		rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

		rsaPublicKey_forSquareMul.setExponent(squareExponent, (short) 0x00,
				(short) 0x01);


		/**
		 * set public key modulus
		 */
		rsaPublicKey_forSquareMul.setModulus(SecP192r1_P_ForRSA, (short) 0x00, (short) 0x40);
		rsaPublicKey_forModPow.setModulus(SecP192r1_P_ForRSA, (short) 0x00, (short) 0x40);
		// rsaPublicKey.setModulus(N, (short) 0x00, LENGTH_MODULUS);

		/**
		 * v and KV are should be computed here from SRP 6a v = g^X X = H (salt,
		 * H(identity':'password)) .... from bouncy castle SRP 6a API K = H(N,
		 * g) ... g.. padded with leading 0s
		 */
		v_Pi = new byte[(short) 0x100];
		kv = new byte[(short) 0x100];
		salt = new byte[(short) 0x10];
		B = new byte[(short) 0x100];

		staticComputations(length);

	}

	/**
	 * Computes/generates Applet side parameters that are static (session
	 * independent) This values are salt, k and kv Called during from the
	 * constructor of this class (at Applet installation) and for changing the
	 * secure channel password and/or user ID
	 */
	public void staticComputations(short length){
		/**
		 * generate salt
		 */
		rng.generateData(salt, (short) 0x00, LENGTH_SALT);

		/**
		 * compute U_Pi = OS2IP(H (salt, H(identity':'password))) mod r
		 */
				
		msgDigest_SHA256.doFinal(tempBuffer, (short) 0x00, length, tempBuffer,
				OUTPUT_OFFSET_2);
		msgDigest_SHA256.update(salt, (short) 0x00, LENGTH_SALT);
		msgDigest_SHA256.doFinal(tempBuffer, OUTPUT_OFFSET_2,
				LENGTH_MESSAGE_DIGEST, tempBuffer, (short) (0x0));

		
		// OS2IP mod N
		Bignat i1 = new Bignat(LENGTH_MESSAGE_DIGEST, false);
		i1.from_byte_array(LENGTH_MESSAGE_DIGEST, (short) 0, tempBuffer, (short)0x0);
		Bignat bn = new Bignat((short)LENGTH_MODULUS, false);
		bn.from_byte_array(LENGTH_MODULUS, (short)0, SecP192r1_N, (short)0);
		
		i1.remainder_divide(bn, null);
//		Util.arrayCopy(i1.as_byte_array(), (short) (LENGTH_MESSAGE_DIGEST-LENGTH_MODULUS), v, (short)0, LENGTH_MODULUS);

		/**
		 * compute v = g^X
		 * TODO change to U_Pi . G
		 */
		vPilen = calculateVPi( v_Pi, (short) (0), i1.as_byte_array(), (short) (LENGTH_MESSAGE_DIGEST-LENGTH_MODULUS), LENGTH_MODULUS);

		
				
		/**
		 * compute K = H(N, g)
		 */
//		msgDigest_SHA256.update(N, (short) 0x00, LENGTH_MODULUS);
//		msgDigest_SHA256.doFinal(tempBuffer, (short) 0x00, LENGTH_MODULUS,
//				tempBuffer, (short) (OUTPUT_OFFSET_2 - 0x20));

		/**
		 * compute KV save copy of V in KV because v and tempBuffer are subject
		 * to change
		 */
//		Util.arrayCopy(v, (short) 0x00, kv, (short) 0x00, LENGTH_MODULUS);
//		modMultiply(v, (short) 0x00, LENGTH_MODULUS, tempBuffer,
//				OUTPUT_OFFSET_1, LENGTH_MODULUS);
//		Util.arrayCopy(kv, (short) 0x00, v, (short) 0x00, LENGTH_MODULUS);
//		Util.arrayCopy(tempBuffer, (short) 0x00, kv, (short) 0x00,
//				vPilen);
	}

	private void initializeECPoint(ECKey ecPoint) {
		ecPoint.setFieldFP(SecP192r1_P, BAS, (short)24);
		ecPoint.setA(SecP192r1_A, BAS, (short)24);
		ecPoint.setB(SecP192r1_B, BAS, (short)24);
		ecPoint.setG(SecP192r1_G, BAS, (short)49);
		ecPoint.setK(SecP192r1_H);
		ecPoint.setR(SecP192r1_N, BAS, (short)24);
	}

	/**
	 * Initializes SRP-6a key agreement
	 * 
	 * @param apdu
	 *            reference for the APDU object used by this Applet
	 * @param incomingBuf
	 *            reference to the APDU buffer that contains the client public
	 *            key A
	 * @return true if key agreement initialization completes successfully.
	 *         false if the client public A is zero
	 */
	public boolean initWithSRP(APDU apdu, byte[] incomingBuf) {

		/**
		 * if incoming public A mod N = 0 abort
		 */
//		Util.arrayCopy(N, (short) 0x00, tempBuffer, OUTPUT_OFFSET_2,
//				LENGTH_MODULUS);
//		if ((Util.arrayCompare(incomingBuf, ISO7816.OFFSET_CDATA, tempBuffer,
//				(short) 0x00, LENGTH_MODULUS) == 0)
//				| (Util.arrayCompare(incomingBuf, ISO7816.OFFSET_CDATA,
//						tempBuffer, OUTPUT_OFFSET_2, LENGTH_MODULUS) == 0)) {
//
//			return false;
//		}

		// apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, LENGTH_MODULUS);

//		/**
//		 * generate SE secret b and compute ... B = kv + g^b
//		 */
//		generateRandom(tempBuffer, OFFSET_b, KEYLENGTH);

//		ECPublicKey pointPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_192, false);
//		ECPrivateKey pointPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, false);
//
//		initializeECPoint(pointPublic);
//		initializeECPoint(pointPrivate);
//		
//		KeyPair keyPair = new KeyPair(pointPublic,pointPrivate);
//		keyPair.genKeyPair();
//		
//		KeyAgreement agreement = KeyAgreementX.getInstance(KeyAgreementX.ALG_EC_SVDP_DH_PLAIN_XY, false);
//		agreement.init(ecPrivate);
//		short vPilen = agreement.generateSecret(incomingBuf, (short) (ISO7816.OFFSET_CDATA), apdu.getIncomingLength(), kv, (byte)0);
		
		

		/**
		 * Generate public/private keys
		 */
		//Initialize public / private key pair
		KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_192);
		initializeECPoint((ECKey)keyPair.getPublic());
		ecPrivate = (ECPrivateKey) keyPair.getPrivate();
		initializeECPoint(ecPrivate);
		//Generate Private/Public key
		keyPair.genKeyPair();

		//Create JCOP API EC Point and copy W into it
		ecPublic = ECPointBuilder.buildECPoint(ECPointBuilder.TYPE_EC_FP_POINT,KeyBuilder.LENGTH_EC_FP_192);
		short lenW = ((ECPublicKey)keyPair.getPublic()).getW(tempBuffer, (short) 0x0);
		initializeECPoint(ecPublic);
		ecPublic.setW(tempBuffer, (short) 0x0, lenW);
		
		/**
		 * compute g^b using rsa public encryption ... b = exponent g = cipher
		 * input tempOutput array should be filled with zero before this method
		 * is invoked
		 */
		// rsaPublicKey.setExponent(tempBuffer, OFFSET_b, LENGTH_KEY);
		// rsaCipher.init(rsaPublicKey, Cipher.MODE_ENCRYPT);
		//
		// tempBuffer[(short) 0xFF] = g;
		//
		// rsaCipher.doFinal(tempBuffer, (short) 0x00, LENGTH_MODULUS,
		// tempBuffer,
		// (short) 0x00);
		//
		// Util.arrayCopy(kv, (short) 0x00, tempBuffer, OUTPUT_OFFSET_1,
		// LENGTH_MODULUS);

		/**
		 * Compute o4 = GE2OSP-X(Vpi)
		 */
		
		
		/**
		 * Q_B = G*d_b + REDP(X(vPi))
		 */

		Util.arrayCopy(v_Pi, (short) 0, tempBuffer, (short) 0, (short) (LENGTH_MODULUS + 1));
		tempBuffer[0] = (byte)0x01;
		
		short redpLength = Redp1(tempBuffer, (short) 0, (short) (LENGTH_MODULUS + 1), tempBuffer, OUTPUT_OFFSET_REDP);
		
//		ECPoint outputE = ECPointBuilder.buildECPoint(ECPointBuilder.TYPE_EC_FP_POINT,KeyBuilder.LENGTH_EC_FP_192);
//		
//		initializeECPoint(outputE);
//		ECKey e;
		
//		outputE.setW(buffer, offset, length);
		
		// TODO

//		ecmultiply(tempBuffer,(short) 0x00, SecP192r1_G,tempBuffer,OFFSET_b,KEYLENGTH);
		
//		boolean carry = add(tempBuffer, (short) 0x00, LENGTH_MODULUS,
//				tempBuffer, OUTPUT_OFFSET_1, LENGTH_MODULUS);
//
//		if (/*
//			 * (tempOutput[(short) 0x00] & 0xff) > (tempOutput[OUTPUT_OFFSET_2]
//			 * & 0xff)|
//			 */carry) {
//			subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
//					OUTPUT_OFFSET_2, LENGTH_MODULUS);
//		}

		/**
		 * compute u = H(A , B) incomingBuf contains A,B from ISO7816.OFFSET_CLA
		 * to 2 * LENGTH_MODULUS
		 */
		/*msgDigest_SHA256.update(incomingBuf, ISO7816.OFFSET_CDATA,
				LENGTH_MODULUS);
		msgDigest_SHA256.doFinal(tempBuffer, (short) 0x00, LENGTH_MODULUS,
				tempBuffer, OFFSET_u);

		// copy B for sending later
		Util.arrayCopy(tempBuffer, (short) 0x00, B, (short) 0x00,
				LENGTH_MODULUS);
*/
		/**
		 * compute v^u
		 */
		// rsaPublicKey.setExponent(tempBuffer, OFFSET_u,
		// LENGTH_MESSAGE_DIGEST);
		// rsaCipher.init(rsaPublicKey, Cipher.MODE_ENCRYPT);
		//
		// Util.arrayCopy(v, (short) 0x00, tempBuffer, OUTPUT_OFFSET_1,
		// LENGTH_MODULUS);
		//
		// rsaCipher.doFinal(tempBuffer, OUTPUT_OFFSET_1, LENGTH_MODULUS,
		// tempBuffer, OUTPUT_OFFSET_1);
		//
		// // multiply with with A ..... A * v^u
		// modMultiply(incomingBuf, ISO7816.OFFSET_CDATA, LENGTH_MODULUS,
		// tempBuffer, OUTPUT_OFFSET_1, LENGTH_MODULUS);
		//
		// // compute S = (A * v^u ) ^b
		//
		// rsaPublicKey.setExponent(tempBuffer, OFFSET_b, LENGTH_KEY);
		// rsaCipher.init(rsaPublicKey, Cipher.MODE_ENCRYPT);
		// rsaCipher.doFinal(tempBuffer, (short) 0x00, LENGTH_MODULUS,
		// tempBuffer,
		// OUTPUT_OFFSET_1);

		/**
		 * compute K = H(S)
		 */
		msgDigest_SHA256.doFinal(tempBuffer, OUTPUT_OFFSET_1, LENGTH_MODULUS,
				tempBuffer, (short) 0x00);

		/**
		 * reset secret value used for key agreement
		 */
		//Util.arrayFillNonAtomic(tempBuffer, OFFSET_b, (short) 0x20, (byte) 0x00);

		/**
		 * compute random point e1
		 */
//		
//		GE2OSPX(tempBuffer,)
		//Temporarily implement GE2OSPX myself
//		incomingBuf[0] = (byte)0x01;
//		Redp
		
		
		/**
		 * send public key W_S = (G*s) + e1
		 */
//		short len = ecPublic.getW(incomingBuf, ISO7816.OFFSET_CLA);
//		apdu.setOutgoingAndSend(ISO7816.OFFSET_CLA, len);
		
			
		Util.arrayCopy(v_Pi, (short) 0, incomingBuf, ISO7816.OFFSET_CLA, (short) 49);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CLA, (short) 49);
//		Util.arrayCopy(tempBuffer, (short) 0, incomingBuf, ISO7816.OFFSET_CLA, (short) redpLength);
//		apdu.setOutgoingAndSend(ISO7816.OFFSET_CLA, (short) redpLength);
		return true;
	}

	public short calculateVPi(byte[] dstbuffer, short offset, byte[] uPiSrc, short uPiOffset, short length) {
		return multiplyGeneratorPoint(dstbuffer, offset, uPiSrc, uPiOffset, length);
	}


	public short Redp1(byte[] oPi, short offset, short length, byte[] pointOutput, short outoffset) {
		byte[] o1 = new byte[LENGTH_MESSAGE_DIGEST];
		msgDigest_SHA256.doFinal(oPi, offset, length,
				o1, (short) 0x00);
		
		
		// OS2IP mod N
		Bignat i1 = new Bignat(LENGTH_MESSAGE_DIGEST, false);
		i1.from_byte_array(LENGTH_MESSAGE_DIGEST, (short) 0, o1, (short)0x0);
		Bignat bn = new Bignat((short)LENGTH_MODULUS, false);
		bn.from_byte_array(LENGTH_MODULUS, (short)0, SecP192r1_P, (short)0);
		
//		i1.remainder_divide(bn, null);

		short outputLen = computeRandomPoint(i1.as_byte_array(),(byte)(0),
				i1.length(),pointOutput,outoffset,(byte)0);

//		short outputLen = (short) LENGTH_MESSAGE_DIGEST;
//		Util.arrayCopy(i1.as_byte_array(), (short)0, pointOutput, outoffset, outputLen);
		return outputLen;
	}

	private byte[] getPadded(byte[] n, short offset, short arrayLength, short newlength) {
		byte[] bs = n;
		if (arrayLength < newlength) {
			byte[] tmp = new byte[newlength];
			Util.arrayCopy(bs, offset, tmp, (short)(newlength - arrayLength), (short) arrayLength);
			bs = tmp;
		}
		return bs;
	}
	
/*
	public static ECFieldElement I2FEP(ECParameterSpec _ecspec, BigInteger _i){
		ECFieldElement output = null;
		
		if(_ecspec.getCurve() instanceof AbstractF2m){
			//TODO
		} else{
			output = _ecspec.getCurve().fromBigInteger(_i);
		}
		
		return output;
	}*/
	private short computeRandomPoint(byte[] i1, short i1offset,short i1length, byte[] outarray,  short offset, byte counter) {
		byte[] o2 = getPadded(i1,i1offset,i1length, LENGTH_MESSAGE_DIGEST);
		byte[] o3 = new byte[LENGTH_MESSAGE_DIGEST];
		msgDigest_SHA256.doFinal(o2, (short) 0, LENGTH_MESSAGE_DIGEST,
				o3, (short) 0x00);

		// x = I2FEP (OS2IP(o3) mod q)
		Bignat x = new Bignat(LENGTH_MESSAGE_DIGEST, false);
		x.from_byte_array(LENGTH_MESSAGE_DIGEST, (short) 0, o3, (short)0x0);
		Bignat xmodq = new Bignat(LENGTH_MODULUS, false);
		Bignat q = new Bignat((short)LENGTH_MODULUS, false);
		q.from_byte_array(LENGTH_MODULUS, (short)0, SecP192r1_P, (short)0);
		
		x.remainder_divide(q, null);
		
		Util.arrayFillNonAtomic(outarray, (short) (offset), (short) LENGTH_SQUARE_MULT_MODULUS, (byte) 0 );

//		Util.arrayCopy(x.as_byte_array(), (short)0, outarray, offset, LENGTH_MESSAGE_DIGEST);
//		Util.arrayCopy(o2, (short)0, outarray, (short) (offset+LENGTH_MESSAGE_DIGEST), (short) o2.length);
//		Util.arrayCopy(x.as_byte_array(), (short)0, outarray, (short)(offset), LENGTH_MESSAGE_DIGEST);
		
//		BigInteger q = ecSpec.getCurve().getField().getCharacteristic();
//		ECFieldElement x = I2FEP(ecSpec, OS2IP(o3).mod(q));
//		ECFieldElement y = null;
		
		short outputElength = 0;
		
		if (!Bignat.valueOf(LENGTH_MODULUS, (byte)0).same_value(x)){
			byte mu = (byte) (i1[(byte)(i1.length-1)] & 0x01);
			
//			if(ECAlgorithms.isF2mCurve(ecSpec.getCurve())){ 
//				//TODO				
//			} else if(ECAlgorithms.isFpCurve(ecSpec.getCurve())) { 
//				BigInteger p = ecSpec.getCurve().getField().getCharacteristic();
			
				if (Bignat.valueOf(LENGTH_MODULUS, (byte)3).same_value(q)){
					// TODO
				} else { //TODO if (BigInteger.valueOf(3).compareTo(p) == -1){
					short length; 
					//p is greater than 3

//					outputElength = (short) x.length();
					
		    		
		    		try{
			    		/**
			    		 * compute x^2
			    		 */
		    			// TODO very slow, can it be improved? Maybe using EC co-processor?
		    			rsaCipher.init(rsaPublicKey_forSquareMul, Cipher.MODE_ENCRYPT);
		    			// Fill temporary buffer of size SQUARE_MULTIPLICATION_MODULUS with zeros
		    			Util.arrayFillNonAtomic(tempBuffer, (short) (0), (short) LENGTH_SQUARE_MULT_MODULUS, (byte) 0 );
		    			// Put padding before and after x (e.g. [20 B] | x | [20 B])
		    			Util.arrayCopy(x.as_byte_array(), (short) (x.length() - LENGTH_MODULUS), tempBuffer, 
		    					(byte) (LENGTH_PADDING_FOR_SQUARE_MULT), 
		    					LENGTH_MODULUS );
//		    			Util.arrayCopy(tempBuffer, (short)0, outarray, (short)(offset), LENGTH_SQUARE_MULT_MODULUS);
		    			length = rsaCipher.doFinal(tempBuffer, (short) 0, (short) (LENGTH_SQUARE_MULT_MODULUS), tempBuffer, (short) 0);
//		    			Util.arrayCopy(tempBuffer, (short)0, outarray, (short)(offset), LENGTH_SQUARE_MULT_MODULUS);
//		    			
//		    			outarray[offset] = tempBuffer[0];
		    			/*
		    			Util.arrayFillNonAtomic(tempBuffer, (short) 0, (short) 64, (byte) 0 );
		    			Util.arrayCopy(x.as_byte_array(), (short) 0, tempBuffer, (byte) (64 - x.length()), x.length() );
		    			length = rsaCipher.doFinal(tempBuffer, (short) 0, (short) 64, tempBuffer, (short) 0);

		    			Bignat x2 = new Bignat((short)64, false);
		    			x2.from_byte_array((short)64, (short) 0, tempBuffer, (short)0x0);
		    			x2.remainder_divide(q, null);
		    			Util.arrayCopy(x2.as_byte_array(), (short) 32, outarray, (byte) offset, (short) 32 );
		    			*/
//		    			Util.arrayFillNonAtomic(outarray, (short) (offset), (short) LENGTH_SQUARE_MULT_MODULUS, (byte) 0 );
//		    			Util.arrayCopy(x.as_byte_array(), (short)0, outarray, (short)(offset+ LENGTH_MESSAGE_DIGEST), x.length());

			    		/**
			    		 * add A
			    		 */
//		    			Util.arrayCopy(tempBuffer, (short)0, outarray, (short)(offset), LENGTH_MODULUS);
			    		
		    			if(add(tempBuffer, (short)0, LENGTH_MODULUS, SecP192r1_A, (short)0, (short) SecP192r1_A.length)){
			    			subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, SecP192r1_P_ForRSA,
			    					(short) 0, LENGTH_MODULUS);
			    			outarray[LENGTH_SQUARE_MULT_MODULUS-1] = 0x01;
			    		}
//			    		Util.arrayCopy(tempBuffer, (short)0, outarray, offset, LENGTH_MODULUS);
			    		
						/**
			    		 * (x^2 + A) * x
			    		 */
			    		Util.arrayCopy(tempBuffer, (short) 0, tempBuffer, 
		    					(byte) (LENGTH_PADDING_FOR_SQUARE_MULT), LENGTH_MODULUS );

			    		Util.arrayFillNonAtomic(tempBuffer, (short) (0), 
		    					(short) LENGTH_PADDING_FOR_SQUARE_MULT, (byte) 0 );
			    		Util.arrayFillNonAtomic(tempBuffer, (short) (LENGTH_PADDING_FOR_SQUARE_MULT + LENGTH_MODULUS), 
		    					(short) LENGTH_PADDING_FOR_SQUARE_MULT, (byte) 0 );
			    		
			    		Util.arrayFillNonAtomic(tempBuffer, (short) (LENGTH_SQUARE_MULT_MODULUS), 
		    					(short) LENGTH_PADDING_FOR_SQUARE_MULT, (byte) 0 );
			    		
			    		// copy x after the current temporary buffer location
		    			Util.arrayCopy(x.as_byte_array(), (short) (x.length() - LENGTH_MODULUS), tempBuffer, 
		    					(byte) (LENGTH_SQUARE_MULT_MODULUS+LENGTH_PADDING_FOR_SQUARE_MULT), LENGTH_MODULUS );
		    			
//			    		
		    			// Multiply current value (x^2 + A) with x
			    		modMultiply(tempBuffer, (short)0, (short) (LENGTH_SQUARE_MULT_MODULUS), 
			    				tempBuffer, 
			    				(short) (LENGTH_SQUARE_MULT_MODULUS),LENGTH_SQUARE_MULT_MODULUS, outarray, offset);
		    			
			    		
			    		/**
			    		 * (x^2 + A) * x + b
			    		 */
			    		if(add(tempBuffer, (short)0, LENGTH_MODULUS, SecP192r1_B, (short)0, (short) SecP192r1_B.length)){
			    			subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, SecP192r1_P_ForRSA,
			    					(short) 0, LENGTH_MODULUS);
			    		}
//
//						Util.arrayCopy(tempBuffer, (short)0, outarray, offset, LENGTH_MODULUS);
//			    		Bignat alpha = new Bignat(LENGTH_MODULUS, false);
//			    		alpha.from_byte_array(length, (short)0, tempBuffer, (short)0);
//			    		
			    		// Copy alpha to buffer
			    		Util.arrayCopy(tempBuffer, (short) (0), tempBuffer, 
		    					(byte) (LENGTH_SQUARE_MULT_MODULUS+LENGTH_PADDING_FOR_SQUARE_MULT), LENGTH_MODULUS );
		    			
//			    		findSquareRoot(tempBuffer, (short)LENGTH_PADDING_FOR_SQUARE_MULT, 
//			    				LENGTH_PADDING_FOR_SQUARE_MULT, q, outarray, (short) 0);
			    		
	//
//			    		length = rsaCipher.doFinal(beta.as_byte_array(), (short) 0, beta.length(), tempBuffer, (short) 0);
//			    		
		    		} catch(CryptoException e){
		    			if (e.getReason() == CryptoException.ILLEGAL_USE){
		    				outarray[offset] = 0x01;
		    			}
		    			else if (e.getReason() == CryptoException.INVALID_INIT){
		    				outarray[offset] = 0x02;
		    			}
		    			else if (e.getReason() == CryptoException.ILLEGAL_VALUE){
		    				outarray[offset] = 0x03;
		    			}
		    			else if (e.getReason() == CryptoException.UNINITIALIZED_KEY){
		    				outarray[offset] = 0x04;
		    			} else {
		    				outarray[offset] = 0x0f;
		    			}
		    		}
//		    		beta.from_byte_array(length, (short) 0, tempBuffer, (short)0); 
//		    		if (beta==null || beta.same_value(alpha) && counter<=5) { //No point found, increase i and go back to o2 generation
//						// No Point found, increase i by one 
//						return computeRandomPoint(i1, (byte) 0, LENGTH_MODULUS, outarray, offset, ++counter);
//					} else {
//						
//						if(mu == 1){
//							q.subtract(beta);
//							// Copy y (q-beta) to output
//							outputElength = q.length();
//							Util.arrayCopy(q.as_byte_array(), (short)0, outarray, offset, outputElength);
//						} else if(mu == 0){
//							// Copy beta to output
//							outputElength = beta.length();
//							Util.arrayCopy(beta.as_byte_array(), (short)0, outarray, offset, outputElength);
//						}
////							ECFieldElement fE = ((SecP192R1Curve)ecSpec.getCurve()).fromBigInteger(x);
////							System.out.println("From X: "+ fE.toString());
////
////							ECPoint outputAlpha = ecSpec.getCurve().createPoint(x, rhs);
////							System.out.println("outputAlpha is point on curve " + outputAlpha.isValid());
//
////						outputE = ecSpec.getCurve().validatePoint(x.toBigInteger(), y.toBigInteger());
//						// TODO T= (x,y)
//						// TODO (e = k x T)
////						if(outputE!=null){
////							outputE=outputE.multiply(ecSpec.getCurve().getCofactor());
////						}
//					}
//				}
					
			}
		}

		return outputElength;
	}
	

	private void findSquareRoot(byte[] alpha, short offset, short length, Bignat p, byte[] out, short outoffset) {
		Bignat helper = new Bignat((short) 1, false);
		helper.setLastByte((byte)3);
		Bignat remainder= new Bignat((short) LENGTH_MODULUS, false);
		
		p.remainder_divide(helper,remainder);
		
		if(remainder.getLastByte() == (byte)4 ){ //p = 4 mod 3
			
//			Bignat.valueOf(LENGTH_MODULUS,(byte)4)
//			
//			BigInteger k1 = p.subtract(Bignat.valueOf(LENGTH_MODULUS,
//					(byte)3)).divide().mod(p);
			Bignat k =new Bignat(LENGTH_MODULUS, false);
			k.copy(p);
			k.add(Bignat.valueOf(LENGTH_MODULUS, (byte)1));
			k.shift_right();
			k.shift_right();
			
//			rsaPublicKey_forModPow.setExponent(k.as_byte_array(), (short) 0, k.length());
//			rsaPublicKey_forModPow.setModulus(SecP192r1_P_ForRSA, (short) 0x00, (short) 0x40);
			
			
//			rsaCipher.init(rsaPublicKey_forModPow, Cipher.MODE_ENCRYPT);
//			
//			rsaCipher.doFinal(alpha, offset, length, out, outoffset);
			
			// TODO implement mod pow
//			beta = alpha.modPow(k,p);
		} else { 
			
			helper.setLastByte((byte)5);
			p.remainder_divide(helper,remainder);
			
			if(remainder.getLastByte() == (byte)5){ // p = 8 mod 5
//				BigInteger k = p.subtract(BigInteger.valueOf(5)).divide(BigInteger.valueOf(8));
//				BigInteger gamma = alpha.multiply(BigInteger.valueOf(2)).modPow(k, p);
//				BigInteger i = alpha.multiply(BigInteger.valueOf(2)).multiply(gamma.pow(2)).mod(p);
//				beta = alpha.multiply(gamma).multiply(i.subtract(ONE)).mod(p);
			} else if(remainder.getLastByte() == (byte)1){
				//TODO
			}
		}
	}
	private short multiplyGeneratorPoint(byte[] pointOutputBuffer, short offset, byte[] multiplier, short mpoffset, short mplength){
//		KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_192);
//		ECPublicKey pointPublic= (ECPublicKey) keyPair.getPublic();
//		ECPrivateKey pointPrivate = (ECPrivateKey) keyPair.getPrivate();
		
		ECPublicKey pointPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_192, false);
		ECPrivateKey pointPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, false);

		initializeECPoint(pointPublic);
		initializeECPoint(pointPrivate);
		
		KeyPair keyPair = new KeyPair(pointPublic,pointPrivate);
		keyPair.genKeyPair();
		
		KeyAgreement agreement = KeyAgreementX.getInstance(KeyAgreementX.ALG_EC_SVDP_DH_PLAIN_XY, false);
//		short len = pointPrivate.getS(tempBuffer, (short) 0x0);
//		tempBuffer[0]=(byte) (tempBuffer[0]&0xEE);
//		multiplier[mpoffset] = tempBuffer[0];
//		Util.arrayFillNonAtomic(multiplier, (short) mpoffset, mplength, (byte)0x0);
//		multiplier[mpoffset+mplength] = (byte)0x2;
		pointPrivate.setS(multiplier, (short) mpoffset, mplength);
		agreement.init(pointPrivate);
//		pointPrivate.
//		return agreement.generateSecret(SecP192r1_G, (byte)0x0, (short)SecP192r1_G.length, pointOutputBuffer, offset);
		short len2 = pointPrivate.getG(tempBuffer, (short) (LENGTH_MODULUS*2+1));
		return agreement.generateSecret(tempBuffer, (short) (LENGTH_MODULUS*2+1), len2, pointOutputBuffer, offset);
//		return 10;

//		KeyPair keyPair = new KeyPair(pointPublic,pointPrivate);
		//Generate Private/Public key
//		keyPair.genKeyPair();
//		pointPrivate.setS(multiplier, mpoffset, mplength);
		
//		return pointPublic.getW(pointOutputBuffer, offset);
	}
	
	private short GE2OSPX(ECPoint ecPoint, byte[] buffer, byte offset){
		short ecPointLength=ecPoint.getW(buffer, (short) (offset+0x01));
		
		buffer[0] = (byte)0x01;
		
		return (short) (ecPointLength+1); 
	}
	
	
	private void ecmultiply(byte[] tempBuffer2, short s, byte[] secp192r1g,
			byte[] tempBuffer3, short offsetB, byte keylength2) {
//		ECPoint
	}

	/**
	 * Retrieves the salt used for the key agreement and random initialization
	 * vector to be used in the secure channel session (secure messaging) method
	 * which gets salt value used and random iv to be used for the following
	 * secure session
	 * 
	 * @param out_salt_iv
	 *            byte array buffer where to put the current salt value and
	 *            random iv
	 * @param outOffset
	 *            offset in outSalt to put current salt value and random iv
	 */
	public short getSalt_and_IV(byte[] out_salt_iv, short outOffset) {
		Util.arrayCopy(salt, (short) 0x00, out_salt_iv, outOffset, LENGTH_SALT);
		generateRandom(tempBuffer, OFFSET_IV, LENGTH_IV);

		Util.arrayCopy(tempBuffer, OFFSET_IV, out_salt_iv,
				(short) (outOffset + LENGTH_SALT), LENGTH_IV);
		return (short) (LENGTH_SALT + LENGTH_IV);
	}

	public short getOutputValue(byte[] outArray, short offset){

		// TODO Remove this, only for debugging
		Util.arrayCopy(tempBuffer, OUTPUT_OFFSET_REDP, outArray,
				(short) offset, LENGTH_SQUARE_MULT_MODULUS);
		return LENGTH_SQUARE_MULT_MODULUS;
	}
	/**
	 * Verifies client authentication data M1 and sends Applet authentication
	 * data M2 using the APDU reference
	 * 
	 * @param apdu
	 *            reference for the APDU object used by this Applet
	 * @param incomingBuf
	 *            reference to the APDU buffer that contains client
	 *            Authentication data M1
	 * @return true if authentication is successful, false otherwise
	 */
	
	public boolean authenticate(APDU apdu, byte[] incomingBuf) {

		Util.arrayCopy(kv, (short) 0, incomingBuf, ISO7816.OFFSET_CLA, (short) 49);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CLA, (short) 49);
		return true;
	}
	/*public boolean authenticate(APDU apdu, byte[] incomingBuf) {
		short M_offset = (short) (LENGTH_MODULUS - (short) 0x20);
		/**
		 * compute expected authentication data M = H(u, S)
		 */
	/*	msgDigest_SHA256.update(tempBuffer, OFFSET_u, LENGTH_MESSAGE_DIGEST);
		msgDigest_SHA256.doFinal(tempBuffer, OUTPUT_OFFSET_1, LENGTH_MODULUS,
				tempBuffer, M_offset);

		/**
		 * compare with incoming Auth data if authenticated compute server ..
		 * (SE ) Authentication Data.... H (u, M, S) from the previous operation
		 * tempoutput contains M, S from offset M_offset - M_offset +
		 * LENGTH_MODULUS
		 */
	/*	if (Util.arrayCompare(incomingBuf, ISO7816.OFFSET_CDATA, tempBuffer,
				M_offset, LENGTH_MESSAGE_DIGEST) == 0) {
			msgDigest_SHA256
					.update(tempBuffer, OFFSET_u, LENGTH_MESSAGE_DIGEST);
			msgDigest_SHA256.doFinal(tempBuffer, M_offset, (short) 0x120,
					incomingBuf, ISO7816.OFFSET_CDATA);

			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 0x20);
			return true;
		}

		return false;
	}*/

	/**
	 * generates secure random byte array
	 * 
	 * @param buffer
	 *            output byte array buffer
	 * @param offset
	 *            offset in the output buffer
	 * @param length
	 *            length of the random data
	 * @return true if random data is generated successfully, false otherwise
	 */
	private boolean generateRandom(byte[] buffer, short offset, short length) {
		try {
			rng.generateData(buffer, offset, length);
			return true;
		} catch (Exception ex) {
			Util.arrayFillNonAtomic(buffer, (short) 0, length, (byte) 0);
			return false;
		}
	}

	/**
	 * returns buffer containing the result of the key agreement
	 * 
	 * @return
	 */
	public byte[] getResult() {
		// TODO Auto-generated method stub
		return tempBuffer;
	}

	/**
	 * Addition of big integer x and y specified by offset and length the result
	 * is saved in x
	 * 
	 * @param x
	 * @param xOffset
	 * @param xLength
	 * @param y
	 * @param yOffset
	 * @param yLength
	 * @return
	 */
	private boolean add(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength) {
		short digit_mask = 0xff;
		short digit_len = 0x08;
		short result = 0;
		short i = (short) (xLength + xOffset - 1);
		short j = (short) (yLength + yOffset - 1);

		for (; i >= xOffset; i--, j--) {
			result = (short) (result + (short) (x[i] & digit_mask) + (short) (y[j] & digit_mask));

			x[i] = (byte) (result & digit_mask);
			result = (short) ((result >> digit_len) & digit_mask);
		}
		while (result > 0 && i >= xOffset) {
			result = (short) (result + (short) (x[i] & digit_mask));
			x[i] = (byte) (result & digit_mask);
			result = (short) ((result >> digit_len) & digit_mask);
			i--;
		}

		return result != 0;
	}

	/**
	 * subtracts big integer y from x specified by offset and length the result
	 * is saved in x
	 * 
	 * @param x
	 * @param xOffset
	 * @param xLength
	 * @param y
	 * @param yOffset
	 * @param yLength
	 * @return
	 */
	private boolean subtract(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength) {
		short digit_mask = 0xff;
		short i = (short) (xLength + xOffset - 1);
		short j = (short) (yLength + yOffset - 1);
		short carry = 0;
		short subtraction_result = 0;

		for (; i >= xOffset && j >= yOffset; i--, j--) {
			subtraction_result = (short) ((x[i] & digit_mask)
					- (y[j] & digit_mask) - carry);
			x[i] = (byte) (subtraction_result & digit_mask);
			carry = (short) (subtraction_result < 0 ? 1 : 0);
		}
		for (; i >= xOffset && carry > 0; i--) {
			if (x[i] != 0)
				carry = 0;
			x[i] -= 1;
		}

		return carry > 0;
	}

	/**
	 * multiplies big integer x and y specified by offset and length The result
	 * is saved in the temporary output buffer (tempOutput) used by this class
	 * 
	 * @param x
	 * @param xOffset
	 * @param xLength
	 * @param y
	 * @param yOffset
	 * @param yLength
	 */
	private void modMultiply(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength, byte[]outarray, short offset) {
		Util.arrayCopy(x, xOffset, tempBuffer, (short) 0x00, xLength);

		/**
		 * x+y
		 */

		Util.arrayCopy(SecP192r1_P_ForRSA, (short) 0x00, tempBuffer, OUTPUT_OFFSET_2,
				LENGTH_SQUARE_MULT_MODULUS);
		Util.arrayCopy(x, (short)xOffset, outarray, offset, xLength);
		if (add(x, (short)LENGTH_PADDING_FOR_SQUARE_MULT, (short)(LENGTH_MODULUS), y,
				(short) (yOffset+LENGTH_PADDING_FOR_SQUARE_MULT), (short)LENGTH_MODULUS)) {
			subtract(x, (short) LENGTH_PADDING_FOR_SQUARE_MULT, (short) (LENGTH_MODULUS), tempBuffer,
					OUTPUT_OFFSET_2, LENGTH_MODULUS);
		} // OK
		
		/**
		 * (x+y)^2
		 */

		rsaCipher.init(rsaPublicKey_forSquareMul, Cipher.MODE_ENCRYPT);
		rsaCipher.doFinal(x, (short) xOffset, LENGTH_SQUARE_MULT_MODULUS, tempBuffer,
				(short) 0); // OK

		/**
		 * compute x^2
		 */
//		Util.arrayCopy(tempBuffer, (short)0, outarray, offset, xLength);
		rsaCipher.doFinal(outarray, offset, LENGTH_SQUARE_MULT_MODULUS, outarray, offset); // OK

		/**
		 * compute (x+y)^2 - x^2
		 */
		if (subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, outarray, offset,
				LENGTH_MODULUS)) {
			add(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
					OUTPUT_OFFSET_2, LENGTH_MODULUS);
		} // OK
//		Util.arrayCopy(tempBuffer, (short)0, outarray, offset, LENGTH_MODULUS);

		/**
		 * compute y^2
		 */
		rsaCipher.doFinal(y, yOffset, yLength, y, yOffset); //OK

		
		/**
		 * compute (x+y)^2 - x^2 - y^2
		 */

		if (subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, y, yOffset,
				LENGTH_MODULUS)) {

			add(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
					OUTPUT_OFFSET_2, LENGTH_MODULUS);

		}

//		Util.arrayCopy(tempBuffer, (short)0, outarray, offset, LENGTH_MODULUS);
		/**
		 * divide by 2
		 */

		modular_division_by_2(tempBuffer, (short) 0x00, LENGTH_MODULUS);

	}

	/**
	 * performs a modular division by 2 The output is of operation is saved in
	 * the input itself
	 * 
	 * @param input
	 * @param inOffset
	 * @param inLength
	 */
	private void modular_division_by_2(byte[] input, short inOffset,
			short inLength) {
		short carry = 0;
		short digit_mask = 0xff;
		short digit_first_bit_mask = 0x80;
		short lastIndex = (short) (inOffset + inLength - 1);

		short i = inOffset;
		if ((byte) (input[lastIndex] & 0x01) != 0) {
			if (add(input, inOffset, inLength, tempBuffer, OUTPUT_OFFSET_2,
					LENGTH_SQUARE_MULT_MODULUS)) {
				carry = digit_first_bit_mask;
			}
		}

		for (; i <= lastIndex; i++) {
			if ((input[i] & 0x01) == 0) {
				input[i] = (byte) (((input[i] & digit_mask) >> 1) | carry);
				carry = 0;
			} else {
				input[i] = (byte) (((input[i] & digit_mask) >> 1) | carry);
				carry = digit_first_bit_mask;
			}
		}
	}

}
