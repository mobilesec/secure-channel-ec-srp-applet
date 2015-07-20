package at.fhooe.usmile.securechannel.ecsc_srp_6a;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import javacardx.framework.math.BigNumber;

import com.nxp.id.jcopx.ECPoint;
import com.nxp.id.jcopx.ECPointBuilder;
import com.nxp.id.jcopx.KeyAgreementX;

public class UsmileKeyAgreement {

	/**
	 * size of the SRP modulus
	 */
	private final static short LENGTH_MODULUS = (short) 0x18;
	private final static short OUTPUT_OFFSET_S = (short) 0x100;
	private final static short OUTPUT_OFFSET_1 = (short) 0x140;
	private final static short OUTPUT_OFFSET_2 = (short) 0x180;

	private static final short LENGTH_EC_POINT = LENGTH_MODULUS * 2 + 1;
	
	private MessageDigest msgDigest_SHA256;
	private final static short LENGTH_MESSAGE_DIGEST = 0x20;

	private static final short LENGTH_PADDING_FOR_SQUARE_MULT = 20;
	private static final short LENGTH_SQUARE_MULT_MODULUS = 64;
	
	private final static short LENGTH_IV = (short) 0x10;
	private final static short OFFSET_IV = (short) 0x20;
	private RandomData rng;

	private Cipher rsaCipher;
	private Cipher rsaCipherModPow;
	
	private RSAPublicKey rsaPublicKey_forSquareMul;
	private RSAPublicKey rsaPublicKey_forModPow;

	// Elliptic Curve
	private ECPoint ecPublic;
	private ECPrivateKey ecPrivate;

	byte[] tempBuffer;
	
	private static byte[] v_Pi;
	private static byte[] salt;
	private static byte[] redp;
	private static Bignat SecP192r1_Q; 
	
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
	KeyAgreement agreement;
	ECPrivateKey pointPrivate;
	ECPoint nxpPointForAddition;
	KeyPair keyPair;
	
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
		rsaCipherModPow = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
		
		rsaPublicKey_forSquareMul.setExponent(squareExponent, (short) 0x00,
				(short) 0x01);

		/**
		 * set public key modulus
		 */
		rsaPublicKey_forSquareMul.setModulus(SecP192r1_P_ForRSA, (short) 0x00, (short) 0x40);
		rsaPublicKey_forModPow.setModulus(SecP192r1_P_ForRSA, (short) 0x00, (short) 0x40);

		/**
		 * v and KV are should be computed here from SRP 6a v = g^X X = H (salt,
		 * H(identity':'password)) .... from bouncy castle SRP 6a API K = H(N,
		 * g) ... g.. padded with leading 0s
		 */
		v_Pi = new byte[(short) LENGTH_EC_POINT];
		redp = new byte[(short) LENGTH_EC_POINT];
//		i2 = new byte[(short) LENGTH_MESSAGE_DIGEST];
		salt = new byte[(short) 0x10];
//		B = new byte[(short) 0x100];

		/**
		 * Initialize point and agreement scheme for Elliptic curve multiplication
		 */
		pointPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, false);
		nxpPointForAddition = ECPointBuilder.buildECPoint(ECPointBuilder.TYPE_EC_FP_POINT,KeyBuilder.LENGTH_EC_FP_192);

		initializeECPoint(nxpPointForAddition);
		initializeECPoint(pointPrivate);
		
		agreement = KeyAgreementX.getInstance(KeyAgreementX.ALG_EC_SVDP_DH_PLAIN_XY, false);
		

		/**
		 * Initialize EC Keys for Point addition (pub keys from alice and bob)
		 */
		// Initialize public / private key pair
		keyPair = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_192);
		ecPrivate = (ECPrivateKey) keyPair.getPrivate();
		ecPublic = ECPointBuilder.buildECPoint(ECPointBuilder.TYPE_EC_FP_POINT,KeyBuilder.LENGTH_EC_FP_192);

		initializeECPoint((ECKey)keyPair.getPublic());
		initializeECPoint(ecPrivate);
		initializeECPoint(ecPublic);
		
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

		SecP192r1_Q = new Bignat((short)LENGTH_MODULUS, false);
		SecP192r1_Q.from_byte_array(LENGTH_MODULUS, (short)0, SecP192r1_P, (short)0);
		
		i1.remainder_divide(bn, null);
//		Util.arrayCopy(i1.as_byte_array(), (short) (LENGTH_MESSAGE_DIGEST-LENGTH_MODULUS), v, (short)0, LENGTH_MODULUS);

		/**
		 * compute v = g^X
		 * TODO change to U_Pi . G
		 */
		calculateVPi( v_Pi, (short) (0), i1.as_byte_array(), (short) (LENGTH_MESSAGE_DIGEST-LENGTH_MODULUS), LENGTH_MODULUS);

		// Copy V_Pi to temporary buffer
		Util.arrayCopy(v_Pi, (short) 0, tempBuffer, (short) OUTPUT_OFFSET_S, (short) (LENGTH_MODULUS + 1));
		tempBuffer[OUTPUT_OFFSET_S] = (byte)0x01;
		
		short redpLength = Redp1(SecP192r1_Q, tempBuffer, (short) OUTPUT_OFFSET_S, (short) (LENGTH_MODULUS + 1), redp, (short) (1));
		
		if (redpLength == 0){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		} 
		
//		redp[0] = 0x04;
				
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
		 * Generate public/private keys
		 */
		//Generate Private/Public key
		keyPair.genKeyPair();
		
		//Copy new public key values into NXP EC point (public parameter of Bob) 
		short lenW = ((ECPublicKey)keyPair.getPublic()).getW(tempBuffer, (short) 0x0);
		ecPublic.setW(tempBuffer, (short) 0x0, lenW);
		
		/**
		 * Initialize Q_A from incoming buffer
		 */
		nxpPointForAddition.setW(incomingBuf, ISO7816.OFFSET_CDATA, apdu.getIncomingLength());

		///////////////////// ---- PUBLIC KEY Q_B COMPUTATION ---- /////////////////////
		/**
		 * Compute Q_B = G*d_b + REDP(X(vPi))
		 */
		redp[0] = 0x04;
		ecPublic.addPoint(redp, (short) 0, LENGTH_EC_POINT);
		
		// Save Q_A to temporary location for Hash computation
		Util.arrayCopy(incomingBuf, ISO7816.OFFSET_CDATA, tempBuffer, (short) 0, apdu.getIncomingLength());
		
		// Write Q_B in outgoing buffer
		ecPublic.getW(incomingBuf, ISO7816.OFFSET_CLA);

		/**
		 * Compute o3 = H( X (Q_A) | X (Q_B) )
		 */
		// Only use X coordinate of Q_A and Q_B --> set first byte to 1
		tempBuffer[0] = 0x01;
		incomingBuf[ISO7816.OFFSET_CLA] = 0x01;

		msgDigest_SHA256.update(tempBuffer, (short) 0x0,
				(short) (LENGTH_MODULUS + 1));
		msgDigest_SHA256.doFinal(incomingBuf, ISO7816.OFFSET_CLA, (short) (LENGTH_MODULUS + 1),
				tempBuffer, (short) (OUTPUT_OFFSET_1)); // Store the digest at OFFSET 1 so that it can be used
														// for verification
		
		// Set the description-byte of the Public ECPoint back to 4 
		incomingBuf[ISO7816.OFFSET_CLA] = 0x04;

		////////////////////// ---- SHARED SECRET COMPUTATION ---- //////////////////////
		/**
		 * Compute i2 = OS2IP ( o3 )
		 */
//		Bignat i2 = new Bignat(LENGTH_MESSAGE_DIGEST, false);
//		i2.from_byte_array(LENGTH_MESSAGE_DIGEST, (short)0, tempBuffer, (short)(OUTPUT_OFFSET_1));
//		i2.remainder_divide(SecP192r1_Q, null); // ~ 0,5 s
		
		try{
//    		modMultiply(tempBuffer, (short)0, (short) (LENGTH_SQUARE_MULT_MODULUS), 
//    				tempBuffer, 
//    				(short) (LENGTH_SQUARE_MULT_MODULUS),LENGTH_SQUARE_MULT_MODULUS, (short) (LENGTH_SQUARE_MULT_MODULUS*2));

    		Util.arrayFillNonAtomic(tempBuffer, (short) 0, (short)(LENGTH_SQUARE_MULT_MODULUS*2), (byte) 0);
    		Util.arrayCopy(tempBuffer, OUTPUT_OFFSET_1, tempBuffer, (short)(LENGTH_PADDING_FOR_SQUARE_MULT-8), LENGTH_MESSAGE_DIGEST);
    		tempBuffer[LENGTH_SQUARE_MULT_MODULUS + LENGTH_PADDING_FOR_SQUARE_MULT + LENGTH_MODULUS -1]=0x01;
			modMultiply(tempBuffer, (short)0, LENGTH_SQUARE_MULT_MODULUS, tempBuffer, LENGTH_SQUARE_MULT_MODULUS, LENGTH_SQUARE_MULT_MODULUS, (short) (LENGTH_SQUARE_MULT_MODULUS*2));
//			rsaCipherModulus.init(rsaPublicKey_forModulus, Cipher.MODE_ENCRYPT);
//			rsaCipherModulus.doFinal(tempBuffer, OUTPUT_OFFSET_1, LENGTH_SQUARE_MULT_MODULUS, tempBuffer,  (short)0);
//			PrivateKey pk = KeyAgreement.getInstance(KeyAgreementX.ALG_EC_SVDP_DH, externalAccess);
//			KeyBuilder.buildKey(KeyBuil, keyLength, keyEncryption)
//			ka.getInstance(algorithm, externalAccess)
//			Util.arrayCopy(tempBuffer, (short) 0, redp, (short)0, LENGTH_MODULUS);
		} catch(CryptoException e){
			if (e.getReason() == CryptoException.ILLEGAL_USE){
				redp[1] = 0x01;
			}
			else if (e.getReason() == CryptoException.INVALID_INIT){
				redp[1] = 0x02;
			}
			else if (e.getReason() == CryptoException.ILLEGAL_VALUE){
				redp[1] = 0x03;
			}
			else if (e.getReason() == CryptoException.UNINITIALIZED_KEY){
				redp[1] = 0x04;
			} else {
				redp[1] = 0x0f;
			}
		}
//		i2.to_byte_array(LENGTH_MODULUS, (short) (LENGTH_MESSAGE_DIGEST-LENGTH_MODULUS), tempBuffer, (short)0);
		
		/**
		 *  Compute Q_A + V_pi * i
		 */
		multiplyECPoint(v_Pi, (short)0, tempBuffer, (short)0, LENGTH_MODULUS, tempBuffer, (short)0); // V_pi * i
		
		nxpPointForAddition.addPoint(tempBuffer, (short) 0, (short) LENGTH_EC_POINT); // +Q_A
		
		/**
		 * Multiply outcome with d_B --> S = (Q_A + V_pi * i) * d_B
		 */
		short len = nxpPointForAddition.getW(tempBuffer, (short) 0);
		agreement.init(ecPrivate); // d_B
		agreement.generateSecret(tempBuffer, (short) 0, len, 
				tempBuffer, (short) (OUTPUT_OFFSET_S-1 )); 	// Store and use X coordinate at Location of S --> start one byte before to remove leading 0x04
		
		/**
		 * compute K = H(S)
		 */
		msgDigest_SHA256.doFinal(tempBuffer, OUTPUT_OFFSET_S, LENGTH_MODULUS,
				tempBuffer, (short) 0x00);

		/**
		 * Return Q_B, salt and IV
		 */
		len += getSalt_and_IV(incomingBuf, (short)(ISO7816.OFFSET_CLA + LENGTH_EC_POINT));
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CLA, len);
		return true;
	}

	public short calculateVPi(byte[] dstbuffer, short offset, byte[] uPiSrc, short uPiOffset, short length) {
		return multiplyGeneratorPoint(dstbuffer, offset, uPiSrc, uPiOffset, length);
	}


	public short Redp1(Bignat q, byte[] oPi, short offset, short length, byte[] pointOutput, short outoffset) {
		byte[] o1 = new byte[LENGTH_MESSAGE_DIGEST];
		msgDigest_SHA256.doFinal(oPi, offset, length,
				o1, (short) 0x00);
		
		
		// OS2IP mod N
		Bignat i1 = new Bignat(LENGTH_MESSAGE_DIGEST, false);
		i1.from_byte_array(LENGTH_MESSAGE_DIGEST, (short) 0, o1, (short)0x0);

		short outputLen = computeRandomPoint(i1, q, pointOutput, outoffset, (byte)0);

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
	private short computeRandomPoint(Bignat i1, Bignat q, byte[] outarray,  short offset, byte counter) {
		byte[] o2 = null;
		byte[] o3 = new byte[LENGTH_MESSAGE_DIGEST];
		Bignat x = new Bignat(LENGTH_MESSAGE_DIGEST, false);
		short outputElength = 0;
		
		while(counter < 5 && outputElength == 0) {
			o2 = getPadded(i1.as_byte_array(),(short)0,i1.length(), LENGTH_MESSAGE_DIGEST);
			msgDigest_SHA256.doFinal(o2, (short) 0, LENGTH_MESSAGE_DIGEST,
					o3, (short) 0x00);
	
			x.from_byte_array(LENGTH_MESSAGE_DIGEST, (short) 0, o3, (short)0x0);
			x.remainder_divide(q, null);
			
			Util.arrayFillNonAtomic(outarray, (short) (offset), (short) (LENGTH_MODULUS*2), (byte) 0 );
			Util.arrayCopy(x.as_byte_array(), (short) (LENGTH_MESSAGE_DIGEST - LENGTH_MODULUS), outarray, offset, LENGTH_MODULUS);
	
			
			if (!Bignat.valueOf(LENGTH_MODULUS, (byte)0).same_value(x)){
//				byte mu = (byte) (i1.getLastByte() & 0x01);
				
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
				    		}
	//			    		Util.arrayCopy(tempBuffer, (short)0, outarray, offset, LENGTH_MODULUS);

							/**
				    		 * (x^2 + A) * x
				    		 */
			    			//Copy (x^2 + A) to position after padding
				    		Util.arrayCopy(tempBuffer, (short) 0, tempBuffer, 
			    					(byte) (LENGTH_PADDING_FOR_SQUARE_MULT), LENGTH_MODULUS );
	
				    		// Fill padding with zeros
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (0), 
			    					(short) LENGTH_PADDING_FOR_SQUARE_MULT, (byte) 0 );
				    		// Fill trailing bytes with zeros
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (LENGTH_PADDING_FOR_SQUARE_MULT + LENGTH_MODULUS), 
			    					(short) LENGTH_PADDING_FOR_SQUARE_MULT, (byte) 0 );
				    		
			    			// Fill padding bytes with zeros
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (LENGTH_SQUARE_MULT_MODULUS), 
			    					(short) LENGTH_SQUARE_MULT_MODULUS, (byte) 0 );
				    		
				    		// copy x after the current temporary buffer location
			    			Util.arrayCopy(x.as_byte_array(), (short) (x.length() - LENGTH_MODULUS), tempBuffer, 
			    					(byte) (LENGTH_SQUARE_MULT_MODULUS+LENGTH_PADDING_FOR_SQUARE_MULT), LENGTH_MODULUS );
	
			    			// Multiply current value (x^2 + A) with x
				    		modMultiply(tempBuffer, (short)0, (short) (LENGTH_SQUARE_MULT_MODULUS), 
				    				tempBuffer, 
				    				(short) (LENGTH_SQUARE_MULT_MODULUS),LENGTH_SQUARE_MULT_MODULUS, (short) (LENGTH_SQUARE_MULT_MODULUS*2));

				    		/**
				    		 * (x^2 + A) * x + b
				    		 */
				    		if(add(tempBuffer, (short)0, LENGTH_MODULUS, SecP192r1_B, (short)0, (short) SecP192r1_B.length)){
				    			subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, SecP192r1_P_ForRSA,
				    					(short) 0, LENGTH_MODULUS);
				    		}
				    		Util.arrayCopy(tempBuffer, (short)0, tempBuffer, LENGTH_SQUARE_MULT_MODULUS, LENGTH_MODULUS);
				    		
	//						Util.arrayCopy(tempBuffer, (short)0, outarray, offset, LENGTH_MODULUS);
	//			    		Bignat alpha = new Bignat(LENGTH_MODULUS, false);
	//			    		alpha.from_byte_array(length, (short)0, tempBuffer, (short)0);
	//			    		
				    		// Copy alpha to buffer
				    		Util.arrayCopy(tempBuffer, (short) (0), tempBuffer, 
			    					(byte) (LENGTH_PADDING_FOR_SQUARE_MULT*2), LENGTH_MODULUS );
				    		Util.arrayCopy(tempBuffer, (short)0, tempBuffer, OUTPUT_OFFSET_S, LENGTH_MODULUS);
				    		tempBuffer[OUTPUT_OFFSET_S] = 0x01;
				    		// Fill padding with zeros
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (0), 
			    					(short) (LENGTH_PADDING_FOR_SQUARE_MULT*2), (byte) 0 );
				    		
				    		// Fill second area with zeros
	//			    		Util.arrayFillNonAtomic(tempBuffer, (short) (LENGTH_SQUARE_MULT_MODULUS), 
	//		    					(short) (LENGTH_SQUARE_MULT_MODULUS), (byte) 0 );
				    		
				    		findSquareRoot(tempBuffer, (short)(0), 
				    				LENGTH_SQUARE_MULT_MODULUS, q, tempBuffer, (short)(LENGTH_PADDING_FOR_SQUARE_MULT));
				    		Util.arrayCopy(tempBuffer, (short)LENGTH_PADDING_FOR_SQUARE_MULT, outarray, (short) (offset+LENGTH_MODULUS), LENGTH_MODULUS);
				    		
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (0), 
			    					(short) (LENGTH_PADDING_FOR_SQUARE_MULT), (byte) 0 );
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (LENGTH_PADDING_FOR_SQUARE_MULT+LENGTH_MODULUS), 
			    					(short) (LENGTH_PADDING_FOR_SQUARE_MULT), (byte) 0 );
				    		
				    		length = rsaCipher.doFinal(tempBuffer, (short) 0, LENGTH_SQUARE_MULT_MODULUS, tempBuffer, (short) 0);

				    		if(Util.arrayCompare(tempBuffer, (short) 0, tempBuffer, LENGTH_SQUARE_MULT_MODULUS, LENGTH_MODULUS) == 0){
					    		outputElength = LENGTH_MODULUS;
				    		} else {
				    			i1.add(Bignat.valueOf((byte) 1, (byte) 1));
				    			counter++;
	//			    			return computeRandomPoint(i1, q, outarray, offset, ++counter);
				    		}
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
				}
			}
		}

		return outputElength;
	}
	

	private void findSquareRoot(byte[] alpha, short offset, short length, Bignat p, byte[] out, short outoffset) {
		Bignat helper = new Bignat((short) LENGTH_SQUARE_MULT_MODULUS, false);
		Bignat remainder= new Bignat((short) LENGTH_MODULUS, false);
		
		byte t = (byte) (p.getLastByte() & 0x03); // mod 4
		if(t == (byte)3 ){ //p = 3 mod 4
			
			Bignat k =new Bignat(LENGTH_MODULUS, false);
			k.copy(p);
			k.div_2();
			k.div_2();
			k.add(Bignat.valueOf(LENGTH_MODULUS, (byte)1));
			
			rsaPublicKey_forModPow.setExponent(k.as_byte_array(), (short) 0, (short) k.length());
			rsaPublicKey_forModPow.setModulus(SecP192r1_P_ForRSA, (short) 0x00, (short) 0x40);
			
			rsaCipherModPow.init(rsaPublicKey_forModPow, Cipher.MODE_ENCRYPT);

			rsaCipherModPow.doFinal(alpha, offset, length, alpha, offset);

			// TODO can we improve this?
			helper.from_byte_array(LENGTH_SQUARE_MULT_MODULUS, (short)0, alpha, offset);
			helper.remainder_divide(p, null);
			helper.to_byte_array(LENGTH_SQUARE_MULT_MODULUS, (short)(LENGTH_PADDING_FOR_SQUARE_MULT*2), out, outoffset);
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
	private short multiplyECPoint(byte[] ecpoint, short ecpointoffset, byte[] multiplier, short mpoffset, short moduluslength, byte[] pointOutputBuffer, short offset){
		pointPrivate.setS(multiplier, (short) mpoffset, moduluslength);
		
		agreement.init(pointPrivate);
		return agreement.generateSecret(ecpoint, ecpointoffset, (short) (moduluslength*2+1), pointOutputBuffer, offset);
	}

	private short multiplyGeneratorPoint(byte[] pointOutputBuffer, short offset, byte[] multiplier, short mpoffset, short mplength){
		
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
//		pointPrivate.setS(multiplier, (short) mpoffset, mplength);
//		agreement.init(pointPrivate);
//		ecPrivate.getG(tempBuffer, (short) (0));
		return multiplyECPoint(SecP192r1_G, (short) (0), multiplier, mpoffset, mplength, pointOutputBuffer, offset);
	}
	
	private short GE2OSPX(ECPoint ecPoint, byte[] buffer, byte offset){
		short ecPointLength=ecPoint.getW(buffer, (short) (offset+0x01));
		
		buffer[0] = (byte)0x01;
		
		return (short) (ecPointLength+1); 
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
		Util.arrayCopy(redp, (short)0, outArray,
				(short) offset, LENGTH_EC_POINT);
//		outArray[offset] = 0x01;
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
	
	/*public boolean authenticate(APDU apdu, byte[] incomingBuf) {

		Util.arrayCopy(kv, (short) 0, incomingBuf, ISO7816.OFFSET_CLA, (short) 49);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CLA, (short) 49);
		return true;
	}*/
	public boolean authenticate(APDU apdu, byte[] incomingBuf) {
		short M_offset = (short)(OUTPUT_OFFSET_S - LENGTH_MESSAGE_DIGEST);
		/**
		 * compute expected authentication data M = H(u, S)
		 */
		msgDigest_SHA256.update(tempBuffer, OUTPUT_OFFSET_1, LENGTH_MESSAGE_DIGEST);
		msgDigest_SHA256.doFinal(tempBuffer, OUTPUT_OFFSET_S, LENGTH_MODULUS,
				tempBuffer, (short) M_offset );

		/**
		 * compare with incoming Auth data if authenticated compute server ..
		 * (SE ) Authentication Data.... H (u, M, S) from the previous operation
		 * tempoutput contains M, S from offset M_offset - M_offset +
		 * LENGTH_MODULUS
		 */
		if (Util.arrayCompare(incomingBuf, ISO7816.OFFSET_CDATA, tempBuffer,
				(short) M_offset, LENGTH_MESSAGE_DIGEST) == 0) {
			msgDigest_SHA256
					.update(tempBuffer, OUTPUT_OFFSET_1, LENGTH_MESSAGE_DIGEST);
			msgDigest_SHA256.doFinal(tempBuffer, M_offset, (short) (LENGTH_MODULUS + LENGTH_MESSAGE_DIGEST),
					incomingBuf, (short) ISO7816.OFFSET_CDATA);

//			Util.arrayCopy(tempBuffer, M_offset, incomingBuf, ISO7816.OFFSET_CDATA, (short) (LENGTH_MODULUS + LENGTH_MESSAGE_DIGEST));
			
			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (LENGTH_MESSAGE_DIGEST));
			return true;
		} else {
			Util.arrayCopy(tempBuffer, OUTPUT_OFFSET_S, incomingBuf, ISO7816.OFFSET_CDATA, LENGTH_MODULUS);
			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA,LENGTH_MODULUS);
		}

		
		return false;
	}

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
			short yOffset, short yLength, short tempOutoffset) {
		/**
		 * x+y
		 */
		Util.arrayCopy(SecP192r1_P_ForRSA, (short) 0x00, tempBuffer, OUTPUT_OFFSET_2,
				LENGTH_SQUARE_MULT_MODULUS);
		Util.arrayCopy(x, xOffset, tempBuffer, tempOutoffset, xLength);
		if (add(x, LENGTH_PADDING_FOR_SQUARE_MULT, (LENGTH_MODULUS), y,
				(short) (yOffset+LENGTH_PADDING_FOR_SQUARE_MULT), LENGTH_MODULUS)) {
			subtract(x, LENGTH_PADDING_FOR_SQUARE_MULT, (LENGTH_MODULUS), tempBuffer,
					OUTPUT_OFFSET_2, LENGTH_MODULUS);
		} // OK
		
		/**
		 * (x+y)^2
		 */

		rsaCipher.init(rsaPublicKey_forSquareMul, Cipher.MODE_ENCRYPT);
		rsaCipher.doFinal(x, xOffset, LENGTH_SQUARE_MULT_MODULUS, x,
				xOffset); // OK

		/**
		 * compute x^2
		 */
		rsaCipher.doFinal(tempBuffer, tempOutoffset, LENGTH_SQUARE_MULT_MODULUS, tempBuffer, tempOutoffset); // OK

		/**
		 * compute (x+y)^2 - x^2
		 */
		if (subtract(x, xOffset, LENGTH_MODULUS, tempBuffer, tempOutoffset,
				LENGTH_MODULUS)) {
			add(x, xOffset, LENGTH_MODULUS, tempBuffer,
					OUTPUT_OFFSET_2, LENGTH_MODULUS);
		} // OK

		/**
		 * compute y^2
		 */
		rsaCipher.doFinal(y, yOffset, yLength, y, yOffset); //OK

		
		/**
		 * compute (x+y)^2 - x^2 - y^2
		 */

		if (subtract(x, xOffset, LENGTH_MODULUS, y, yOffset,
				LENGTH_MODULUS)) {

			add(x, xOffset, LENGTH_MODULUS, tempBuffer,
					OUTPUT_OFFSET_2, LENGTH_MODULUS);

		}

		/**
		 * divide by 2
		 */

		modular_division_by_2(x, xOffset, LENGTH_MODULUS);

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
					LENGTH_MODULUS)) {
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
