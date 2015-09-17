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
	private final static short OUTPUT_OFFSET_S = (short) 0x100;
	private final static short OUTPUT_OFFSET_1 = (short) 0x140;
	private final static short OUTPUT_OFFSET_2 = (short) 0x180;

	private static final byte REDP_MAX_INCREASE = 5;
	
	private static final short LENGTH_EC_POINT = LENGTH_MODULUS * 2 + 1;
	
	private final static short LENGTH_MESSAGE_DIGEST = 0x20;

	private static final short LENGTH_PADDING_FOR_SQUARE_MULT = 20;
	private static final short LENGTH_SQUARE_MULT_MODULUS = 64;
	
	private final static short LENGTH_IV = (short) 0x10;
	private final static short OFFSET_IV = (short) 0x20;

	private final static byte LENGTH_SALT = 0x10;

	private final static byte[] SQUARE_EXPONENT = new byte[] { 0x02 };
	
	private RandomData mSaltGenerator;

	private Cipher mRsaCipherForSquaring;
	private Cipher mRsaCipherModPow;
	
	private MessageDigest mUsedMsgDigest; // SHA-256
	
	private RSAPublicKey mRsaPublicKekForSquare;
	private RSAPublicKey mRsaPublicKeyModPow;

	// Elliptic Curve
	private ECPoint mLocalECPublicKey;
	private ECPrivateKey mLocalECPrivateKey;

	private byte[] tempBuffer;
	
	private static byte[] mV_Pi;
	private static byte[] mSalt;
	private static byte[] mREDP;
	
	private static Bignat mCurveQ; 
		
	private KeyAgreement mECMultiplHelper;
	private ECPrivateKey mECMultiplHelperPrivatePoint;
	private ECPoint mNxpPointForECAddition;
	private KeyPair mECKeyPairGenerator;
	
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
		mUsedMsgDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256,
				false);
		/**
		 * init random data generator
		 */
		mSaltGenerator = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

		mRsaPublicKekForSquare = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		mRsaPublicKeyModPow = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		
		mRsaCipherForSquaring = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
		mRsaCipherModPow = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
		
		mRsaPublicKekForSquare.setExponent(SQUARE_EXPONENT, (short) 0x00,
				(short) 0x01);

		/**
		 * set public key modulus
		 */
		mRsaPublicKekForSquare.setModulus(CurveConstants.SecP192r1_P_ForRSA, (short) 0x00, (short) 0x40);
		mRsaPublicKeyModPow.setModulus(CurveConstants.SecP192r1_P_ForRSA, (short) 0x00, (short) 0x40);

		/**
		 * v and KV are should be computed here from SRP 6a v = g^X X = H (salt,
		 * H(identity':'password)) .... from bouncy castle SRP 6a API K = H(N,
		 * g) ... g.. padded with leading 0s
		 */
		mV_Pi = new byte[(short) LENGTH_EC_POINT];
		mREDP = new byte[(short) LENGTH_EC_POINT];
		mSalt = new byte[(short) 0x10];

		/**
		 * Initialize point and agreement scheme for Elliptic curve multiplication
		 */
		mECMultiplHelperPrivatePoint = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, false);
		mNxpPointForECAddition = ECPointBuilder.buildECPoint(ECPointBuilder.TYPE_EC_FP_POINT,KeyBuilder.LENGTH_EC_FP_192);

		SRP5Utils.initializeECPoint(mNxpPointForECAddition);
		SRP5Utils.initializeECPoint(mECMultiplHelperPrivatePoint);

		mECMultiplHelper = KeyAgreementX.getInstance(KeyAgreementX.ALG_EC_SVDP_DH_PLAIN_XY, false);
//		mECTester = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
		
		/**
		 * Initialize EC Keys for Point addition (pub keys from alice and bob)
		 */
//		KeyPair test = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_224);
//		test.genKeyPair();
		
		mECKeyPairGenerator = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_192);
		mLocalECPrivateKey = (ECPrivateKey) mECKeyPairGenerator.getPrivate();
		mLocalECPublicKey = ECPointBuilder.buildECPoint(ECPointBuilder.TYPE_EC_FP_POINT,KeyBuilder.LENGTH_EC_FP_192);

		SRP5Utils.initializeECPoint((ECKey)mECKeyPairGenerator.getPublic());
		SRP5Utils.initializeECPoint(mLocalECPrivateKey);
		SRP5Utils.initializeECPoint(mLocalECPublicKey);
		
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
		mSaltGenerator.generateData(mSalt, (short) 0x00, LENGTH_SALT);

		/**
		 * compute U_Pi = OS2IP(H (salt, H(identity':'password))) mod r
		 */
				
		mUsedMsgDigest.doFinal(tempBuffer, (short) 0x00, length, tempBuffer,
				OUTPUT_OFFSET_2);
		mUsedMsgDigest.update(mSalt, (short) 0x00, LENGTH_SALT);
		mUsedMsgDigest.doFinal(tempBuffer, OUTPUT_OFFSET_2,
				LENGTH_MESSAGE_DIGEST, tempBuffer, (short) (0x0));

		// OS2IP mod N
		Bignat i1 = new Bignat(LENGTH_MESSAGE_DIGEST, false);
		i1.from_byte_array(LENGTH_MESSAGE_DIGEST, (short) 0, tempBuffer, (short)0x0);
		Bignat bn = new Bignat((short)LENGTH_MODULUS, false);
		bn.from_byte_array(LENGTH_MODULUS, (short)0, CurveConstants.SecP192r1_N, (short)0);

		mCurveQ = new Bignat((short)LENGTH_MODULUS, false);
		mCurveQ.from_byte_array(LENGTH_MODULUS, (short)0, CurveConstants.SecP192r1_P, (short)0);
		
		// TODO improve computation performance of modulo operation
		i1.remainder_divide(bn, null);

		/**
		 * precompute k = parameter for finding square root of alpha
		 */
		Bignat k = null;
		
		byte t = (byte) (mCurveQ.getLastByte() & 0x03); // mod 4
		if(t == (byte)3 ){ //p = 3 mod 4
			k = new Bignat(LENGTH_MODULUS, false);
			k.copy(mCurveQ);
			k.div_2();
			k.div_2();
			k.add(Bignat.valueOf(LENGTH_MODULUS, (byte)1));
			
			mRsaPublicKeyModPow.setExponent(k.as_byte_array(), (short) 0, (short) k.length());
			mRsaPublicKeyModPow.setModulus(CurveConstants.SecP192r1_P_ForRSA, (short) 0x00, (short) 0x40);
		} else {
			// TODO
		}
		
		/**
		 * compute V_Pi
		 */
		calculateVPi( mV_Pi, (short) (0), i1.as_byte_array(), (short) (LENGTH_MESSAGE_DIGEST-LENGTH_MODULUS), LENGTH_MODULUS);

		// Copy V_Pi to temporary buffer
		Util.arrayCopy(mV_Pi, (short) 0, tempBuffer, (short) OUTPUT_OFFSET_S, (short) (LENGTH_MODULUS + 1));
		tempBuffer[OUTPUT_OFFSET_S] = (byte)0x01;
		
		// Compute random point
		short redpLength = Redp1(k, tempBuffer, (short) OUTPUT_OFFSET_S, (short) (LENGTH_MODULUS + 1), mREDP, (short) (1));
		mREDP[0] = 0x04;
		
		// Could not compute random point, return an error
		if (redpLength == 0){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		} 
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
		//Generate new Private/Public key (d_B ad Q_B)
		mECKeyPairGenerator.genKeyPair();
		
//		mECTester.init((ECPrivateKey)mECKeyPairGenerator.getPrivate());
//		mECTester.generateSecret(incomingBuf, ISO7816.OFFSET_CDATA, apdu.getIncomingLength(), tempBuffer, (short)0x0);
		
		//Copy new public key values into NXP EC point (public parameter of Bob) 
		short lenW = ((ECPublicKey)mECKeyPairGenerator.getPublic()).getW(tempBuffer, (short) 0x0);
		mLocalECPublicKey.setW(tempBuffer, (short) 0x0, lenW);
		
		/**
		 * Initialize Q_A from incoming buffer
		 */
		mNxpPointForECAddition.setW(incomingBuf, ISO7816.OFFSET_CDATA, apdu.getIncomingLength()); // Q_A

		///////////////////// ---- PUBLIC KEY Q_B COMPUTATION ---- /////////////////////
		/**
		 * Compute Q_B = G*d_b + REDP(X(vPi))
		 */
		mLocalECPublicKey.addPoint(mREDP, (short) 0, LENGTH_EC_POINT);
		
		/**
		 * Compute o3 = H( X (Q_A) | X (Q_B) )
		 */
		// Use Q_A
		// Only use X coordinate of Q_A and Q_B --> set first byte to 1
		incomingBuf[ISO7816.OFFSET_CDATA] = 0x01;

		mUsedMsgDigest.update(incomingBuf, (short) ISO7816.OFFSET_CDATA,
				(short) (LENGTH_MODULUS + 1));

		// Write Q_B in outgoing buffer
		mLocalECPublicKey.getW(incomingBuf, ISO7816.OFFSET_CLA);
		incomingBuf[ISO7816.OFFSET_CLA] = 0x01;
		
		mUsedMsgDigest.doFinal(incomingBuf, ISO7816.OFFSET_CLA, (short) (LENGTH_MODULUS + 1),
				tempBuffer, (short) (OUTPUT_OFFSET_1)); // Store the digest at OFFSET 1 so that it can be used
														// for verification
		
		// Set the description-byte of the Public ECPoint back to 4 
		incomingBuf[ISO7816.OFFSET_CLA] = 0x04;

		////////////////////// ---- SHARED SECRET COMPUTATION ---- //////////////////////
		/**
		 * Compute i2 = OS2IP ( o3 )
		 */
		// Reset temporary buffer
		Util.arrayFillNonAtomic(tempBuffer, (short) 0, (short)(LENGTH_SQUARE_MULT_MODULUS * 2), (byte) 0);
		moduloP(tempBuffer, OUTPUT_OFFSET_1);
		
		/**
		 *  Compute Q_A + V_pi * i
		 */
		multiplyECPoint(mV_Pi, (short)0, tempBuffer, (short)0, LENGTH_MODULUS, tempBuffer, (short)0); // V_pi * i
		mNxpPointForECAddition.addPoint(tempBuffer, (short) 0, (short) LENGTH_EC_POINT); // Q_A + V_pi*i
		
		/**
		 * Multiply outcome with d_B --> S = (Q_A + V_pi * i) * d_B
		 */
		short len = mNxpPointForECAddition.getW(tempBuffer, (short) 0);
		mECMultiplHelper.init(mLocalECPrivateKey); // d_B
		mECMultiplHelper.generateSecret(tempBuffer, (short) 0, len, 
				tempBuffer, (short) (OUTPUT_OFFSET_S-1 )); 	// Store and use X coordinate at Location of S --> start one byte before to remove leading 0x04
		
		/**
		 * compute K = H(S)
		 */
		mUsedMsgDigest.doFinal(tempBuffer, OUTPUT_OFFSET_S, LENGTH_MODULUS,
				tempBuffer, (short) 0x00); // Only use x coordinate for shared secret

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

	public short Redp1(Bignat k, byte[] oPi, short offset, short length, byte[] pointOutput, short outoffset) {
		byte[] o1 = new byte[LENGTH_MESSAGE_DIGEST];
		mUsedMsgDigest.doFinal(oPi, offset, length,
				o1, (short) 0x00);
		
		
		// OS2IP mod N
		Bignat i1 = new Bignat(LENGTH_MESSAGE_DIGEST, false);
		i1.from_byte_array(LENGTH_MESSAGE_DIGEST, (short) 0, o1, (short)0x0);

		short outputLen = computeRandomPoint(k, i1, pointOutput, outoffset, (byte)0);

		return outputLen;
	}

	private static byte[] getPadded(byte[] n, short offset, short arrayLength, short newlength) {
		byte[] bs = n;
		if (arrayLength < newlength) {
			byte[] tmp = new byte[newlength];
			Util.arrayCopy(bs, offset, tmp, (short)(newlength - arrayLength), (short) arrayLength);
			bs = tmp;
		}
		return bs;
	}
	
	private void moduloP(byte[] data, short dataoffset){
		Util.arrayCopy(data, dataoffset, tempBuffer, 
				(short)(LENGTH_PADDING_FOR_SQUARE_MULT-(LENGTH_MESSAGE_DIGEST-LENGTH_MODULUS)), 
				LENGTH_MESSAGE_DIGEST);
		
		// Set multiplier to one (only modulo operation)
		tempBuffer[LENGTH_SQUARE_MULT_MODULUS + LENGTH_PADDING_FOR_SQUARE_MULT + LENGTH_MODULUS - 1]=0x01;
		
		// Multiply data with 1 for modulo operation 
		modMultiply(tempBuffer, (short)0, LENGTH_SQUARE_MULT_MODULUS, 
				tempBuffer, LENGTH_SQUARE_MULT_MODULUS, LENGTH_SQUARE_MULT_MODULUS, 
				(short) (LENGTH_SQUARE_MULT_MODULUS*2));
	}
	
	private short computeRandomPoint(Bignat k, Bignat i1, byte[] outarray,  short offset, byte counter) {
		byte[] o2 = null;
		byte[] o3 = new byte[LENGTH_MESSAGE_DIGEST];
//		Bignat x = new Bignat(LENGTH_MESSAGE_DIGEST, false);
		short outputElength = 0;
		
		while(counter < REDP_MAX_INCREASE && outputElength == 0) {
			Util.arrayFillNonAtomic(o3, (short) 0, LENGTH_MESSAGE_DIGEST, (byte) 0);
			Util.arrayFillNonAtomic(tempBuffer, (short) 0, (short)(LENGTH_SQUARE_MULT_MODULUS *2), (byte) 0);
			
			o2 = getPadded(i1.as_byte_array(),(short)0,i1.length(), LENGTH_MESSAGE_DIGEST);
			mUsedMsgDigest.doFinal(o2, (short) 0, LENGTH_MESSAGE_DIGEST,
					o3, (short) 0x00);
			moduloP(o3,(short)0);
			
//			x.from_byte_array(LENGTH_MESSAGE_DIGEST, (short) 0, o3, (short)0x0);
//			x.remainder_divide(mUsedCurveQ, null);
//			Util.arrayCopy(x.as_byte_array(), (short) (LENGTH_MESSAGE_DIGEST-LENGTH_MODULUS), tempBuffer, (short)0, LENGTH_MODULUS);
			
			Util.arrayFillNonAtomic(outarray, (short) (offset), (short) (LENGTH_MODULUS*2), (byte) 0 );
			Util.arrayCopy(tempBuffer, (short) (0), outarray, offset, LENGTH_MODULUS);
	
			
			if (!isZero(tempBuffer, (short)0, LENGTH_MODULUS)){
					if (Bignat.valueOf(LENGTH_MODULUS, (byte)3).same_value(mCurveQ)){
						// TODO
					} else { //TODO if (BigInteger.valueOf(3).compareTo(p) == -1){
						//p is greater than 3
	
			    		try{
				    		/**
				    		 * compute x^2
				    		 */
			    			mRsaCipherForSquaring.init(mRsaPublicKekForSquare, Cipher.MODE_ENCRYPT);
			    			// Copy x to fill temporary buffer of size SQUARE_MULTIPLICATION_MODULUS with zeros
			    			Util.arrayCopy(tempBuffer, (short) (0), tempBuffer, 
			    					(byte) (LENGTH_PADDING_FOR_SQUARE_MULT), 
			    					LENGTH_MODULUS );
			    			// Put padding before and after x (e.g. [20 B] | x | [20 B])
			    			Util.arrayFillNonAtomic(tempBuffer, (short) (0), (short) LENGTH_PADDING_FOR_SQUARE_MULT, (byte) 0 );
			    			Util.arrayFillNonAtomic(tempBuffer, (short) (LENGTH_MODULUS+LENGTH_PADDING_FOR_SQUARE_MULT), (short) LENGTH_PADDING_FOR_SQUARE_MULT, (byte) 0 );
			    			
			    			mRsaCipherForSquaring.doFinal(tempBuffer, (short) 0, (short) (LENGTH_SQUARE_MULT_MODULUS), tempBuffer, (short) 0);

			    			/**
				    		 * add a
				    		 */
			    			if(add(tempBuffer, (short)0, LENGTH_MODULUS, CurveConstants.SecP192r1_A, 
			    					(short)0, (short) CurveConstants.SecP192r1_A.length)){
				    			subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, CurveConstants.SecP192r1_P_ForRSA,
				    					(short) 0, LENGTH_MODULUS);
				    		}
	//			    		Util.arrayCopy(tempBuffer, (short)0, outarray, offset, LENGTH_MODULUS);

							/**
				    		 * (x^2 + a) * x
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
			    			Util.arrayCopy(outarray, offset, tempBuffer, 
			    					(byte) (LENGTH_SQUARE_MULT_MODULUS+LENGTH_PADDING_FOR_SQUARE_MULT), LENGTH_MODULUS );
	
			    			// Multiply current value (x^2 + A) with x
				    		modMultiply(tempBuffer, (short)0, (short) (LENGTH_SQUARE_MULT_MODULUS), 
				    				tempBuffer, 
				    				(short) (LENGTH_SQUARE_MULT_MODULUS),LENGTH_SQUARE_MULT_MODULUS, (short) (LENGTH_SQUARE_MULT_MODULUS*2));

				    		/**
				    		 * (x^2 + a) * x + b
				    		 */
				    		if(add(tempBuffer, (short)0, LENGTH_MODULUS, CurveConstants.SecP192r1_B, 
				    				(short)0, (short) CurveConstants.SecP192r1_B.length)){
				    			subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, CurveConstants.SecP192r1_P_ForRSA,
				    					(short) 0, LENGTH_MODULUS);
				    		}
				    		Util.arrayCopy(tempBuffer, (short)0, tempBuffer, LENGTH_SQUARE_MULT_MODULUS, LENGTH_MODULUS);
				    		
				    		// Copy alpha to buffer
				    		Util.arrayCopy(tempBuffer, (short) (0), tempBuffer, 
			    					(byte) (LENGTH_PADDING_FOR_SQUARE_MULT*2), LENGTH_MODULUS );
				    		
				    		// Copy alpha to ??
				    		Util.arrayCopy(tempBuffer, (short)0, tempBuffer, OUTPUT_OFFSET_S, LENGTH_MODULUS);
				    		
				    		tempBuffer[OUTPUT_OFFSET_S] = 0x01;
				    		
				    		// Fill padding with zeros
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (0), 
			    					(short) (LENGTH_PADDING_FOR_SQUARE_MULT*2), (byte) 0 );
				    		
				    		findSquareRoot(k, tempBuffer, (short)(0), 
				    				LENGTH_SQUARE_MULT_MODULUS, tempBuffer, (short)(LENGTH_PADDING_FOR_SQUARE_MULT));
				    		
				    		Util.arrayCopy(tempBuffer, (short)LENGTH_PADDING_FOR_SQUARE_MULT, outarray, (short) (offset+LENGTH_MODULUS), LENGTH_MODULUS);
				    		
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (0), 
			    					(short) (LENGTH_PADDING_FOR_SQUARE_MULT), (byte) 0 );
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (LENGTH_PADDING_FOR_SQUARE_MULT+LENGTH_MODULUS), 
			    					(short) (LENGTH_PADDING_FOR_SQUARE_MULT), (byte) 0 );
				    		
				    		mRsaCipherForSquaring.doFinal(tempBuffer, (short) 0, LENGTH_SQUARE_MULT_MODULUS, tempBuffer, (short) 0);

				    		if(Util.arrayCompare(tempBuffer, (short) 0, tempBuffer, LENGTH_SQUARE_MULT_MODULUS, LENGTH_MODULUS) == 0){
								byte mu = (byte) (i1.getLastByte() & 0x01);
								
								if(mu == 1) { // negate
									Util.arrayCopy(CurveConstants.SecP192r1_P, (short)0, tempBuffer, (short) (0), LENGTH_MODULUS);
						    		if(subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, outarray,
						    				(short) (offset+LENGTH_MODULUS), LENGTH_MODULUS)) {
						    			add(tempBuffer, (short) 0x00, LENGTH_MODULUS, CurveConstants.SecP192r1_P_ForRSA,
						    					(short) 0, LENGTH_MODULUS);
						    		}
						    		
									Util.arrayCopy(tempBuffer, (short)0, outarray, (short) (offset+LENGTH_MODULUS), LENGTH_MODULUS);
								}
								 
								outputElength = LENGTH_MODULUS;
				    		} else {
				    			i1.add(Bignat.valueOf((byte) 1, (byte) 1));
				    			counter++;
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
			} else { // isZero
				outputElength = -1;
			}
		}

		return outputElength;
	}
	

	private boolean isZero(byte[] tempBuffer, short offset, short length) {
		for (short i=0; i<= length;i++) {
			if(tempBuffer[(short)(offset + i)] != (short) 0x00) {
				return false;
			}
		}
		return true;
	}

	private void findSquareRoot(Bignat k, byte[] alpha, short offset, short length, byte[] out, short outoffset) {
		Bignat helper = new Bignat((short) LENGTH_SQUARE_MULT_MODULUS, false);
		Bignat remainder= new Bignat((short) LENGTH_MODULUS, false);
		

		byte t = (byte) (mCurveQ.getLastByte() & 0x03); // mod 4
		if(t == (byte)3 ){ //p = 3 mod 4
//			rsaPublicKey_forModPow.setExponent(k.as_byte_array(), (short) 0, (short) k.length());
//			rsaPublicKey_forModPow.setModulus(SecP192r1_P_ForRSA, (short) 0x00, (short) 0x40);
			
			mRsaCipherModPow.init(mRsaPublicKeyModPow, Cipher.MODE_ENCRYPT);
			mRsaCipherModPow.doFinal(alpha, offset, length, alpha, offset);

			// TODO can we improve this?
			helper.from_byte_array(LENGTH_SQUARE_MULT_MODULUS, (short)0, alpha, offset);
			helper.remainder_divide(mCurveQ, null);
			helper.to_byte_array(LENGTH_SQUARE_MULT_MODULUS, (short)(LENGTH_PADDING_FOR_SQUARE_MULT*2), out, outoffset);
		} else { 
			
			helper.setLastByte((byte)5);
//			SecP192r1_Q.remainder_divide(helper,remainder);
			
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
		mECMultiplHelperPrivatePoint.setS(multiplier, (short) mpoffset, moduluslength);
		
		mECMultiplHelper.init(mECMultiplHelperPrivatePoint);
		return mECMultiplHelper.generateSecret(ecpoint, ecpointoffset, (short) (moduluslength*2+1), pointOutputBuffer, offset);
	}

	private short multiplyGeneratorPoint(byte[] pointOutputBuffer, short offset, byte[] multiplier, short mpoffset, short mplength){
		return multiplyECPoint(CurveConstants.SecP192r1_G, (short) (0), 
				multiplier, mpoffset, mplength, pointOutputBuffer, offset);
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
		Util.arrayCopy(mSalt, (short) 0x00, out_salt_iv, outOffset, LENGTH_SALT);
		generateRandom(tempBuffer, OFFSET_IV, LENGTH_IV);

		Util.arrayCopy(tempBuffer, OFFSET_IV, out_salt_iv,
				(short) (outOffset + LENGTH_SALT), LENGTH_IV);
		return (short) (LENGTH_SALT + LENGTH_IV);
	}

	public short getOutputValue(byte[] outArray, short offset){

		// TODO Remove this, only for debugging
		Util.arrayCopy(mREDP, (short)0, outArray,
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
	
	public boolean authenticate(APDU apdu, byte[] incomingBuf) {
		short M_offset = (short)(OUTPUT_OFFSET_S - LENGTH_MESSAGE_DIGEST);
		/**
		 * compute expected authentication data M = H(o3, S)
		 */
		mUsedMsgDigest.update(tempBuffer, OUTPUT_OFFSET_1, LENGTH_MESSAGE_DIGEST);
		mUsedMsgDigest.doFinal(tempBuffer, OUTPUT_OFFSET_S, LENGTH_MODULUS,
				tempBuffer, (short) M_offset );

		/**
		 * compare with incoming Auth data if authenticated compute server ..
		 * (SE ) Authentication Data.... H (o3, M, S) from the previous operation
		 * tempoutput contains M, S from offset M_offset - M_offset +
		 * LENGTH_MODULUS
		 */
		if (Util.arrayCompare(incomingBuf, ISO7816.OFFSET_CDATA, tempBuffer,
				(short) M_offset, LENGTH_MESSAGE_DIGEST) == 0) {
			mUsedMsgDigest
					.update(tempBuffer, OUTPUT_OFFSET_1, LENGTH_MESSAGE_DIGEST);
			mUsedMsgDigest.doFinal(tempBuffer, M_offset, (short) (LENGTH_MODULUS + LENGTH_MESSAGE_DIGEST),
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
			mSaltGenerator.generateData(buffer, offset, length);
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
		Util.arrayCopy(CurveConstants.SecP192r1_P_ForRSA, (short) 0x00, tempBuffer, OUTPUT_OFFSET_2,
				LENGTH_MODULUS);
		Util.arrayCopy(x, xOffset, tempBuffer, tempOutoffset, xLength);
		if (add(x, LENGTH_PADDING_FOR_SQUARE_MULT, (LENGTH_MODULUS), y,
				(short) (yOffset+LENGTH_PADDING_FOR_SQUARE_MULT), LENGTH_MODULUS)) {
			subtract(x, LENGTH_PADDING_FOR_SQUARE_MULT, (LENGTH_MODULUS), CurveConstants.SecP192r1_P_ForRSA,
					(short) 0x00, LENGTH_MODULUS);
		} // OK
		
		/**
		 * (x+y)^2
		 */
		mRsaCipherForSquaring.init(mRsaPublicKekForSquare, Cipher.MODE_ENCRYPT);
		mRsaCipherForSquaring.doFinal(x, xOffset, LENGTH_SQUARE_MULT_MODULUS, x,
				xOffset); // OK

		/**
		 * compute x^2
		 */
		mRsaCipherForSquaring.doFinal(tempBuffer, tempOutoffset, LENGTH_SQUARE_MULT_MODULUS, tempBuffer, tempOutoffset); // OK

		/**
		 * compute (x+y)^2 - x^2
		 */
		if (subtract(x, xOffset, LENGTH_MODULUS, tempBuffer, tempOutoffset,
				LENGTH_MODULUS)) {
			add(x, xOffset, LENGTH_MODULUS, CurveConstants.SecP192r1_P_ForRSA,
					(short) 0x00, LENGTH_MODULUS);
		} // OK

		/**
		 * compute y^2
		 */
		mRsaCipherForSquaring.doFinal(y, yOffset, yLength, y, yOffset); //OK

		
		/**
		 * compute (x+y)^2 - x^2 - y^2
		 */

		if (subtract(x, xOffset, LENGTH_MODULUS, y, yOffset,
				LENGTH_MODULUS)) {

			add(x, xOffset, LENGTH_MODULUS, CurveConstants.SecP192r1_P_ForRSA,
					(short) 0x00, LENGTH_MODULUS);

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
