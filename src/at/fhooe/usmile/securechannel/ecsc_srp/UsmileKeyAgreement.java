package at.fhooe.usmile.securechannel.ecsc_srp;

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
	 * Size of the SRP modulus
	 */
	private final static short LENGTH_MODULUS = CurveConstants.MODULUS_SIZE;

	// An EC point consists of two coordinates one preceding tag indicating if the point is compressed
	private static final short LENGTH_EC_POINT = LENGTH_MODULUS * 2 + 1;
	
	/**
	 * RSA object definition for modulo exponentiation
	 */
	// RSA Modulus size used for modulo exponentiation
	private static final short LENGTH_RSAOBJECT_MODULUS = 64; // in bytes
	
	// Amount of required padding zeros for modulo exponentiation
	private static final short LENGTH_PADDING_FOR_SQUARE_MULT = 
			(LENGTH_RSAOBJECT_MODULUS - LENGTH_MODULUS) / 2;
	
	private final static byte[] SQUARE_EXPONENT = new byte[] { 0x02 };
	

	/**
	 * Define the maximum amount of attempts to find a point on the curve in the REDP-1 function
	 */
	private static final byte REDP_MAX_INCREASE = 10;
	
	/**
	 * Length definitions for ciphers/hashes 
	 */
	// Size of used message digest
	private final static short LENGTH_MESSAGE_DIGEST = (short) 0x20;

	// Initialization Vector size and offset in APDU command sent by card
	private final static short LENGTH_IV = (short) 0x10;
	private final static short OFFSET_IV = (short) 0x20;

	// Length of used salt
	private final static byte LENGTH_SALT = 0x10;


	/**
	 * Offset for the temporary buffer 
	 */
	private final static short TEMP_OFFSET_S = (short) 0x100;
	private final static short TEMP_OFFSET_u = TEMP_OFFSET_S + LENGTH_EC_POINT; // 0x100 + 0x31
	private final static short TEMP_OFFSET_P = TEMP_OFFSET_u + LENGTH_MESSAGE_DIGEST; // 0x131 + 0x20

	/**
	 * Cipher/Hashing objects
	 */
	private RandomData mSaltGenerator;

	private MessageDigest mUsedMsgDigest; 
	
	// Cipher objects for modulo exponentiation 
	private Cipher mRsaCipherForSquaring;
	private Cipher mRsaCipherModPow;
		
	// RSA key objects for modulo exponentiation
	private RSAPublicKey mRsaPublicKekForSquare;
	private RSAPublicKey mRsaPublicKeyModPow;

	// Elliptic Curve points as public/private key pair (Q_B, d_B)
	private KeyPair mECKeyPairGenerator; 
	private ECPoint mLocalECPublicKey; // Q_B
	private ECPrivateKey mLocalECPrivateKey; // d_B
	
	// Helper objects for Elliptic Curve Point multiplications in EC-SRP
	private KeyAgreement mECMultiplHelper;
	private ECPrivateKey mECMultiplHelperPrivatePoint;
	
	// Helper object for Elliptic Curve Point additions in EC-SRP
	private ECPoint mNxpPointForECAddition;
	/**
	 * Temporary buffer for fast data processing
	 */
	private byte[] tempBuffer;
	
	/**
	 * Static data, should not be changed often 
	 */
	// Password verifier
	private static byte[] mV_Pi;
	// Static salt for user and password identifiers
	private static byte[] mSalt;
	// Pseudo-randomly generated EC point from password verify V_Pi
	private static byte[] mREDP; 

	// Curve Polynom
	private static Bignat mCurveP; 
		
	/**
	 * Constructors
	 * 
	 * <p>
	 * Performs necessary initialization and memory allocations
	 * 
	 * @param initBuffer
	 *            initialization byte array buffer, contains identity':'password
	 * @param length Length of ID and password
	 * 
	 */
	public UsmileKeyAgreement(byte[] initBuffer, short length) {

		tempBuffer = initBuffer;

		/**
		 * init messageDigest
		 */
		mUsedMsgDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256,
				false);
		
		// Initialize all key objects
		initializeKeys();
		
		// Compute all values which will not change during key agreement and verification phase
		staticComputations(tempBuffer, (short)0, length);
	}

	private void initializeKeys() {
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

		// Copy P of used curve to temporary transient memory for faster computation (used several times)
		Util.arrayCopy(CurveConstants.P_forRSAOperation, (short) 0x00, tempBuffer, TEMP_OFFSET_P,
				LENGTH_MODULUS);
		
		/**
		 * set public key modulus
		 */
		mRsaPublicKekForSquare.setModulus(tempBuffer, TEMP_OFFSET_P, (short) LENGTH_RSAOBJECT_MODULUS);
		mRsaPublicKeyModPow.setModulus(tempBuffer, TEMP_OFFSET_P, (short) LENGTH_RSAOBJECT_MODULUS);

		/**
		 * Initialize static values for key agreement
		 */
		mV_Pi = new byte[(short) LENGTH_EC_POINT];
		mREDP = new byte[(short) LENGTH_EC_POINT];
		mSalt = new byte[(short) 0x10];

		/**
		 * Initialize point and agreement scheme for Elliptic curve multiplication
		 */
		mECMultiplHelperPrivatePoint = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, false);
		mECMultiplHelper = KeyAgreementX.getInstance(KeyAgreementX.ALG_EC_SVDP_DH_PLAIN_XY, false);
		
		/**
		 * Initialize EC Keys for Point addition (pub keys from alice and bob)
		 */
		mNxpPointForECAddition = ECPointBuilder.buildECPoint(ECPointBuilder.TYPE_EC_FP_POINT,KeyBuilder.LENGTH_EC_FP_192);

		SRP5Utils.initializeECPoint(mNxpPointForECAddition);
		SRP5Utils.initializeECPoint(mECMultiplHelperPrivatePoint);

		/**
		 * Local public/private key pair
		 */
		mECKeyPairGenerator = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_192);
		mLocalECPrivateKey = (ECPrivateKey) mECKeyPairGenerator.getPrivate();
		mLocalECPublicKey = ECPointBuilder.buildECPoint(ECPointBuilder.TYPE_EC_FP_POINT,KeyBuilder.LENGTH_EC_FP_192);

		SRP5Utils.initializeECPoint((ECKey)mECKeyPairGenerator.getPublic());
		SRP5Utils.initializeECPoint(mLocalECPrivateKey);
		SRP5Utils.initializeECPoint(mLocalECPublicKey);
	}

	/**
	 * Computes/generates Applet side parameters that are static (session
	 * independent). This values are salt, V_pi and U_pi. Called during from the
	 * constructor of this class (at Applet installation) and for changing the
	 * secure channel password and/or user ID
	 * @param idPassword ID and password for establishing a secure channel 
	 * @param offset Offset to the ID and password array
	 * @param length Length of ID and password
	 */
	public void staticComputations(byte[] idPassword, short offset, short length){
		/**
		 * Generate salt
		 */
		mSaltGenerator.generateData(mSalt, (short) 0x00, LENGTH_SALT);

		/**
		 * compute U_Pi = OS2IP(H (salt, H(identity':'password))) mod N
		 */
		mUsedMsgDigest.doFinal(idPassword, offset, length, tempBuffer,
				(byte)0x0);
		mUsedMsgDigest.update(mSalt, (short) 0x00, LENGTH_SALT);
		mUsedMsgDigest.doFinal(tempBuffer, (byte)0x0,
				LENGTH_MESSAGE_DIGEST, tempBuffer, (short) (0x0));

		// OS2IP mod N
		Bignat i1 = new Bignat(LENGTH_MESSAGE_DIGEST, false);
		i1.from_byte_array(LENGTH_MESSAGE_DIGEST, (short) 0, tempBuffer, (short)0x0);
		Bignat bn = new Bignat((short)LENGTH_MODULUS, false);
		bn.from_byte_array(LENGTH_MODULUS, (short)0, CurveConstants.N, (short)0);

		mCurveP = new Bignat((short)LENGTH_MODULUS, false);
		mCurveP.from_byte_array(LENGTH_MODULUS, (short)0, tempBuffer, TEMP_OFFSET_P);

		
		// TODO improve computation performance of modulo operation
		i1.remainder_divide(bn, null);

		/**
		 * Precompute k = parameter for finding square root of alpha
		 */
		Bignat k = null;
		
		byte t = (byte) (mCurveP.getLastByte() & 0x03); // mod 4
		if(t == (byte)3 ){ //p = 3 mod 4
			k = new Bignat(LENGTH_MODULUS, false);
			k.copy(mCurveP);
			k.div_2();
			k.div_2();
			k.add(Bignat.valueOf(LENGTH_MODULUS, (byte)1));
			
			mRsaPublicKeyModPow.setExponent(k.as_byte_array(), (short) 0, (short) k.length());
			mRsaPublicKeyModPow.setModulus(tempBuffer, TEMP_OFFSET_P, (short) LENGTH_RSAOBJECT_MODULUS);
		} else {
			// TODO
		}
		
		/**
		 * compute V_Pi
		 */
		calculateVPi( mV_Pi, (short) (0), i1.as_byte_array(), (short) (LENGTH_MESSAGE_DIGEST-LENGTH_MODULUS), LENGTH_MODULUS);

		// Copy V_Pi to temporary buffer
		Util.arrayCopy(mV_Pi, (short) 0, tempBuffer, (short) TEMP_OFFSET_S, (short) (LENGTH_MODULUS + 1));
		tempBuffer[TEMP_OFFSET_S] = (byte)0x01;
		
		// Compute random point
		short redpLength = Redp1(tempBuffer, (short) TEMP_OFFSET_S, (short) (LENGTH_MODULUS + 1), mREDP, (short) (1));
		mREDP[0] = 0x04;
		
		// Could not compute random point, return an error
		if (redpLength == 0){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		} 
	}


	/**
	 * Initializes EC-SRP key agreement
	 * 
	 * @param apdu
	 *            reference for the APDU object used by this Applet
	 * @param incomingBuf
	 *            reference to the APDU buffer that contains the client public
	 *            key Q_A
	 * @return true if key agreement initialization completes successfully.
	 *         false if it fails
	 */
	public boolean initWithSRP(APDU apdu, byte[] incomingBuf) {
		/**
		 * Generate public/private keys
		 */
		//Generate new Private/Public key (d_B ad Q_B)
		mECKeyPairGenerator.genKeyPair();
		
		//Copy new public key values into NXP EC point (public parameter of Bob) 
		short lenW = ((ECPublicKey)mECKeyPairGenerator.getPublic()).getW(tempBuffer, (short) 0x0);
		mLocalECPublicKey.setW(tempBuffer, (short) 0x0, lenW);

		// Copy P to temporary transient memory for faster computation (used several times)
		Util.arrayCopy(CurveConstants.P_forRSAOperation, (short) 0x00, tempBuffer, TEMP_OFFSET_P,
				LENGTH_MODULUS);
		/**
		 * Initialize Q_A from incoming buffer
		 */
		mNxpPointForECAddition.setW(incomingBuf, ISO7816.OFFSET_CDATA, apdu.getIncomingLength()); // Q_A

		///////////////////// ---- PUBLIC KEY Q_B COMPUTATION ---- /////////////////////
		/**
		 * Compute Q_B = G*d_b + REDP(X(vPi))
		 */
		try{
			mLocalECPublicKey.addPoint(mREDP, (short) 0, LENGTH_EC_POINT);
		} catch(Exception e){
			incomingBuf[ISO7816.OFFSET_CLA] = (byte)0x01;
			apdu.setOutgoingAndSend(ISO7816.OFFSET_CLA, (byte)1);
		}
		
		/**
		 * Compute u = H( X (Q_A) | X (Q_B) )
		 */
		// Use Q_A
		// Only use X coordinate of Q_A and Q_B --> set first byte to 1
		incomingBuf[ISO7816.OFFSET_CDATA] = 0x01;

		mUsedMsgDigest.update(incomingBuf, (short) ISO7816.OFFSET_CDATA,
				(short) (LENGTH_MODULUS + 1));

		// Write Q_B in outgoing buffer
		mLocalECPublicKey.getW(incomingBuf, ISO7816.OFFSET_CLA);
		incomingBuf[ISO7816.OFFSET_CLA] = 0x01;
		
		// Compute u 
		mUsedMsgDigest.doFinal(incomingBuf, ISO7816.OFFSET_CLA, (short) (LENGTH_MODULUS + 1),
				tempBuffer, (short) (TEMP_OFFSET_u)); // Store the digest at OFFSET 1 so that it can be used
														// for verification
		
		// Set the description-byte of the Public ECPoint back to 4 
		incomingBuf[ISO7816.OFFSET_CLA] = 0x04;

		////////////////////// ---- SHARED SECRET COMPUTATION ---- //////////////////////
		/**
		 * Compute i2 = OS2IP ( u )
		 */
		// Reset temporary buffer
		Util.arrayFillNonAtomic(tempBuffer, (short) 0, (short)(LENGTH_RSAOBJECT_MODULUS * 2), (byte) 0);
		moduloP(tempBuffer, TEMP_OFFSET_u, tempBuffer, (byte)0);
		
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
				tempBuffer, (short) (TEMP_OFFSET_S-1 )); 	
				// Store and use X coordinate at Location of S --> 
				// start one byte before to remove leading 0x04 in hash generation
		
		/**
		 * compute K = H(S)
		 */
		mUsedMsgDigest.doFinal(tempBuffer, TEMP_OFFSET_S, LENGTH_MODULUS,
				tempBuffer, (short) 0x00); // Only use x coordinate for shared secret

		/**
		 * Return Q_B, salt and IV
		 */
		len += getSalt_and_IV(incomingBuf, (short)(ISO7816.OFFSET_CLA + LENGTH_EC_POINT));
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CLA, len);
		
		return true;
	}
	
	/**
	 * Compute V_Pi = u_Pi * G 
	 * @param dstbuffer
	 * @param offset
	 * @param uPiSrc
	 * @param uPiOffset
	 * @param length
	 * @return
	 */
	public short calculateVPi(byte[] dstbuffer, short offset, byte[] uPiSrc, short uPiOffset, short length) {
		return multiplyGeneratorPoint(dstbuffer, offset, uPiSrc, uPiOffset, length);
	}

	/**
	 * Compute the Pseudo-random EC point from the password derived hash-string o_Pi
	 * @param oPi Password derived hash string 
	 * @param offset Offset of oPi in the byte array
	 * @param length Length of oPi
	 * @param pointOutput Output buffer for the EC point
	 * @param outoffset Output offset
	 * @return Length of the EC point (0 if no point could be computed)
	 */
	public short Redp1(byte[] oPi, short offset, short length, byte[] pointOutput, short outoffset) {
		byte[] o1 = new byte[LENGTH_MESSAGE_DIGEST];
		mUsedMsgDigest.doFinal(oPi, offset, length,
				o1, (short) 0x00);
		
		// OS2IP mod N
		Bignat i1 = new Bignat(LENGTH_MESSAGE_DIGEST, false);
		i1.from_byte_array(LENGTH_MESSAGE_DIGEST, (short) 0, o1, (short)0x0);

		short outputLen = computeRandomPoint(i1, pointOutput, outoffset);
		return outputLen;
	}


	/**
	 * Compute the pseudo-random EC point from the integer representation of o_Pi (--> i1). 
	 * i1 will be increased until a pseudo random point was found or MAX_INCREASE was reached.
	 * @param i1 Integer representation of o_Pi
	 * @param outarray Output array buffer
	 * @param offset Offset of output array
	 * @return Length of the output EC point
	 */
	private short computeRandomPoint(Bignat i1, byte[] outarray,  short offset) {
		byte[] o2 = null;
		byte[] o3 = new byte[LENGTH_MESSAGE_DIGEST];
		short outputElength = 0;
		byte counter = 0; 
		
		// Try to find a random EC point
		while(counter < REDP_MAX_INCREASE && outputElength == 0) {
			Util.arrayFillNonAtomic(tempBuffer, (short) 0, (short)(LENGTH_RSAOBJECT_MODULUS *2), (byte) 0);
			Util.arrayFillNonAtomic(outarray, (short) (offset), (short) (LENGTH_MODULUS*2), (byte) 0 );
			
			o2 = getPadded(i1.as_byte_array(),(short)0,i1.length(), LENGTH_MESSAGE_DIGEST);
			mUsedMsgDigest.doFinal(o2, (short) 0, LENGTH_MESSAGE_DIGEST,
					o3, (short) 0x00);
			moduloP(o3, (short)0, tempBuffer, (byte) (0));
			
			Util.arrayCopy(tempBuffer, (short) (0), outarray, offset, LENGTH_MODULUS);
			
			if (!isZero(tempBuffer, (short)0, LENGTH_MODULUS)){
					if (Bignat.valueOf(LENGTH_MODULUS, (byte)3).same_value(mCurveP)){
						// TODO check if this case can actually occur
					} else { 
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
			    			
			    			mRsaCipherForSquaring.doFinal(tempBuffer, (short) 0, (short) (LENGTH_RSAOBJECT_MODULUS), tempBuffer, (short) 0);

			    			/**
				    		 * add a
				    		 */
			    			if(Bignat.add(tempBuffer, (short)0, LENGTH_MODULUS, CurveConstants.A, 
			    					(short)0, (short) CurveConstants.A.length)){
			    				Bignat.subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
				    					TEMP_OFFSET_P, LENGTH_MODULUS);
				    		}

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
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (LENGTH_RSAOBJECT_MODULUS), 
			    					(short) LENGTH_RSAOBJECT_MODULUS, (byte) 0 );
				    		
				    		// copy x after the current temporary buffer location
			    			Util.arrayCopy(outarray, offset, tempBuffer, 
			    					(byte) (LENGTH_RSAOBJECT_MODULUS+LENGTH_PADDING_FOR_SQUARE_MULT), LENGTH_MODULUS );
	
			    			// Multiply current value (x^2 + A) with x
				    		modMultiply(tempBuffer, (short)0, (short) (LENGTH_RSAOBJECT_MODULUS), 
				    				tempBuffer, 
				    				(short) (LENGTH_RSAOBJECT_MODULUS),LENGTH_RSAOBJECT_MODULUS, (short) (LENGTH_RSAOBJECT_MODULUS*2));

				    		/**
				    		 * (x^2 + a) * x + b
				    		 */
				    		if(Bignat.add(tempBuffer, (short)0, LENGTH_MODULUS, CurveConstants.B, 
				    				(short)0, (short) CurveConstants.B.length)){
				    			Bignat.subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
				    					TEMP_OFFSET_P, LENGTH_MODULUS);
				    		}
				    		Util.arrayCopy(tempBuffer, (short)0, tempBuffer, LENGTH_RSAOBJECT_MODULUS, LENGTH_MODULUS);
				    		
				    		// Copy alpha to buffer
				    		Util.arrayCopy(tempBuffer, (short) (0), tempBuffer, 
			    					(byte) (LENGTH_PADDING_FOR_SQUARE_MULT*2), LENGTH_MODULUS );
				    						    		
				    		// Fill padding with zeros
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (0), 
			    					(short) (LENGTH_PADDING_FOR_SQUARE_MULT*2), (byte) 0 );
				    		
				    		findSquareRoot(tempBuffer, (short)(0), 
				    				LENGTH_RSAOBJECT_MODULUS, tempBuffer, (short)(LENGTH_PADDING_FOR_SQUARE_MULT));
				    		
				    		Util.arrayCopy(tempBuffer, (short)LENGTH_PADDING_FOR_SQUARE_MULT, outarray, (short) (offset+LENGTH_MODULUS), LENGTH_MODULUS);
				    		
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (0), 
			    					(short) (LENGTH_PADDING_FOR_SQUARE_MULT), (byte) 0 );
				    		Util.arrayFillNonAtomic(tempBuffer, (short) (LENGTH_PADDING_FOR_SQUARE_MULT+LENGTH_MODULUS), 
			    					(short) (LENGTH_PADDING_FOR_SQUARE_MULT), (byte) 0 );
				    		
				    		mRsaCipherForSquaring.doFinal(tempBuffer, (short) 0, LENGTH_RSAOBJECT_MODULUS, tempBuffer, (short) 0);

				    		if(Util.arrayCompare(tempBuffer, (short) 0, tempBuffer, LENGTH_RSAOBJECT_MODULUS, LENGTH_MODULUS) == 0){
								byte mu = (byte) (i1.getLastByte() & 0x01);
								
								if(mu == 1) { // negate
									Util.arrayCopy(tempBuffer, TEMP_OFFSET_P, tempBuffer, (short) (0), LENGTH_MODULUS);
						    		if(Bignat.subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, outarray,
						    				(short) (offset+LENGTH_MODULUS), LENGTH_MODULUS)) {
						    			Bignat.add(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
						    					TEMP_OFFSET_P, LENGTH_MODULUS);
						    		}
									// TODO EC point multiply with cofactor H !

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
							outputElength = 0x01;
			    		}
				}
			} else { // isZero
				outputElength = 0;
			}
		}

		return outputElength;
	}


	/**
	 * Find the modular square root of a given large integer 
	 * (Method for finding a square root modular a prime as described in IEEE Std 1363a-2004: A.17.1.3.) 
	 * @param alpha Value of which the square root should be found
	 * @param offset Offset to alpha in the byte array
	 * @param length Length of alpha
	 * @param out Output array
	 * @param outoffset Output offset
	 */
	private void findSquareRoot(byte[] alpha, short offset, short length, byte[] out, short outoffset) {
		Bignat helper = new Bignat((short) LENGTH_RSAOBJECT_MODULUS, false);

		byte bHelper = (byte) (mCurveP.getLastByte() & 0x03); // mod 4
		if(bHelper == (byte)3 ){ //p = 3 mod 4
			mRsaCipherModPow.init(mRsaPublicKeyModPow, Cipher.MODE_ENCRYPT);
			mRsaCipherModPow.doFinal(alpha, offset, length, alpha, offset);

			// TODO can we improve this?
			helper.from_byte_array(LENGTH_RSAOBJECT_MODULUS, (short)0, alpha, offset);
			helper.remainder_divide(mCurveP, null);
			helper.to_byte_array(LENGTH_RSAOBJECT_MODULUS, (short)(LENGTH_PADDING_FOR_SQUARE_MULT*2), out, outoffset);
		} else { 
			bHelper = (byte) (mCurveP.getLastByte() & 0x07); // mod 8
			
			// TODO perform more checks and test if it is working
			if(bHelper == (byte)5){ // p = 8 mod 5
				// TODO test if this is working
//				BigInteger k = p.subtract(BigInteger.valueOf(5)).divide(BigInteger.valueOf(8));
//				BigInteger gamma = alpha.multiply(BigInteger.valueOf(2)).modPow(k, p);
//				BigInteger i = alpha.multiply(BigInteger.valueOf(2)).multiply(gamma.pow(2)).mod(p);
//				beta = alpha.multiply(gamma).multiply(i.subtract(ONE)).mod(p);
			} else if(bHelper == (byte)1){
				// TODO
			} else {
				// TODO error handling
			}
		}
	}

	/**
	 * Get padded byte array. Returns the same array if the new length is smaller or equal the old length
	 * @param n Large integer which should be padded
	 * @param offset Offset of the large integer 
	 * @param arrayLength Length of the current integer
	 * @param newlength New (padded) length of the large integer
	 * @return A new (or the same) byte array with padding. 
	 */
	private static byte[] getPadded(byte[] n, short offset, short arrayLength, short newlength) {
		byte[] bs = n;
		if (arrayLength < newlength) {
			byte[] tmp = new byte[newlength];
			Util.arrayCopy(bs, offset, tmp, (short)(newlength - arrayLength), (short) arrayLength);
			bs = tmp;
		}
		return bs;
	}
	
	/**
	 * Compute the modulus of a large integer with P (EC curve polynomial representation). 
	 * Used modular multiplication of the big integer with the value one.    
	 * @param data Data from which the modulos should be computed
	 * @param dataoffset Offset of data
	 * @param outarray Output array (should have at least LENGTH_RSAOBJECT_MODULUS size)
	 */
	private void moduloP(byte[] data, short dataoffset, byte[] outarray, byte outoffset){
		Util.arrayCopy(data, dataoffset, outarray, 
				(short)(outoffset + LENGTH_PADDING_FOR_SQUARE_MULT-(LENGTH_MESSAGE_DIGEST-LENGTH_MODULUS)), 
				LENGTH_MESSAGE_DIGEST);
		
		// Set multiplier to one (only modulo operation)
		tempBuffer[LENGTH_RSAOBJECT_MODULUS + LENGTH_PADDING_FOR_SQUARE_MULT + LENGTH_MODULUS - 1]=0x01;
		
		// Multiply data with 1 for modulo operation 
		modMultiply(outarray, outoffset, LENGTH_RSAOBJECT_MODULUS, 
				tempBuffer, LENGTH_RSAOBJECT_MODULUS, LENGTH_RSAOBJECT_MODULUS, 
				(short) (LENGTH_RSAOBJECT_MODULUS*2));
	}

	/**
	 * Check if the byte array is zero
	 * @param tempBuffer
	 * @param offset
	 * @param length
	 * @return
	 */
	private boolean isZero(byte[] tempBuffer, short offset, short length) {
		for (short i=0; i<= length;i++) {
			if(tempBuffer[(short)(offset + i)] != (short) 0x00) {
				return false;
			}
		}
		return true;
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
	public void modMultiply(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength, short tempOutoffset) {
		/**
		 * x+y
		 */
		Util.arrayCopy(x, xOffset, tempBuffer, tempOutoffset, xLength);
		if (Bignat.add(x, LENGTH_PADDING_FOR_SQUARE_MULT, (LENGTH_MODULUS), y,
				(short) (yOffset+LENGTH_PADDING_FOR_SQUARE_MULT), LENGTH_MODULUS)) {
			Bignat.subtract(x, LENGTH_PADDING_FOR_SQUARE_MULT, (LENGTH_MODULUS), tempBuffer,
					TEMP_OFFSET_P, LENGTH_MODULUS);
		} 
		
		/**
		 * (x+y)^2
		 */
		mRsaCipherForSquaring.init(mRsaPublicKekForSquare, Cipher.MODE_ENCRYPT);
		mRsaCipherForSquaring.doFinal(x, xOffset, LENGTH_RSAOBJECT_MODULUS, x,
				xOffset); // OK

		/**
		 * compute x^2
		 */
		mRsaCipherForSquaring.doFinal(tempBuffer, tempOutoffset, LENGTH_RSAOBJECT_MODULUS, tempBuffer, tempOutoffset); // OK

		/**
		 * compute (x+y)^2 - x^2
		 */
		if (Bignat.subtract(x, xOffset, LENGTH_MODULUS, tempBuffer, tempOutoffset,
				LENGTH_MODULUS)) {
			Bignat.add(x, xOffset, LENGTH_MODULUS, tempBuffer,
					TEMP_OFFSET_P, LENGTH_MODULUS);
		} 

		/**
		 * compute y^2
		 */
		mRsaCipherForSquaring.doFinal(y, yOffset, yLength, y, yOffset); //OK

		
		/**
		 * compute (x+y)^2 - x^2 - y^2
		 */

		if (Bignat.subtract(x, xOffset, LENGTH_MODULUS, y, yOffset,
				LENGTH_MODULUS)) {

			Bignat.add(x, xOffset, LENGTH_MODULUS, tempBuffer,
					TEMP_OFFSET_P, LENGTH_MODULUS);

		}

		/**
		 * divide by 2
		 */

		Bignat.modular_division_by_2(x, xOffset, LENGTH_MODULUS, tempBuffer, TEMP_OFFSET_P, CurveConstants.MODULUS_SIZE);
	}
	
	/**
	 * Multiply an EC point with any large integer. Uses the Key Agreement API of Java card.
	 * @param ecpoint The point which should be multiplied
	 * @param ecpointoffset Offset of the point in the byte array
	 * @param multiplier Large integer for multiplication
	 * @param mpoffset Offset of the large integer
	 * @param moduluslength Length of the integer
	 * @param pointOutputBuffer Output buffer
	 * @param offset Offset of the output buffer
	 * @return Length of the final EC point
	 */
	private short multiplyECPoint(byte[] ecpoint, short ecpointoffset, byte[] multiplier, short mpoffset, short moduluslength, byte[] pointOutputBuffer, short offset){
		mECMultiplHelperPrivatePoint.setS(multiplier, (short) mpoffset, moduluslength);
		
		mECMultiplHelper.init(mECMultiplHelperPrivatePoint);
		return mECMultiplHelper.generateSecret(ecpoint, ecpointoffset, (short) (moduluslength*2+1), pointOutputBuffer, offset);
	}

	/**
	 * Multiply a large integer with the used EC generator point G. Uses the Key Agreement API of Java card
	 * @param pointOutputBuffer Outputbuffer byte array
	 * @param offset Offset in output array
	 * @param multiplier Large integer for multiplication with EC point
	 * @param mpoffset Offset of large integer 
	 * @param mplength Length of the multiplier
	 * @return Length of final EC point
	 */
	private short multiplyGeneratorPoint(byte[] pointOutputBuffer, short offset, byte[] multiplier, short mpoffset, short mplength){
		return multiplyECPoint(CurveConstants.G, (short) (0), 
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
		short M_offset = (short)(TEMP_OFFSET_S - LENGTH_MESSAGE_DIGEST);
		/**
		 * compute expected authentication data M = H(o3, S)
		 */
		mUsedMsgDigest.update(tempBuffer, TEMP_OFFSET_u, LENGTH_MESSAGE_DIGEST);
		mUsedMsgDigest.doFinal(tempBuffer, TEMP_OFFSET_S, LENGTH_MODULUS,
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
					.update(tempBuffer, TEMP_OFFSET_u, (byte)LENGTH_MESSAGE_DIGEST);
			mUsedMsgDigest.doFinal(tempBuffer, M_offset, (short) (LENGTH_MODULUS + LENGTH_MESSAGE_DIGEST),
					incomingBuf, (short) ISO7816.OFFSET_CDATA);

			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (LENGTH_MESSAGE_DIGEST));
			return true;
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

}
