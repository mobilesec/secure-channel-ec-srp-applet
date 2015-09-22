package at.fhooe.usmile.securechannel.ecsc_srp;

import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class SecureMessaging {

	private AESKey mEncryptionKey;
	private AESKey mMackey_1;
	private AESKey mMackey_2;

	private Cipher mAESCipher;

	private byte[] tempBuffer;

	private static final short ENC_KEY_SIZE = (short) 0x20;

	private MessageDigest msgDigest_SHA256;

	private static final short OFFSET_MAC_KEY_1 = (short) 0x2E0;
	private static final short OFFSET_MAC_KEY_2 = (short) 0x2F0;
	private static final short OFFSET_ENC_KEY = (short) 0x2C0;
	private static final short OFFSET_IV = (short) 0x2B0;

	private static final short OFFSET_SEND_SEQUENCE_COUNTER = (short) 0x0E;
	private static final short OFFSET_TEMP_DATA = (short)0x10;
	private static final short OFFSET_ZERO_IV = (short) 0x290;

	private static final short BLOCK_SIZE = 0x10;
	private static final short LENGTH_HEADER = 0x04;
	private static final short LENGTH_CHECK_SUM = 0x08;
	private static final short OFFSET_INCOMING_DO87 = 0x05;
	private static final short OFFSET_INCOMING_ENCRYPTED_DATA = 0x08;
	private static final short OFFSET_OUTGOING_ENCRYPTED_DATA = 0x13;
	private static final short LENGTH_DO99 = 0x04;

	private static final byte[] c1 = new byte[] { 0x01 };
	private static final byte[] c2 = new byte[] { 0x02 };

	private static short ssc;
	private Signature mSignature;

	/**
	 * Constructor
	 * 
	 * @param _tempBuffer a reference for Transient byte array buffer that is used for intermediate operations 
	 */
	public SecureMessaging(byte[] _tempBuffer) {
		tempBuffer = _tempBuffer;

		mEncryptionKey = (AESKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_AES_256, false);

		mMackey_1 = (AESKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_AES_128, false);

		mMackey_2 = (AESKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_AES_128, false);

		// iv = new byte[(short)0x10];

		mAESCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,
				false);

		msgDigest_SHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256,
				false);

		mSignature = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD,
				false);

	} 
	
	/**
	 * Initializes secure messaging with key obtained from the key agreement
	 * 
	 * @param buffer  byte array buffer containing secure session (Secure messaging) base key and IV
	 * @param offsetKey offset of base key in the buffer
	 * @param offsetIV offset of the IV in the buffer
	 */
	public void initSecureMessaging(byte[] buffer, short offsetKey,
			short offsetIV) {

		msgDigest_SHA256.update(buffer, offsetKey, ENC_KEY_SIZE);
		msgDigest_SHA256.doFinal(c1, (short) 0x00, (short) 0x01, tempBuffer,
				OFFSET_ENC_KEY);

		msgDigest_SHA256.update(buffer, offsetKey, ENC_KEY_SIZE);
		msgDigest_SHA256.doFinal(c2, (short) 0x00, (short) 0x01, tempBuffer,
				OFFSET_MAC_KEY_1);

		mEncryptionKey.setKey(tempBuffer, OFFSET_ENC_KEY);
		mMackey_1.setKey(tempBuffer, OFFSET_MAC_KEY_1);
		mMackey_2.setKey(tempBuffer, OFFSET_MAC_KEY_2);

		Util.arrayCopy(buffer, offsetIV, tempBuffer, OFFSET_IV, (short) 0x10);
		Util.arrayFillNonAtomic(tempBuffer, (short) 0x00, (short) 0x2B0,
				(byte) 0x00);
		ssc = (short) 0x0000;
		Util.setShort(tempBuffer, OFFSET_SEND_SEQUENCE_COUNTER, ssc);

	}

	/**
	 * processes incoming ISO/IEC 7816 secure messaging Command APDU buffer
	 * according to ETSI TS 102 176-2 and updates the input with decoded Command APDU
	 * 
	 * @param incomingBuffer incoming Command APDU buffer
	 * @param length length of the Command APDU excluding LE byte (this value is obtained from APDU.setIncomingAndReceiveMethod)
	 * @return the length of the decoded command data (LC)
	 */
	public short unwrapApdu(byte[] incomingBuffer, short length) {

		/**
		 * copy command header and pad new size = BLOCK Length since the header
		 * is always constant (0x04)
		 */
		Util.arrayCopy(incomingBuffer, (short) 0x00, tempBuffer, OFFSET_TEMP_DATA,
				LENGTH_HEADER);
		short currentTempBuffOffset = get_ISO7816_Padded(tempBuffer, (short)0x00,
				(short) (OFFSET_TEMP_DATA + LENGTH_HEADER));
		 
		/**
		 * append DO87 to padded header
		 */
		short lenD087 = (short) ((incomingBuffer[(short) (OFFSET_INCOMING_DO87 + 1)] & 0x00FF) + 2);
		short lenEncryptedData = (short) (lenD087 - 3);

		Util.arrayCopy(incomingBuffer, OFFSET_INCOMING_DO87, tempBuffer,
				currentTempBuffOffset, lenD087);

		/**
		 * append DO97 and padd tempbuffer
		 */
		currentTempBuffOffset = (short) (currentTempBuffOffset + lenD087);
		short offsetDO97 = (short) (lenD087 + OFFSET_INCOMING_DO87);
		Util.arrayCopy(incomingBuffer, offsetDO97, tempBuffer, currentTempBuffOffset,
				(short) 0x03);

		currentTempBuffOffset = (short) (currentTempBuffOffset + 3);
		currentTempBuffOffset = get_ISO7816_Padded(tempBuffer, (short) 0x00,
				currentTempBuffOffset);

		/**
		 * compute checksum and compare
		 */
		computeChecksum_CMAC_with_AES_CBC_Signature(tempBuffer, (short) 0x00,
				currentTempBuffOffset, tempBuffer, currentTempBuffOffset);
		short offsetIncomingCheckSum = (short) (offsetDO97 + 5);
		if (Util.arrayCompare(incomingBuffer, offsetIncomingCheckSum,
				tempBuffer, currentTempBuffOffset , LENGTH_CHECK_SUM) == 0x00) {
			// decrypt apdu
			short lenPaddedData = decrypt(incomingBuffer,
					OFFSET_INCOMING_ENCRYPTED_DATA, lenEncryptedData,
					incomingBuffer, ISO7816.OFFSET_CDATA);
			short originalLC = get_ISO7816_unPadded(incomingBuffer,
					ISO7816.OFFSET_CDATA, lenPaddedData);
			incomingBuffer[ISO7816.OFFSET_LC] = (byte) (originalLC & 0x00ff);
			return originalLC;
		} else {
			// exception checksum error
		}

		return (short) 0;
	}

	/**
	 * Constructs an ISO/IEC 7816-4 secure messaging response buffer with ETSI TS 102 176-2 format
	 * 
	 * @param inputBuffer byte array buffer containing the response data
	 * @param offset the offset of response data in inputBuffer
	 * @param length length of the response data
	 * @param SW status word
	 * @param output byte array buffer to be updated with secure messaging response APDU
	 * @param outOffset the offset in output buffer for updating with secure messaging response APDU
	 * @return The length of the encoded (secure messaging) response APDU buffer
	 * 
	 */

	public short wrapApdu(byte[] inputBuffer, short offset, short length,
			byte[] SW, byte[] output, short outOffset) {
		Util.arrayCopy(inputBuffer, offset, tempBuffer,
				OFFSET_OUTGOING_ENCRYPTED_DATA, length);

		/**
		 * padd and encrypt data
		 */
		short lenData = get_ISO7816_Padded(tempBuffer,
				OFFSET_OUTGOING_ENCRYPTED_DATA, length);
		lenData = encrypt(tempBuffer, OFFSET_OUTGOING_ENCRYPTED_DATA, lenData,
				tempBuffer, OFFSET_OUTGOING_ENCRYPTED_DATA);
		// form D087 TLV
		tempBuffer[0x10] = (byte) 0x87;
		tempBuffer[0x11] = (byte) ((short) (lenData + 1) & 0x00ff);
		tempBuffer[0x12] = (byte) 0x01;

		/**
		 * form DO99 TLV
		 */
		short offsetDO99 = (short) (lenData + OFFSET_OUTGOING_ENCRYPTED_DATA);
		tempBuffer[offsetDO99] = (byte) 0x99;
		tempBuffer[(short) (offsetDO99 + 1)] = (byte) 0x02;
		Util.arrayCopy(SW, (short) 0x00, tempBuffer, (short) (offsetDO99 + 2),
				(short) 0x02);

		/**
		 * pad and compute checksum
		 */
		short paddedLen = get_ISO7816_Padded(tempBuffer, (short) 0x00,
				(short) (offsetDO99 + LENGTH_DO99));
		computeChecksum_CMAC_with_AES_CBC_Signature(tempBuffer, (short) 0x00,
				paddedLen, tempBuffer, paddedLen);

		/**
		 * form DO8E TLV
		 */
		short offsetDO8E = (short) (offsetDO99 + LENGTH_DO99);
		tempBuffer[offsetDO8E] = (byte) 0x8E;
		tempBuffer[(short) (offsetDO8E + 1)] = (byte) LENGTH_CHECK_SUM;
		Util.arrayCopy(tempBuffer, paddedLen , tempBuffer,
				(short) (offsetDO8E + 2), LENGTH_CHECK_SUM);

		/**
		 * copy result to output
		 */
		short lenWrapped = (short) (offsetDO8E + 2 + LENGTH_CHECK_SUM - OFFSET_TEMP_DATA );
		Util.arrayCopy(tempBuffer, OFFSET_TEMP_DATA, output, outOffset, lenWrapped);
		return lenWrapped;

	}

	/**
	 * Calculates MAC over input using AES-CMAC-128 according to RFC 4493 
	 * 
	 * <p>
	 * The last block to this input is always padded as specified in ETSI TS 102 176-2. 
	 * Therefore only one Mac subkey is used for XORing the last block. 
	 *  
	 * @param input  byte array buffer containing the data over which MAC is computed
	 * @param offset offset of data in the input buffer
	 * @param length length of the data
	 * @param output output byte array buffer
	 * @param outOffset offset in the output for MAC value
	 */

	public void computeChecksum_CMAC_with_AES_CBC_Signature(byte[] input,
			short offset, short length, byte[] output, short outOffset) {
		if (length % BLOCK_SIZE != 0) {
			// exception incorrect input block size
			return;
		}
		if (ssc == (short) 0x0fff) {
			// exception max counter ... re-establish secure session
			return;
		}
		ssc++;
		Util.setShort(tempBuffer, OFFSET_SEND_SEQUENCE_COUNTER, ssc);
		
	 	mSignature.init(mMackey_1, Signature.MODE_SIGN, tempBuffer,
	 			OFFSET_ZERO_IV, BLOCK_SIZE);

		short len = (short) (length - BLOCK_SIZE);
		short i = 0;
		short lastBlockOffset = (short) (offset + len);
		/**
		 * save copy of the last block before modifying
		 */
		Util.arrayCopy(input, lastBlockOffset, output, (short)(outOffset + (short)0x10), BLOCK_SIZE);
		while (i < BLOCK_SIZE) {
			input[(short) (lastBlockOffset + i)] = (byte) (input[(short) (lastBlockOffset + i)] ^ tempBuffer[(short) (OFFSET_MAC_KEY_2 + i)]);
			i++;
		}
	  
		/**
		 * sign
		 */	
		 mSignature.sign(input, offset, length, output, outOffset);
		/**
		 * restore last block
		 */
		 Util.arrayCopy(input,(short)(outOffset + (short)0x10) , output, lastBlockOffset, BLOCK_SIZE);
	}

	/**
	 * 
	 * Performs AES encryption with 256 bit Encryption Key and Random IV
	 * 
	 * @param data
	 * @param offset
	 * @param length
	 * @param output
	 * @param offsetOut
	 * @return
	 */
	public short encrypt(byte[] data, short offset, short length,
			byte[] output, short offsetOut) {
		mAESCipher.init(mEncryptionKey, Cipher.MODE_ENCRYPT, tempBuffer,
				OFFSET_IV, (short) 0x10);
		short len = mAESCipher.doFinal(data, offset, length, output, offsetOut);
		return len;
	}

	/**
	 * Performs AES decryption with 256 bit Encryption Key and Random IV
	 * 
	 * @param cipher
	 * @param offset
	 * @param length
	 * @param output
	 * @param offsetOut
	 * @return
	 */
	public short decrypt(byte[] cipher, short offset, short length,
			byte[] output, short offsetOut) {
		mAESCipher.init(mEncryptionKey, Cipher.MODE_DECRYPT, tempBuffer,
				OFFSET_IV, (short) 0x10);
		short len = mAESCipher.doFinal(cipher, offset, length, output,
				offsetOut);
		return len;
	}

 
	/**
	 * Performs padding of input according to ISO7816
	 * 
	 * @param unpadded
	 * @param offset
	 * @param length
	 * @return new length of the padded value
	 */
	public short get_ISO7816_Padded(byte[] unpadded, short offset, short length) {
		short padLength = (short) (0x10 - (length % 0x10));
		Util.arrayFillNonAtomic(unpadded, (short) (offset + length),
				(short) padLength, (byte) 0x00);
		unpadded[(short) (offset + length)] = (byte) 0x80;
		return (short) (padLength + length);

	}

	/**
	 * 
	 * Removes ISO7816 specified padding from input
	 * 
	 * @param padded
	 * @param offset
	 * @param length
	 * @return new length without padding
	 */
	public short get_ISO7816_unPadded(byte[] padded, short offset, short length) {
		short unpaddedLen = -1;
		for (short i = (short) ((short) (offset + length) - 1); i >= offset; i--) {
			if (padded[i] == (byte) 0x80) {
				unpaddedLen = (short) (i - offset);
				break;
			}
		}
		if (unpaddedLen == -1) {
			// padding exception
		}
		return unpaddedLen;
	}

	
/**
 * ============================= The following three methods are optional ways of computing MAC ======================
 * ============================= left only for the purpose of documentation  	======================================
 * ============================= the are not useful in the current implementation ====================================
 * 	
 */
	
	/**
	 *  N.B. This method is not used in the current implementation
	 * 
	 * Calculates MAC over input according to ETSI TS 102 176-2 - Which uses CBC
	 * MAC with Encryption of Last Block the MAC is constructed using AES CBC
	 * cipher (ISO/IEC 9797 Mac algorithm 2)
	 * 
	 * @param input
	 * @param offset
	 * @param length
	 * @param output
	 * @param outOffset
	 */

	public void computeChecksum_CBC_MAC_with_AES_CBC_Cipher(byte[] input,
			short offset, short length, byte[] output, short outOffset) {
		if (length % BLOCK_SIZE != 0) {
			// exception incorrect input block size
			return;
		}
		if (ssc == (short) 0x0fff) {
			// exception max counter ... re-establish secure session
			return;
		}
		ssc++;
		Util.setShort(tempBuffer, OFFSET_SEND_SEQUENCE_COUNTER, ssc);
		 
		short len = (short) (length / BLOCK_SIZE);
		short xIndex = offset;
		/**
		 * make sure the output is set to 0 ... because block chain starts with 0 IV
		 */
		Util.arrayFillNonAtomic(output, outOffset, BLOCK_SIZE, (byte)0x00);
		 
		for (short i = 0; i < len; i++) {
			 
			mAESCipher.init(mMackey_1, Cipher.MODE_ENCRYPT, output,
					outOffset, BLOCK_SIZE);
			mAESCipher.doFinal(tempBuffer, xIndex , BLOCK_SIZE, output, outOffset);
 	 
			xIndex = (short) (xIndex + BLOCK_SIZE);
		}
		mAESCipher.init(mMackey_2, Cipher.MODE_ENCRYPT, tempBuffer,
				OFFSET_ZERO_IV, BLOCK_SIZE);
		mAESCipher.doFinal(output, outOffset , BLOCK_SIZE, output, outOffset);

	}

	/**
	 * 
	 *   N.B. This method is not used in the current implementation
	 * 
	 * Calculates MAC over input according to ETSI TS 102 176-2 - Which uses CBC
	 * MAC with Encryption of Last Block constructed from AES CBC Signature and
	 * AES Cipher for encrypting the last output is more efficient compared to
	 * using using only AES Cipher
	 * 
	 * @param input
	 * @param offset
	 * @param length
	 * @param output
	 * @param outOffset
	 */

	public void computeChecksum_CBC_MAC_from_AES_CBCSignature(byte[] input,
			short offset, short length, byte[] output, short outOffset) {
		if (length % BLOCK_SIZE != 0) {
			// exception incorrect input block size
			return;
		}
		if (ssc == (short) 0x0fff) {
			// exception max counter ... re-establish secure session
			return;
		}
		ssc++;
		Util.setShort(tempBuffer, OFFSET_SEND_SEQUENCE_COUNTER, ssc);
		/**
		 * sign with CBC
		 */
		mSignature.init(mMackey_1, Signature.MODE_SIGN, tempBuffer,
				OFFSET_ZERO_IV, BLOCK_SIZE);
		
		mSignature.sign(input, offset, length, output, outOffset);
		/**
		 * encrypt the output with sub key 2
		 */
		mAESCipher.init(mMackey_2, Cipher.MODE_ENCRYPT, tempBuffer,
				OFFSET_ZERO_IV, BLOCK_SIZE);
		mAESCipher.doFinal(output, outOffset , BLOCK_SIZE, output, outOffset);

	}

	/**
	 *  N.B. This method is not used in the current implementation
	 *  
	 * Calculates MAC over input according to RFC 4493 - The last block to this
	 * input is always padded as specified in ETSI TS 102 176-2. There for The
	 * second Mac sub key is XORed with the last block before encryption
	 * 
	 * @param input
	 * @param offset
	 * @param length
	 * @param output
	 * @param outOffset
	 */
	public void computeChecksum_CMAC_with_AES_CBC_Cipher(byte[] input,
			short offset, short length, byte[] output, short outOffset) {
		if (length % BLOCK_SIZE != 0) {
			// exception incorrect input block size
			return;
		}
		if (ssc == (short) 0x0fff) {
			// exception max counter ... re-establish secure session
			return;
		}
		ssc++;
		Util.setShort(tempBuffer, OFFSET_SEND_SEQUENCE_COUNTER, ssc);
    
		short len = (short) (length / BLOCK_SIZE);
		short xIndex = offset;
		mAESCipher.init(mMackey_1, Cipher.MODE_ENCRYPT, tempBuffer,
				OFFSET_ZERO_IV, BLOCK_SIZE);
		for (short i = 0; i < len; i++) {
			
			if (i == (short) (len - 1)) {
				short j = 0;
				while (j < BLOCK_SIZE) {
					output[(short) (outOffset + j)] = (byte) (output[(short) (outOffset + j)] ^ tempBuffer[(short) (OFFSET_MAC_KEY_2 + j)]);
					j++;
				}
				mAESCipher.doFinal(tempBuffer, outOffset , BLOCK_SIZE, output, outOffset);
				return;
			} 
			
			mAESCipher.update(tempBuffer, xIndex , BLOCK_SIZE, output, outOffset);
 	 
			xIndex = (short) (xIndex + BLOCK_SIZE);
		}
	}

	
	
}
