/**
 * 
 */
package at.fhooe.usmile.securechannel.ecsc_srp;

import javacard.framework.APDU;
import javacard.framework.CardException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * @author Endalkachew Asnake
 * 
 */
public class UsmileSecureChannel {

	private byte[] currentStage;
	private UsmileKeyAgreement usmileKeyAgreement;
	private SecureMessaging usmileSecureMessaging;
	
	static private byte connectionTries;
	 
	private byte[] sessionState;
 	
	byte[] temp_outputBuf;
 
 	private static final byte INS_KEY_AGREEMENT_01 = 0x01;
 	private static final byte INS_KEY_AGREEMENT_02 = 0x03;
 	
 	private static final byte INS_PASSWORD_CHANGE = 0x04;
	
	private static final byte MAX_PASSWORD_TRY_LIMIT = 0x05;
	
	private static final byte[] SW_OK = new byte[]{(byte)0x90, 0x00};
	
	private static final  short SW_BLOCKED = 0x0100;
	//private static final  short SW_FAILED = 0x0110;
 
	/**
	 * Constructor
	 * 
	 * Performs required initialization and required memory allocations for the secure channel
	 * <p>This method has to be called only during Applet installation
	 * 
	 * @param initData global byte array buffer containing install parameter (userid:password)
	 * @param offset offset of install parameter in the initData
	 * @param length length of the install parameter
	 */
	public UsmileSecureChannel(byte[] initData, short offset, short length) {
	  
		temp_outputBuf = JCSystem.makeTransientByteArray((short)0x300, JCSystem.CLEAR_ON_DESELECT);
		
		Util.arrayCopy(initData, offset, temp_outputBuf, (short)0x00, length);
		
		usmileKeyAgreement = new UsmileKeyAgreement(temp_outputBuf, length);

		sessionState = JCSystem.makeTransientByteArray((short) 0x01,
				JCSystem.CLEAR_ON_DESELECT);
 
		usmileSecureMessaging = new SecureMessaging(temp_outputBuf);
		connectionTries = 0x00;

		currentStage = JCSystem.makeTransientByteArray((short) 0x01,
				JCSystem.CLEAR_ON_DESELECT);
		
	}

	/**
	 * Checks the current state of the secure channel session
	 * 
	 * @return true if secure channel session is established, false otherwise
	 */
	public boolean isSessionSecure() {
		if (sessionState[0] == 0x01) {
			return true;
		}
		return false;
	}

	/**
	 * resets the state of the secure channel session
	 * 
	 */
	public void resetSessionState() {
		sessionState[0] = 0x00;
		Util.arrayFillNonAtomic(temp_outputBuf, (short)0x00, (short)0x340, (byte)0x00);
	}

	/**
	 * Handles all key agreement (secure channel initialization) operation according to the current state of the secure channel
	 * 
	 * @param apdu apdu reference for the APDU object used by this Applet
	 * @param incomingBuf reference to the APDU buffer that contains key agreement (secure channel initialization) data
	 * @throws CardException 
	 */
	public void establishSecureSession(APDU apdu, byte[] incomingBuf) {

		byte ins = incomingBuf[ISO7816.OFFSET_INS];
	 		if ((connectionTries < MAX_PASSWORD_TRY_LIMIT) ) {

			switch (ins) {
			case INS_KEY_AGREEMENT_01: 
				Util.arrayFillNonAtomic(temp_outputBuf, (short)0x00, (short)0x300, (byte)0x00);
				currentStage[(short) 0x00] = 0x00;
				if(usmileKeyAgreement.initWithSRP(apdu, incomingBuf)){
					currentStage[(short) 0x00] = 0x01;
				}
				break; 
				
			case INS_KEY_AGREEMENT_02:
				if (currentStage[(short) 0x00] == 0x01) {
					 connectionTries++;
				  
					if (usmileKeyAgreement.authenticate(apdu, incomingBuf)){
				 
						currentStage[(short) 0x00] = 0x02;
						usmileSecureMessaging.initSecureMessaging(temp_outputBuf, (short)0x00, (short)0x20); 	 
						
						if(incomingBuf[ISO7816.OFFSET_P1] == INS_PASSWORD_CHANGE){
							currentStage[(short) 0x00] = 0x03;
						}else{	
							sessionState[0] = 0x01;  
							connectionTries = (byte)0x00;
						}
					} else {
						ISOException.throwIt(ISO7816.SW_DATA_INVALID);
					}
				}
				break; 
			case INS_PASSWORD_CHANGE:
				/**
				 * for changing password 
				 * in the authentication stage if INS and P1 are set 04 ... calculate key agreement static values again
				 * 
				 * and reset the session. Session has to be reestablished using the new password
				 */
				if(currentStage[ 0x00] == 0x03){
					
					short len = usmileSecureMessaging.unwrapApdu(incomingBuf, (short)(incomingBuf[ISO7816.OFFSET_LC] & 0xff));
					
					Util.arrayFillNonAtomic(temp_outputBuf, (short)0x00, (short)0x340, (byte)0x00);
					
					Util.arrayCopy(incomingBuf, ISO7816.OFFSET_CDATA, temp_outputBuf, (short)0x00, len);
					
					/**
					 * clear password from the incoming buffer
					 */
					Util.arrayFillNonAtomic(incomingBuf, ISO7816.OFFSET_CDATA, len, (byte)0x00);
					
					usmileKeyAgreement.staticComputations(temp_outputBuf, (byte) 0, len);
					
					currentStage[(short) 0x00] = 0x00;
					
					connectionTries = (byte)0x00;
					
					resetSessionState();
				} 
				break;
			default:
				break;
			}
		} else if (connectionTries >= MAX_PASSWORD_TRY_LIMIT ) {
			// terminate ...
			 
			ISOException.throwIt(SW_BLOCKED);
		}  
	}

	/** 
	 * processes incoming ISO/IEC 7816 secure messaging Command APDU buffer and
	 * updates the the input buffer with decoded Command APDU buffer
	 * 
	 * @param incomingBuffer incoming secure messaging Command APDU buffer
	 * @param length length of the Command APDU excluding LE byte (this value is obtained from APDU.setIncomingAndReceiveMethod)
	 * @return the length of the decoded command data (LC)
	 */
	public short decodeIncoming(APDU apdu, byte[] incomingBuffer, short length) {

		short len = usmileSecureMessaging.unwrapApdu(incomingBuffer, length); 
		return len;
	}

	/**
	 * Constructs an ISO/IEC 7816-4 secure messaging response buffer
	 * 
	 * @param apdu
	 * @param inputBuffer byte array buffer containing the response data
	 * @param offset the offset of response data in inputBuffer
	 * @param length length of the response data   
	 */
	public void encodeAndSend(APDU apdu, byte[] incomingBuffer, short offset, short length) {
		// byte[] buf = apdu.getBuffer();
 		short len = usmileSecureMessaging.wrapApdu(incomingBuffer, offset, length, SW_OK, incomingBuffer, (short) 0x00) ; 			 
		apdu.setOutgoingAndSend((short) 0x00, len);
	}

}
