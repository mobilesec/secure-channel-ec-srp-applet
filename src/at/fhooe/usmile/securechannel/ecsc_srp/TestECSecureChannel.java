package at.fhooe.usmile.securechannel.ecsc_srp;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;

public class TestECSecureChannel extends Applet {

	private UsmileSecureChannel usChannel;  
	
	public TestECSecureChannel(byte[] bArray, short bOffset, byte bLength){
		
	    byte iLen = bArray[bOffset]; // aid length
	    bOffset = (short) (bOffset+iLen+1);
	    byte cLen = bArray[bOffset]; // info length
	    bOffset = (short) (bOffset+cLen+1);
	    byte aLen = bArray[bOffset]; // applet data length
	
	    usChannel = new UsmileSecureChannel(bArray, (short) (bOffset + 1), (short)aLen);
		
		register();
	}
		
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new TestECSecureChannel( bArray, bOffset,  bLength);
		
	}
	
	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) { 	
			return;
		}
		byte[] incomingBuf = apdu.getBuffer(); 
		short length = apdu.setIncomingAndReceive();
		if(!usChannel.isSessionSecure()){
			usChannel.establishSecureSession(apdu, incomingBuf);
		}else{
			if(incomingBuf[ISO7816.OFFSET_INS] == 0x20){
				usChannel.resetSessionState();
			}else{
				short decodedLC = usChannel.decodeIncoming(apdu, incomingBuf, length);
				if(decodedLC >   0){ 		
			 		usChannel.encodeAndSend(apdu, incomingBuf, ISO7816.OFFSET_CDATA, (short)(incomingBuf[ISO7816.OFFSET_LC] & 0x00FF));
				}
			}
		}
	}
}
