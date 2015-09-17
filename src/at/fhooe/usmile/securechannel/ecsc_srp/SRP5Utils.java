package at.fhooe.usmile.securechannel.ecsc_srp;

import javacard.security.ECKey;

import com.nxp.id.jcopx.ECPoint;

public class SRP5Utils {

	final static short BAS = 0;
	
	public static short GE2OSPX(ECPoint ecPoint, byte[] buffer, byte offset){
		short ecPointLength=ecPoint.getW(buffer, (short) (offset+0x01));
		buffer[0] = (byte)0x01;
		return (short) (ecPointLength+1); 
	}

	public static void initializeECPoint(ECKey ecPoint) {
		ecPoint.setFieldFP(CurveConstants.SecP192r1_P, BAS, (short)24);
		ecPoint.setA(CurveConstants.SecP192r1_A, BAS, (short)24);
		ecPoint.setB(CurveConstants.SecP192r1_B, BAS, (short)24);
		ecPoint.setG(CurveConstants.SecP192r1_G, BAS, (short)49);
		ecPoint.setK(CurveConstants.SecP192r1_H);
		ecPoint.setR(CurveConstants.SecP192r1_N, BAS, (short)24);
	}
}
