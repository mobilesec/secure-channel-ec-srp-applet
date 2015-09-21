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
		ecPoint.setFieldFP(CurveConstants.P, BAS, (short)24);
		ecPoint.setA(CurveConstants.A, BAS, (short)24);
		ecPoint.setB(CurveConstants.B, BAS, (short)24);
		ecPoint.setG(CurveConstants.G, BAS, (short)49);
		ecPoint.setK(CurveConstants.H);
		ecPoint.setR(CurveConstants.N, BAS, (short)24);
	}
}
