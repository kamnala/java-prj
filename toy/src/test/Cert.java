package test;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.SimpleTimeZone;

import com.gpki.gpkiapi.cert.CertPathValidator;
import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.cert.RevReason;
import com.gpki.gpkiapi.crypto.PrivateKey;
import com.gpki.gpkiapi.crypto.PublicKey;
import com.gpki.gpkiapi.ocsp.OCSPRequest;
import com.gpki.gpkiapi.ocsp.OCSPResponse;
import com.gpki.gpkiapi.protocol.OCSP;
import com.gpki.gpkiapi.storage.Disk;
import com.gpki.gpkiapi.util.Dump;

/*
 * Created on 2005. 9. 29.
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */

/**
 * @author tomato
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class Cert {
	
	boolean bPrintLog;
	int nErrCnt;
	
	public Cert(boolean bPrintLog) {
		this.bPrintLog = bPrintLog;
	}
	
	public int getErrCnt() {
		return nErrCnt;
	}
	
	void view() {
		
		byte[] bBuf = null;
		byte[] cert_serialNum = {(byte)0x3c, (byte)0xc2, (byte)0x81, (byte)0x4b, (byte)0x00, (byte)0xe7, 
				(byte)0x52, (byte)0x4d, (byte)0x9b, (byte)0xaa, (byte)0x47, (byte)0xb7, (byte)0xe1, (byte)0x61, 
				(byte)0xf5, (byte)0x0e};
		String cert_issDN = "cn=Root CA,ou=GPKI,o=Government of Korea,c=KR";
		String cert_notBefore = "20020421090723Z";
		String cert_notAfter = "20120421090723Z";
		String cert_subDN = "cn=Root CA,ou=GPKI,o=Government of Korea,c=KR";
		String cert_pubKeyAlg = "RSA";
		byte[] cert_pubKey = {(byte)0x30, (byte)0x82, (byte)0x01, (byte)0x21, (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01,
				(byte)0x01, (byte)0x05, (byte)0x00, (byte)0x03, (byte)0x82, (byte)0x01, (byte)0x0e, (byte)0x00, (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x09, (byte)0x02, (byte)0x82, (byte)0x01, (byte)0x00,
				(byte)0x40, (byte)0xd6, (byte)0xa1, (byte)0x42, (byte)0x17, (byte)0x2c, (byte)0x55, (byte)0x40, (byte)0xdf, (byte)0x9a, (byte)0x7a, (byte)0xc3, (byte)0x91, (byte)0xf4, (byte)0xe3, (byte)0xbd,
				(byte)0x91, (byte)0x2b, (byte)0xf5, (byte)0xdb, (byte)0x5c, (byte)0x66, (byte)0x2f, (byte)0x89, (byte)0x5c, (byte)0xfd, (byte)0x78, (byte)0xd4, (byte)0x09, (byte)0x4c, (byte)0x3d, (byte)0xa7,
				(byte)0xc4, (byte)0x9c, (byte)0x2e, (byte)0xfa, (byte)0xf0, (byte)0x59, (byte)0xb6, (byte)0xbd, (byte)0xb4, (byte)0xd2, (byte)0x8d, (byte)0x28, (byte)0x08, (byte)0xab, (byte)0xaf, (byte)0x13,
				(byte)0x41, (byte)0xae, (byte)0x80, (byte)0x42, (byte)0xf4, (byte)0xeb, (byte)0x5c, (byte)0x2d, (byte)0x5f, (byte)0x7e, (byte)0x43, (byte)0x7a, (byte)0x35, (byte)0xb5, (byte)0xaf, (byte)0x3f,
				(byte)0xdc, (byte)0xc4, (byte)0x3d, (byte)0x36, (byte)0x45, (byte)0x92, (byte)0xb2, (byte)0xb8, (byte)0x7e, (byte)0x0d, (byte)0xbc, (byte)0xac, (byte)0xc7, (byte)0xc1, (byte)0x64, (byte)0xd8,
				(byte)0xde, (byte)0x6d, (byte)0xce, (byte)0xb3, (byte)0xa4, (byte)0x8e, (byte)0x50, (byte)0x7e, (byte)0x48, (byte)0xf4, (byte)0xad, (byte)0x8e, (byte)0xd9, (byte)0x86, (byte)0x19, (byte)0x35,
				(byte)0x03, (byte)0x8a, (byte)0x77, (byte)0x28, (byte)0x75, (byte)0x2d, (byte)0x82, (byte)0x5b, (byte)0x4a, (byte)0xec, (byte)0xa5, (byte)0xcb, (byte)0x71, (byte)0x02, (byte)0xf4, (byte)0x44,
				(byte)0x31, (byte)0x83, (byte)0x4a, (byte)0x79, (byte)0xec, (byte)0xce, (byte)0x65, (byte)0xff, (byte)0x1c, (byte)0xa1, (byte)0x33, (byte)0x66, (byte)0xaf, (byte)0x5b, (byte)0x32, (byte)0x65,
				(byte)0xfe, (byte)0xe6, (byte)0xad, (byte)0x87, (byte)0x27, (byte)0x4c, (byte)0xfd, (byte)0x4f, (byte)0x18, (byte)0x09, (byte)0x98, (byte)0x64, (byte)0x7e, (byte)0x3f, (byte)0xce, (byte)0x37,
				(byte)0x56, (byte)0xf3, (byte)0xc2, (byte)0xe0, (byte)0xc6, (byte)0x99, (byte)0x9b, (byte)0x00, (byte)0x4b, (byte)0x37, (byte)0x98, (byte)0xef, (byte)0x1c, (byte)0x63, (byte)0x2a, (byte)0x95,
				(byte)0xae, (byte)0xad, (byte)0x03, (byte)0xcf, (byte)0x3a, (byte)0x5c, (byte)0x22, (byte)0x0e, (byte)0x3d, (byte)0xd9, (byte)0xf5, (byte)0x70, (byte)0x71, (byte)0x76, (byte)0xfb, (byte)0x44,
				(byte)0xcf, (byte)0x2b, (byte)0x00, (byte)0x21, (byte)0x26, (byte)0x70, (byte)0x3a, (byte)0xe1, (byte)0xaa, (byte)0xeb, (byte)0xcd, (byte)0x49, (byte)0xfb, (byte)0x3b, (byte)0x62, (byte)0xb8,
				(byte)0x74, (byte)0x5a, (byte)0x56, (byte)0xa5, (byte)0xf2, (byte)0x2c, (byte)0x92, (byte)0x3e, (byte)0xb5, (byte)0x00, (byte)0xbc, (byte)0x84, (byte)0xbf, (byte)0x60, (byte)0xe3, (byte)0x42,
				(byte)0x6e, (byte)0x8d, (byte)0xa3, (byte)0xe0, (byte)0x64, (byte)0xb6, (byte)0xad, (byte)0xa5, (byte)0x43, (byte)0x98, (byte)0xf7, (byte)0x61, (byte)0xdf, (byte)0xc5, (byte)0xe8, (byte)0xe0,
				(byte)0xf0, (byte)0xd5, (byte)0xa6, (byte)0xbd, (byte)0xa0, (byte)0x69, (byte)0x6f, (byte)0x72, (byte)0x6e, (byte)0x8e, (byte)0x8d, (byte)0x0f, (byte)0xcb, (byte)0xf6, (byte)0xf8, (byte)0xeb,
				(byte)0xf6, (byte)0xcc, (byte)0x5b, (byte)0x73, (byte)0x9d, (byte)0xd5, (byte)0x2d, (byte)0xf1, (byte)0xce, (byte)0x17, (byte)0xdb, (byte)0xde, (byte)0x08, (byte)0x7f, (byte)0xdc, (byte)0x8d,
				(byte)0x02, (byte)0x03, (byte)0x01, (byte)0x00, (byte)0x01};
		String cert_ext_basicConsts = "CA : TRUE";
		String cert_ext_certPolicy = "2 5 29 32 0";
		String cert_ext_keyUsage = "keyCertSign, crlSign";
		
;		try {
			
			X509Certificate x509Cert = Disk.readCert("./Sample/CERT/Process/Cert_Root.der");
			
			System.out.println("1. View");
			
			if (bPrintLog) {
				System.out.println(" [TBSCertificate]");
			}
			
			// serialNum
			BigInteger serialNum = x509Cert.getSerialNumber();
			if (bPrintLog) {
			
				System.out.print("  <SerialNum> " + serialNum + "(");
				
				bBuf = serialNum.toByteArray();
				for (int i=0; i<bBuf.length; i++)
					System.out.print(Dump.getHexString(bBuf[i]));
				
				System.out.println(")");
			}
			else {
				if (!ByteUtil.equals(serialNum.toByteArray(), cert_serialNum)) {
					System.out.println("  >> err : serialNum is different.");
				}
			}
			
			// Issuer DN
			String issDN = x509Cert.getIssuerDN();
			
			if (bPrintLog) {
				System.out.println("  <IssuerDN> " + issDN);
			}
			else {
				if (!cert_issDN.equals(issDN)) {
					System.out.println("  >> err : issDN is different.");
				}
			}
			
			// Validity
			Date notBefore = x509Cert.getNotBefore();
			Date notAfter = x509Cert.getNotAfter();
			
			if (bPrintLog) {
				System.out.println("  <Validity> " + notBefore + " ~ " + notAfter);
			}
			else {
				
				Date date = null;
				SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
				dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
				
				date = dateF.parse(cert_notBefore);
				
				if (!date.equals(notBefore)) {
					System.out.println("  >> err : notBefore is different.");
				}
				
				date = dateF.parse(cert_notAfter);
				
				if (!date.equals(notAfter)) {
					System.out.println("  >> err : notAfter is different.");
				}
			}
			
			// Subject DN
			String subDN = x509Cert.getSubjectDN();
			
			if (bPrintLog) {
				System.out.println("  <SubjectDN> " + subDN);
			}
			else {
				if (!cert_subDN.equals(subDN)) {
					System.out.println("  >> err : subDN is different.");
				}
			}
			
			// Subject PublicKeyInfo
			PublicKey pubKey = x509Cert.getSubjectPublicKeyInfo();
			
			String pubKeyAlg = pubKey.getKeyAlg();
			
			if (bPrintLog) {
				System.out.println("  <SubjectPublicKeyInfo> " + pubKeyAlg + " (" + pubKey.getKeyLen() + ")");
				
				bBuf = pubKey.getKey();
				for (int i=0; i<bBuf.length; i++)
				{
					if (i == 0)
						System.out.print("  ");
					System.out.print(Dump.getHexString(bBuf[i]));
				}
				
				System.out.println(" ");
			}
			else {
				if (!cert_pubKeyAlg.equals(pubKeyAlg)) {
					System.out.println("  >> err : pubKeyAlg is different.");
				}
				
				if (!ByteUtil.equals(cert_pubKey, pubKey.getKey())) {
					System.out.println("  >> err : pubKey is different.");
				}
			}
			
			// Extensions
			String extValue;
			if (bPrintLog) {
				System.out.println("  [Extensions]");
			}
			
			//  BasicConstraints
			extValue = x509Cert.getBasicConstsraints();
			if (extValue.length() != 0)
			{
				if (bPrintLog) {
					System.out.println("   <BasicConstraints>");
					System.out.println("   " + extValue + "\n");
					extValue = "";
				}
				else {
					if (!cert_ext_basicConsts.equals(extValue)) {
						System.out.println("  >> err : basicConsts is different.");
					}
				}
			}
			
			//  CertPolicy
			extValue = x509Cert.getCertPolicy();
			if (extValue.length() != 0)
			{
				if (bPrintLog) {
					System.out.println("  <CertPolicy>");
					System.out.println("  " + extValue + "\n");
					extValue = "";
				}
				else {
					if (!cert_ext_certPolicy.equals(extValue)) {
						System.out.println("  >> err : certPolicy is different.");
					}
				}
				
			}
			
			//  KeyUsage
			extValue = x509Cert.getKeyUsage();
			if (extValue.length() != 0)
			{
				if (bPrintLog) {
					System.out.println("   <KeyUsage>");
					System.out.println("   " + extValue + "\n");
					extValue = "";
				}
				else {
					if (!cert_ext_keyUsage.equals(extValue)) {
						System.out.println("  >> err : keyUsage is different.");
					}
				}
			}
							
			System.out.println("  ... ok");
			
		} catch (Exception e) {
			
			e.printStackTrace();
			nErrCnt++;
		}
	}
	
	void verify() {
		
		System.out.println("2. Verify");
		
		CertPathValidator certPathValiditor = null; 
		X509Certificate myCert, cert;
		PrivateKey myPriKey;
		
		try {
			certPathValiditor = new CertPathValidator("./Sample/gpkiapi.conf");
			
			X509Certificate rootCert = Disk.readCert("./Sample/CERT/Verify/TrustCert.der");
			
			certPathValiditor.addTrustedRootCert(rootCert);
			
			long lTime = java.lang.System.currentTimeMillis();
			Date curTime = new Date(lTime);

			certPathValiditor.setValidationTime(curTime);
			certPathValiditor.setUserPolicySet(
					"1.2.410.200004.5.2.1.2;"+	/*SignGate*/
					"1.2.410.200004.5.1.1.5;"+	/*SignKorea*/
					"1.2.410.200005.1.1.4;"+	/*YesSign*/
					"1.2.410.200012.5.4.1.31;"+	/*KTNET*/
					"1.2.410.200004.5.4.1.4;"+	/*CrossCert*/
					"1.2.410.100001.2.2.1;"+	/*GPKI*/
					"1.2.410.200004.5.3.1.4"	/*NCASign*/);
			
			System.out.println(" 2.1. GPKI");
			cert = Disk.readCert("./Sample/CERT/Verify/GPKI_UserCert.der");
			certPathValiditor.setVerifyRange(CertPathValidator.CERT_VERIFY_STRICTLY);
			certPathValiditor.setRevokationCheck(CertPathValidator.REVOKE_CHECK_ARL | CertPathValidator.REVOKE_CHECK_CRL);
//			certPathValiditor.setRevokationCheck(CertPathValidator.REVOKE_CHECK_NONE);
//			certPathValiditor.validate(CertPathValidator.CERT_KM, cert);
			
//			ArrayList revInfo = certPathValiditor.checkStatusByCRL(cert);
//			if (revInfo != null) {
//				
//				RevReason revReason = (RevReason)revInfo.get(0);
//				Date revDate = (Date)revInfo.get(1);
//				
//				System.out.println("ByCRL = " + revReason.toString() + ", "+ revDate);
//			}
//			else {
//				System.out.println("ByCRL = valid..");
//			}
//			
//			revInfo = certPathValiditor.checkStatusByOCSP(cert, null);
//			if (revInfo != null) {
//				
//				RevReason revReason = (RevReason)revInfo.get(0);
//				Date revDate = (Date)revInfo.get(1);
//				X509Certificate ocspSvrCert = certPathValiditor.getOCSPSvrCert();
//				
//				System.out.println("OCSPCert = " + ocspSvrCert.getSubjectDN());
//				System.out.println("ByOCSP = " + revReason.toString() + ", " + revDate);
//			}
//			else {
//				System.out.println("ByOCSP = valid..");
//			}
//				
//			System.out.println("  OK...");
//			
		} catch (Exception e) {
			e.printStackTrace();
			nErrCnt++;
		}
			
		try {
			System.out.println(" 2.2. NPKI (YesSign)");
			cert = Disk.readCert("./Sample/CERT/Verify/NPKI_YesSign_UserCert.der");
			certPathValiditor.setRevokationCheck(CertPathValidator.REVOKE_CHECK_ARL | CertPathValidator.REVOKE_CHECK_CRL);
			certPathValiditor.validate(CertPathValidator.CERT_SIGN, cert);
			System.out.println("  ... ok");
			
		} catch (Exception e) {
			e.printStackTrace();
			nErrCnt++;
		}	
		
		try {
			System.out.println(" 2.3. NPKI (KTNet)");
			cert = Disk.readCert("./Sample/CERT/Verify/NPKI_KTNet_UserCert.der");
			certPathValiditor.setRevokationCheck(CertPathValidator.REVOKE_CHECK_ARL | CertPathValidator.REVOKE_CHECK_CRL | CertPathValidator.REVOKE_CHECK_OCSP);
			certPathValiditor.validate(CertPathValidator.CERT_SIGN, cert);
			System.out.println("  ... ok");
			
		} catch (Exception e) {
			e.printStackTrace();
			nErrCnt++;
		}
		
		try {
			System.out.println(" 2.4. NPKI (SignKorea)");
			cert = Disk.readCert("./Sample/CERT/Verify/NPKI_SignKorea_UserCert.der");
			certPathValiditor.setRevokationCheck(CertPathValidator.REVOKE_CHECK_ARL | CertPathValidator.REVOKE_CHECK_CRL | CertPathValidator.REVOKE_CHECK_OCSP);
			certPathValiditor.validate(CertPathValidator.CERT_SIGN, cert);
			System.out.println("  ... ok");
			
		} catch (Exception e) {
			e.printStackTrace();
			nErrCnt++;
		}
		
		try {
			System.out.println(" 2.5. NPKI (KICA)");
			cert = Disk.readCert("./Sample/CERT/Verify/NPKI_SignGate_UserCert.der");
			certPathValiditor.setRevokationCheck(CertPathValidator.REVOKE_CHECK_ARL | CertPathValidator.REVOKE_CHECK_CRL | CertPathValidator.REVOKE_CHECK_OCSP);
			certPathValiditor.validate(CertPathValidator.CERT_SIGN, cert);
			System.out.println("  ... ok");
			
		} catch (Exception e) {
			e.printStackTrace();
			nErrCnt++;
		}
		
		try {
			System.out.println(" 2.6. NPKI (CrossCert)");
			cert = Disk.readCert("./Sample/CERT/Verify/NPKI_CrossCert_UserCert.der");
			certPathValiditor.setRevokationCheck(CertPathValidator.REVOKE_CHECK_ARL | CertPathValidator.REVOKE_CHECK_CRL | CertPathValidator.REVOKE_CHECK_OCSP);
			certPathValiditor.validate(CertPathValidator.CERT_SIGN, cert);
			System.out.println("  ... ok");
			
		} catch (Exception e) {
			e.printStackTrace();
			nErrCnt++;
		}

//		try {
//			System.out.println(" 2.7. NPKI (NCaSign)");
//			cert = Disk.readCert("./Sample/CERT/Verify/NPKI_NCASign_UserCert.der");
//			certPathValiditor.setRevokationCheck(CertPathValidator.REVOKE_CHECK_ARL | CertPathValidator.REVOKE_CHECK_CRL | CertPathValidator.REVOKE_CHECK_OCSP);
//			certPathValiditor.validate(CertPathValidator.CERT_SIGN, cert);
//			System.out.println("  OK...");
//			
//		} catch (Exception e) {
//			e.printStackTrace();
//			nErrCnt++;
//		}
	}
	
	void verifyVID() {
		
		try {
			
			System.out.println("2. VerifyVID");
		
			X509Certificate cert = Disk.readCert("./Sample/VID/Verify/cert.der");
			PrivateKey prikey = Disk.readPriKey("./Sample/VID/Verify/pri.key", "12345678");
			
			byte[] random = null;
			
			random = prikey.getRandomForVID();
			cert.verifyVID("1234567890123", random);

			System.out.println("  ... ok");
			
		} catch (Exception e) {
			e.printStackTrace();
			nErrCnt++;
		}
	}
	
	void checkStatus() {
		
		try {
			
			System.out.println("3. CheckStauts");
			
			int i = 0;
			String[] targetCerts = {
					"./Sample/CERT/CheckStat/CHECKSTAT_001.cer",
					"./Sample/CERT/CheckStat/CHECKSTAT_002.cer",
					"./Sample/CERT/CheckStat/CHECKSTAT_003.cer",
					"./Sample/CERT/CheckStat/CHECKSTAT_004.cer",
					"./Sample/CERT/CheckStat/CHECKSTAT_005.cer",
					"./Sample/CERT/CheckStat/CHECKSTAT_006.cer"};
			
			X509Certificate myCert = Disk.readCert("./Sample/CERT/CheckStat/CHECKSTAT_MYCERT.cer");
			PrivateKey myPriKey = Disk.readPriKey("./Sample/CERT/CheckStat/CHECKSTAT_MYPRIKEY.key", "qwer1234");
			
			OCSPRequest ocspRequest = new OCSPRequest();
			
			ocspRequest.setMyCert(myCert, myPriKey);
			
			for (i=0; i<targetCerts.length; i++) {
				
				X509Certificate cert = Disk.readCert(targetCerts[i]);
				ocspRequest.addTargetCert(cert);
			}
			
			byte[] reqMsg = ocspRequest.generateReqMsg();
//			byte[] reqMsg = ocspRequest.generateReqMsg(Disk.readCert(targetCerts[0]));
			
//			Disk.write("c:/ocsp/ocspReqMsg.ber", reqMsg);
			
			OCSP ocsp = new OCSP();
			ocsp.connect(Disk.readCert(targetCerts[0]));
			byte[] resMsg = ocsp.sendAndRecv(reqMsg);
			
//			Disk.write("c:/ocsp/ocspResMsg.ber", resMsg);
			
			OCSPResponse ocspResponse = new OCSPResponse(resMsg);
			ocspResponse.verify(reqMsg);
			
			if (bPrintLog) {
				for (i=0; i<ocspResponse.getSingleCertStatCnt(); i++) {
				
					switch (ocspResponse.getCertStatus(i)) {
					
						case 1:
							System.out.println(" good");
							break;
						case 2:
							System.out.println(" revoked (revDate = " + ocspResponse.getRevokedDate(i) + 
									", reason = " + ocspResponse.getRevocationReason(i).toString() + ")");
							break;
						case 3:
							System.out.println(" holded (revDate = " + ocspResponse.getRevokedDate(i));
							break;
						case 4:
							System.out.println(" unknown");
							break;
					}
				}
			}

			X509Certificate ocspCert = ocspResponse.getOcspSvrCert();
			
			if (bPrintLog) {
				System.out.println(ocspCert.getSubjectDN());
			}
			
			System.out.println(" ... ok");
			
		} catch (Exception e) {
			e.printStackTrace();
			nErrCnt++;
		}
	}
}
