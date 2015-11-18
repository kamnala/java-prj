package test;

import java.util.Date;

import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.cms.*;
import com.gpki.gpkiapi.crypto.PrivateKey;
import com.gpki.gpkiapi.crypto.SecretKey;
import com.gpki.gpkiapi.exception.GpkiApiException;
import com.gpki.gpkiapi.storage.Disk;
import com.gpki.gpkiapi.tsa.TimeStamp;
import com.gpki.gpkiapi.tsa.TimeStampToken;
import com.gpki.gpkiapi.util.Dump;
import java.io.File;


/*
 * Created on 2005. 10. 4.
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
public class Cms {
	
	private byte[] plainText = new byte[128];
	private boolean bPrintLog = false;
	private int nErrCnt = 0;
	
	public int getErrCnt() {
		return nErrCnt;
	}
	
	public Cms(boolean bPrintLog) {
		
		try {
			this.bPrintLog = bPrintLog;
			
			plainText = Disk.read("./Sample/CMS/SignedData/Message.dat");
		} catch (Exception e) {
			e.printStackTrace();
			nErrCnt++;		
		}
	}
	
	public void signData() {
			
		System.out.println("1. SignedData");
		
		X509Certificate signerCert1, signerCert2;
		PrivateKey signerPriKey1, signerPriKey2;
		byte[] outData = null;
		
		try {
			
			signerCert1 = Disk.readCert("./Sample/CMS/SignedData/signCert1.der");
			signerPriKey1 = Disk.readPriKey("./Sample/CMS/SignedData/signPri1.key", "12345678");
			
			signerCert2 = Disk.readCert("./Sample/CMS/SignedData/signCert2.der");
			signerPriKey2 = Disk.readPriKey("./Sample/CMS/SignedData/signPri2.key", "12345678");

//			SignedData signedData = new SignedData(SignedData.OPT_USE_CONTENT_INFO);
//			SignedData signedData = new SignedData(SignedData.OPT_USE_CONTENT_INFO|SignedData.OPT_USE_SET_CAPUBS);
			SignedData signedData = new SignedData();
			
			signedData.setConfFile("./Sample/gpkiapi.conf");
			
			System.out.println(" 1.1. Make");
			
			System.out.println("  1.1.1. Message base");
			
			signedData.setMessage(plainText);
			outData = signedData.generate(signerCert1, signerPriKey1);
//			signedData.setMessage_File("D:/03.GPKI/bin/gpkiapi.conf");
//			signedData.generate_noContent_File(signerCert1, signerPriKey1, "C:/signedData1.ber");
			
			signedData.verify(outData);
//			signedData.verify_noContetn_File("signedData1.ber", "aaa");
			byte[] capubs = signedData.getCaPubs();
			if (capubs != null) {
				Disk.write("capubs1.ber", capubs);
			}
			
			signedData.getTBTData(0);
			signedData.getTimeStampToken(0);
//			outData = signedData.addSigner(outData, signerCert2,signerPriKey2);
//			
//			Disk.write("C:/signedData2.ber", outData);
//			
//			signedData.verify(outData);
//			capubs = signedData.getCaPubs();
//			if (capubs != null) {
//				Disk.write("C:/capubs2.ber", capubs);
//			}
//			
			for (int i=0; i<signedData.getSignerCnt(); i++)
			{
				if (bPrintLog) {
					 System.out.println("subject = " + signedData.getSignerCert(i).getSubjectDN());
				}
			}
			
			System.out.println("  ... ok");

			System.out.println("  1.1.2. File base");
			
			signedData.setMessage_File("./Sample/CMS/SignedData/Message.dat");
			signedData.generate_File(signerCert1, signerPriKey1, "./Sample/CMS/SignedData/SignedData_File.ber");
			System.out.println("  ... ok");
			
			System.out.println(" 1.2. Add Signer");

			outData = signedData.addSigner(outData, signerCert2, signerPriKey2);
			System.out.println("  ... ok");
			
			//Disk.write("./Sample/CMS/SignedData.ber", outData);
			
			System.out.println(" 1.3. Verify");
			
			System.out.println("  1.3.1. Message base");

			System.out.print("  - SelfTest");
			
			byte[] msg = null;
			int cnt = 0;
			
			signedData.verify(outData);
			msg = signedData.getMessage();
			
			if (bPrintLog) {
				System.out.println(" ");
				System.out.println("  MSG = " + new String(msg, 0, msg.length));
			}
						
			cnt = signedData.getSignerCnt();
			
			if (bPrintLog) {
				System.out.println("  [SignInfo]");
			}

			for (int i=0; i<cnt; i++) {
				X509Certificate signer = signedData.getSignerCert(i);
				Date signTime = signedData.getSigningTime(i);
				
				if (bPrintLog) {
					System.out.println("  Singner[" + i + "]  = " + signer.getSubjectDN());
					System.out.println("  SignTime[" + i + "] = " + signTime);
				}
			}
			
			System.out.println(" ... ok");
						
			System.out.print("  - Compatibility");
			outData = Disk.read("./Sample/CMS/SignedData/SignedDataWithMultiSigners.p7b");
			
			signedData.verify(outData);
			msg = signedData.getMessage();
			
			if (bPrintLog) {
				System.out.println(" ");
				System.out.println("  MSG = " + new String(msg, 0, msg.length));
			}
			
			cnt = signedData.getSignerCnt();
			
			if (bPrintLog)
				System.out.println("  [SignInfo]");
			
			for (int i=0; i<cnt; i++) {
				X509Certificate signer = signedData.getSignerCert(i);
				Date signTime = signedData.getSigningTime(i);
				
				if (bPrintLog) {
					System.out.println("   Singner[" + i + "]  = " + signer.getSubjectDN());
					System.out.println("   SignTime[" + i + "] = " + signTime);
				}
			}
			
			if (!bPrintLog)
				System.out.println(" ... ok");

			System.out.println("  1.3.2. File base");
						
			signedData.verify_File("./Sample/CMS/SignedData/SignedData_File.ber", "./Sample/CMS/SignedData/Message_File.dat");
						
			cnt = signedData.getSignerCnt();
			
			if (bPrintLog)
				System.out.println("  [SignInfo]");

			for (int i=0; i<cnt; i++) {
				X509Certificate signer = signedData.getSignerCert(i);
				Date signTime = signedData.getSigningTime(i);
				
//				Disk.write("C:/signer.ber", signer.getCert());
				
				if (bPrintLog) {
					System.out.println("  Singner[" + i + "]  = " + signer.getSubjectDN());
					System.out.println("  SignTime[" + i + "] = " + signTime);
				}
			}
			
			if (!bPrintLog)
				System.out.println(" ... ok");
			
			(new File("./Sample/CMS/SignedData/Message_File.dat")).delete();
			(new File("./Sample/CMS/SignedData/SignedData_File.ber")).delete();
			
			System.out.println("  1.3.3. No Content base");
			outData = Disk.read("./Sample/CMS/SignedData/signedData_noContent.p7b");
			signedData.setMessage(plainText);
			signedData.verify(outData);
					
			cnt = signedData.getSignerCnt();
			
			if (bPrintLog)
				System.out.println("  [SignInfo]");

			for (int i=0; i<cnt; i++) {
				X509Certificate signer = signedData.getSignerCert(i);
				Date signTime = signedData.getSigningTime(i);
				
				if (bPrintLog) {
					System.out.println("  Singner[" + i + "]  = " + signer.getSubjectDN());
					System.out.println("  SignTime[" + i + "] = " + signTime);
				}
			}
			
			if (!bPrintLog)
				System.out.println(" ... ok");			
			
			
			System.out.println(" 1.4. SHA256 SignedData");
			System.out.println("  1.4.1. Message base");
			SignedData signedData2 = new SignedData();
			signedData2.setMessage(plainText);
			signedData2.setHashAlgo("SHA256");
			outData = signedData2.generate(Disk.readCert("./Sample/CMS/SignedData/signCert3.der"), Disk.readPriKey("./Sample/CMS/SignedData/signPri3.key", "88888888"));
			if (!bPrintLog)
				System.out.println(" ... ok");			
			
			System.out.println("  1.4.2. verify");
			signedData2.verify(outData);
			if (!bPrintLog)
				System.out.println(" ... ok");			

		} catch (Exception e) {

			(new File("./Sample/CMS/SignedData/Message_File.dat")).delete();
			(new File("./Sample/CMS/SignedData/SignedData_File.ber")).delete();
			
			e.printStackTrace();
			nErrCnt++;
		}
	}
	
	public void ltesForGpki() {
		
		System.out.println("6. LTES");
		
		byte[] outData;
		X509Certificate signerCert1, signerCert2;
		PrivateKey signerPriKey1, signerPriKey2;
		
		try {
			signerCert1 = Disk.readCert("./Sample/CMS/SignedData/signCert1.der");
			signerPriKey1 = Disk.readPriKey("./Sample/CMS/SignedData/signPri1.key", "12345678");
			
			signerCert2 = Disk.readCert("./Sample/CMS/SignedData/signCert2.der");
			signerPriKey2 = Disk.readPriKey("./Sample/CMS/SignedData/signPri2.key", "12345678");
	
			SignedData signedData = new SignedData();
			
			System.out.println(" 6.1. Generate SignedData");
			
			signedData.setMessage(plainText);
			outData = signedData.generate(signerCert1, signerPriKey1);
			System.out.println("  ... ok");
	
			// 시점확인 토큰 요청하기
			System.out.println(" 6.2. TimeStamp for Signer1");
			
			signedData.verify(outData);
			byte[] tbtData = signedData.getTBTData(0);
			
			TimeStampToken tst = reqTimeStampToken(tbtData);
			System.out.println("  ... ok");
			
			// 시점확인 토큰 지정하기
			System.out.println(" 6.3. Set TimeStamptToken");
			byte[] signedDataWithTST = signedData.setTimeStampToken(outData, 0, tst);
			
			// 지정된 시점확인 토큰 확인하기
			verifySignedData(signedDataWithTST);
			System.out.println("  ... ok");
			
	//		Disk.write("C:/signedData.ber", signedDataWithTST);
	//		Disk.write("C:/signature.ber", tbtData);
			
			System.out.println(" 6.4. Add Signer2");
			byte[] signedDataWith2Signer = signedData.addSigner(signedDataWithTST, signerCert2, signerPriKey2);
			
			verifySignedData(signedDataWith2Signer);
			System.out.println("  ... ok");
			
			// 시점확인 토큰 요청하기
			System.out.println(" 6.5. TimeStamp for Signer2");
			
			signedData.verify(signedDataWith2Signer);
			tbtData = signedData.getTBTData(1);
			
			tst = reqTimeStampToken(tbtData);
			System.out.println("  ... ok");
			
			System.out.println(" 6.6. Set TimeStamptToken");
			signedDataWithTST = signedData.setTimeStampToken(signedDataWith2Signer, 1, tst);
			
			// 지정된 시점확인 토큰 확인하기
			verifySignedData(signedDataWithTST);
			System.out.println("  ... ok");
//			Disk.write("C:/signedDataWithTST.ber", signedDataWithTST);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	TimeStampToken reqTimeStampToken(byte[] data) throws GpkiApiException {
		
		TimeStamp timeStamp = new TimeStamp();
		
		timeStamp.setMessage(data);
		timeStamp.setConfFile("./Sample/gpkiapi.conf");
		
		TimeStampToken tst = timeStamp.reqTimeStampToken("152.99.56.61", 80);
		tst.verify(data);
		
		return tst;
	}
	
	void verifySignedData(byte[] sigendDataBuff) throws GpkiApiException, Exception {
		
		byte[] tbtData = null;
		TimeStampToken tst = null;
		
		SignedData signedData = new SignedData();
		
		signedData.verify(sigendDataBuff);
		
		if (bPrintLog) {
			System.out.println(" signerCnt = " + signedData.getSignerCnt());
		}
		for (int i=0; i<signedData.getSignerCnt(); i++) {
			
			if (bPrintLog) {
				System.out.println(" signer = " + signedData.getSignerCert(i).getSubjectDN());
			}
			tbtData = signedData.getTBTData(i);
			
			if (bPrintLog) {
				System.out.print(" tbtData = " + Dump.toHexString(tbtData, 0, tbtData.length));
			}
			tst = signedData.getTimeStampToken(i);
			
			if (tst != null) {
				tst.verify(tbtData);
				if (bPrintLog) {
					System.out.println("timeStampToken exist....");
				}
			}
		}
	}
	
	void envData() {

		System.out.println("2. EnvelopedData");
		
		X509Certificate recCert1, recCert2;
		PrivateKey recPriKey1, recPriKey2;
		byte[] outData = null, msg = null;
		
		try {
			
			recCert1 = Disk.readCert("./Sample/CMS/EnvelopedData/kmCert.der");
			recPriKey1 = Disk.readPriKey("./Sample/CMS/EnvelopedData/kmPri.key", "12345678");
			
			recCert2 = Disk.readCert("./Sample/CMS/EnvelopedData/kmCert2.der");
			recPriKey2 = Disk.readPriKey("./Sample/CMS/EnvelopedData/kmPri2.key", "12345678");

			System.out.println(" 2.1. Make");
			
			EnvelopedData envData = new EnvelopedData("ARIA");
//			EnvelopedData envData = new EnvelopedData("SEED", 
//					EnvelopedData.OPT_USE_CONTENT_INFO);
			
			System.out.println("  2.1.1. File Base");
			
			envData.addRecipient(recCert1);
			envData.generate_File("./Sample/CMS/EnvelopedData/Message.dat", "./Sample/CMS/EnvelopedData/EnvData_File.ber");
			
			// 세션키 정보 확인
			SecretKey secretKey = envData.getSecretKey();
			
			byte[] bKey = null;
			byte[] bIv = null;
			if (bPrintLog == true) {
				System.out.println("Session KeyAlg = " + secretKey.getKeyAlg());
				
				System.out.print("Key = ");	
				bKey = secretKey.getKey();
				for (int i=0; i<bKey.length; i++)
					System.out.print(Dump.getHexString(bKey[i]));
				System.out.println("");
				
				System.out.print("IV  = ");
				bIv = secretKey.getIv();
				for (int i=0; i<bIv.length; i++)
					System.out.print(Dump.getHexString(bIv[i]));
				System.out.println("");
			}
			else
				System.out.println("   ... ok");
			
			System.out.println("  2.1.2. Message Base");
			
			envData.addRecipient(recCert2);
			
			outData = envData.generate(plainText);
			
			// 세션키 정보 확인
			secretKey = envData.getSecretKey();
			
			if (bPrintLog == true) {
				System.out.println("Session KeyAlg = " + secretKey.getKeyAlg());
				
				System.out.print("Key = ");	
				bKey = secretKey.getKey();
				for (int i=0; i<bKey.length; i++)
					System.out.print(Dump.getHexString(bKey[i]));
				System.out.println("");
				
				System.out.print("IV  = ");
				bIv = secretKey.getIv();
				for (int i=0; i<bIv.length; i++)
					System.out.print(Dump.getHexString(bIv[i]));
				System.out.println("");
			}
			else
				System.out.println("   ... ok");
			
			//Disk.write("./Sample/CMS/EnvelopedData.ber", outData);
			
			System.out.println(" 2.2. Process");
			System.out.println("  2.2.1. Message Base");
			System.out.println("   - SelfTest");

			msg = envData.process(outData, recCert1, recPriKey1);
			
			System.out.print("   first recipient");
			
			if (bPrintLog == true) {
				System.out.println(" ");
				System.out.println("  - 원본메시지 = " + new String(msg, 0, msg.length));
			}
			
			// 세션키 정보 확인
			secretKey = envData.getSecretKey();
			
			if (bPrintLog == true) {
				System.out.println("  - Session KeyAlg = " + secretKey.getKeyAlg());
				
				System.out.print("  - Key = ");
				bKey = secretKey.getKey();
				for (int i=0; i<bKey.length; i++)
					System.out.print(Dump.getHexString(bKey[i]));
				System.out.println("");
				
				System.out.print("  - IV  = ");
				bIv = secretKey.getIv();
				for (int i=0; i<bIv.length; i++)
					System.out.print(Dump.getHexString(bIv[i]));
				System.out.println("");
			}
			else
				System.out.println(" ... ok");
			
			msg = envData.process(outData, recCert2, recPriKey2);
			
			System.out.print("   second recipient");
			
			if (bPrintLog == true) {
				System.out.println(" ");
				System.out.println("  - 원본메시지 = " + new String(msg, 0, msg.length));
			}
			
			// 세션키 정보 확인
			secretKey = envData.getSecretKey();
			
			if (bPrintLog == true) {
				System.out.println("  - Session KeyAlg = " + secretKey.getKeyAlg());
				
				System.out.print("  - Key = ");
				bKey = secretKey.getKey();
				for (int i=0; i<bKey.length; i++)
					System.out.print(Dump.getHexString(bKey[i]));
				System.out.println("");
				
				System.out.print("  - IV  = ");
				bIv = secretKey.getIv();
				for (int i=0; i<bIv.length; i++)
					System.out.print(Dump.getHexString(bIv[i]));
				System.out.println("");
			}
			else
				System.out.println(" ... ok");
		
			System.out.println("   - Compatibility");
			outData = Disk.read("./Sample/CMS/EnvelopedData/EnvelopedData.env");
			
			msg = envData.process(outData, recCert1, recPriKey1);
			
			System.out.print("   first recipient");
			
			if (bPrintLog == true) {
				System.out.println(" ");
				System.out.println("  - 원본메시지 = " + new String(msg, 0, msg.length));	
			}
			
			// 세션키 정보 확인
			secretKey = envData.getSecretKey();
			
			if (bPrintLog == true) {
				System.out.println("  - Session KeyAlg = " + secretKey.getKeyAlg());
				
				System.out.print("  - Key = ");
				bKey = secretKey.getKey();
				for (int i=0; i<bKey.length; i++)
					System.out.print(Dump.getHexString(bKey[i]));
				System.out.println("");
				
				System.out.print("  - IV  = ");
				bIv = secretKey.getIv();
				for (int i=0; i<bIv.length; i++)
					System.out.print(Dump.getHexString(bIv[i]));
				System.out.println("");
			}
			else
				System.out.println(" ... ok");
			
			msg = envData.process(outData, recCert2, recPriKey2);
			
			System.out.print("   second recipient");
			
			if (bPrintLog == true) {
				System.out.println(" ");
				System.out.println("  - 원본 메시지 = " + new String(msg, 0, msg.length));
			}
			
			// 세션키 정보 확인
			secretKey = envData.getSecretKey();
			
			if (bPrintLog == true) {
				System.out.println("  - Session KeyAlg = " + secretKey.getKeyAlg());
				
				System.out.print("  - Key = ");
				bKey = secretKey.getKey();
				for (int i=0; i<bKey.length; i++)
					System.out.print(Dump.getHexString(bKey[i]));
				System.out.println("");
				
				System.out.print("  - IV  = ");
				bIv = secretKey.getIv();
				for (int i=0; i<bIv.length; i++)
					System.out.print(Dump.getHexString(bIv[i]));
				System.out.println("");
			}
			else
				System.out.println(" ... ok");
			
			System.out.println("  2.2.2. File Base");
			
			msg = envData.process_File("./Sample/CMS/EnvelopedData/EnvData_File.ber", recCert1, recPriKey1, "./Sample/CMS/EnvelopedData/Message_File.txt");
			
			// 세션키 정보 확인
			secretKey = envData.getSecretKey();
			
			if (bPrintLog == true) {
				System.out.println("  - Session KeyAlg = " + secretKey.getKeyAlg());
				
				System.out.print("  - Key = ");
				bKey = secretKey.getKey();
				for (int i=0; i<bKey.length; i++)
					System.out.print(Dump.getHexString(bKey[i]));
				System.out.println("");
				
				System.out.print("  - IV  = ");
				bIv = secretKey.getIv();
				for (int i=0; i<bIv.length; i++)
					System.out.print(Dump.getHexString(bIv[i]));
				System.out.println("");
			}
			else
				System.out.println(" ... ok");
			
			(new File("./Sample/CMS/EnvelopedData/Message_File.txt")).delete();
			(new File("./Sample/CMS/EnvelopedData/EnvData_File.ber")).delete();
			
			
		} catch (Exception e) {
			
			(new File("./Sample/CMS/EnvelopedData/Message_File.txt")).delete();
			(new File("./Sample/CMS/EnvelopedData/EnvData_File.ber")).delete();

			e.printStackTrace();
			nErrCnt++;
		}
	}
	
	void signedAndEnvData() {

		System.out.println("3. SignedAndEnvelopedData");
		
		X509Certificate signerCert, kmCert;
		PrivateKey signerKey, kmKey;
		byte[] outData = null, msg = null;
		
		try {
	
			signerCert = Disk.readCert("./Sample/CMS/SignedAndEnvelopedData/signCert.der");
			signerKey = Disk.readPriKey("./Sample/CMS/SignedAndEnvelopedData/signPri.key", "12345678");
			
			kmCert = Disk.readCert("./Sample/CMS/SignedAndEnvelopedData/kmCert.der");
			kmKey = Disk.readPriKey("./Sample/CMS/SignedAndEnvelopedData/kmPri.key", "12345678");
			
			System.out.println(" 3.1. Make");
			
			SignedAndEnvelopedData signedAndEnvData = new SignedAndEnvelopedData("SEED");
			
			signedAndEnvData.setMyCert(signerCert, signerKey);
			outData = signedAndEnvData.generate(kmCert, plainText);
			//Disk.write("./Sample/CMS/signedAndEnvData.ber", outData);
			
			System.out.println("  ... ok");
			
			System.out.println(" 3.2. Process");
			
			signedAndEnvData.setMyCert(kmCert, kmKey);
			outData = signedAndEnvData.process(outData);
			
			SecretKey secretKey = signedAndEnvData.getSecretKey();
			
			if (bPrintLog == true) {
				System.out.println("  MSG = " + new String(outData, 0, outData.length));
				
				System.out.println("  - Session KeyAlg = " + secretKey.getKeyAlg());
				
				System.out.print("  - Key = ");
				byte[] bKey = secretKey.getKey();
				for (int i=0; i<bKey.length; i++)
					System.out.print(Dump.getHexString(bKey[i]));
				System.out.println("");
				
				System.out.print("  - IV  = ");
				byte[] bIv = secretKey.getIv();
				for (int i=0; i<bIv.length; i++)
					System.out.print(Dump.getHexString(bIv[i]));
				System.out.println("");
			}
			else
				System.out.println("  ... ok");
			
			//Disk.write("./Sample/CMS/aaa.txt", outData);
			
		} catch (Exception e) {

			e.printStackTrace();
			nErrCnt++;
		}
	}
	
	void signedContent() {
		
		System.out.println("4. SignedContent");
		
		X509Certificate signerCert;
		PrivateKey signerPriKey;
		byte[] outData	= null;
		byte[] msg 		= null;
		int cnt			= 0;
		
		try {
			
			signerCert = Disk.readCert("./Sample/WCMS/SignedContent/SignCert.der");
			signerPriKey = Disk.readPriKey("./Sample/WCMS/SignedContent/SignPri.key", "12345678");
			
			System.out.println(" 4.1. Make");
			
			SignedContent signedContent = new SignedContent();
			
			if (bPrintLog == true)
				System.out.println(new String(plainText, 0, plainText.length));
			
			outData = signedContent.generate(plainText, signerCert, signerPriKey);
			
			//Disk.write("./Sample/CMS/SignedContent.xdr", outData);
			
			System.out.println("  ... ok");
			
			System.out.println(" 4.2. Verify");
			System.out.print("  - SelfTest");
			
			signedContent.verify(outData);
			msg = signedContent.getMessage();
			
			if (bPrintLog == true) {
				System.out.println(" ");
				System.out.println("  Message = " + new String(msg, 0, msg.length));
			}
			
			X509Certificate signer = signedContent.getSignerCert();
			
			if (bPrintLog == true) {
				System.out.println("  Singner = " + signer.getSubjectDN());
				System.out.println("  SignTime = " + signedContent.getSigningTime());
			}
			else
				System.out.println(" ... ok");
			
			System.out.print("  - Compatibility");
			outData = Disk.read("./Sample/WCMS/SignedContent/SignedContent.xdr");
			
			signedContent.verify(outData);
			msg = signedContent.getMessage();
			
			if (bPrintLog == true) {
				System.out.println(" ");
				System.out.println("  Message = " + new String(msg, 0, msg.length));
			}
			
			signer = signedContent.getSignerCert();
			
			if (bPrintLog == true) {
				System.out.println("  Singner = " + signer.getSubjectDN());
				System.out.println("  SignTime = " + signedContent.getSigningTime());
			}
			else
				System.out.println(" ... ok");

		} catch (Exception e) {

			e.printStackTrace();
			nErrCnt++;
		}
	}
	
	void wapEnvData() {

		System.out.println("5. WapEnvelopedData");
		
		X509Certificate recCert;
		PrivateKey recPriKey;
		byte[] outData = null, msg = null;
		
		try {
			
			recCert = Disk.readCert("./Sample/WCMS/WapEnvData/KmCert.der");
			recPriKey = Disk.readPriKey("./Sample/WCMS/WapEnvData/KmPri.key", "12345678");
						
			System.out.println(" 5.1. Make");
			
			WapEnvelopedData wapEnvData = new WapEnvelopedData("3DES");
			
			outData = wapEnvData.generate(plainText, recCert);
			//Disk.write("./Sample/CMS/WapEnvelopedData.xdr", outData);
			
			System.out.println("  ... ok");
			
			System.out.println(" 5.2. Process");
			System.out.print("  - SelfTest");
						
			wapEnvData.setMyCert(recCert, recPriKey);
			msg = wapEnvData.process(outData);

			if (bPrintLog == true) {
				System.out.println(" ");
				System.out.println("  MSG = " + new String(msg, 0, msg.length));
			}
			else
				System.out.println(" ... ok");
			
			System.out.print("  - Compatibility");
			outData = Disk.read("./Sample/WCMS/WapEnvData/WapEnvData.xdr");

			wapEnvData.setMyCert(recCert, recPriKey);
			msg = wapEnvData.process(outData);

			if (bPrintLog == true) {
				System.out.println(" ");
				System.out.println("  MSG = " + new String(msg, 0, msg.length));
			}
			else
				System.out.println(" ... ok");
			
		} catch (Exception e) {

			e.printStackTrace();
			nErrCnt++;
		}
	}
}
