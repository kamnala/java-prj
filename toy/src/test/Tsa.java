package test;

import java.math.BigInteger;

import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.crypto.PrivateKey;
import com.gpki.gpkiapi.storage.Disk;
import com.gpki.gpkiapi.tsa.TimeStamp;
import com.gpki.gpkiapi.tsa.TimeStampToken;
import com.gpki.gpkiapi.tsa.TimeStampRes;
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
public class Tsa {
	
	int nErrCnt;
	boolean bPrintLog;
	
	public Tsa(boolean bPrintLog) {
		this.bPrintLog = bPrintLog;
	}
	public int getErrCnt() {
		return nErrCnt;
	}
	
	public void reqTimeStamp() {
		
		System.out.println("1. TimeStampProtocl");
		
		byte[] message 	= null;
		
		X509Certificate myCert;
		PrivateKey myPriKey;
		
		try {
			
			message = Disk.read("./Sample/TSP/TimeStampProtocol/Message.dat");
						
			TimeStamp timeStamp = new TimeStamp();
			TimeStampToken 	timeStampToken;
					
			// 1. 시점확인 토큰받기
			System.out.println(" 1.1. Request TimeStampToken");
			
			// 시점확인 받을 메시지 설정
			timeStamp.setMessage(message);
			timeStamp.setConfFile("./Sample/gpkiapi.conf");
			
			// 시점확인 토큰 요청하기
			timeStampToken = timeStamp.reqTimeStampToken("152.99.56.61", 80);
			System.out.println("  ... ok");
			
			//Disk.write("./Sample/TSP/TimeStampProtocol/Message.dat", timeStampToken.getTimeStampToken());
			
			// 2. 받은 시점확인 토큰 검증하기
			System.out.println(" 1.2. Verify TimeStampToken");
			timeStampToken.verify(message);
			
			// 3. 시점확인 토큰 내용 확인하기
			displayTimeStampTokenInfo(timeStampToken);
			System.out.println("  ... ok");
			
			// 4. 시점확인 응답 메시지 확인하기
			System.out.println(" 1.3. Process TimeStampResponse");
			
			TimeStampRes	timeStampRes;
			byte[] resMsg = Disk.read("./Sample/TSP/TimeStampProtocol/TimeStampRes_nok.ber");
			
			timeStampRes = new TimeStampRes(resMsg);
			
			int status = timeStampRes.getStatus();
			
			if (bPrintLog) {
				System.out.println("  Status = " + status);
			} 
			/*else {
				if (status != 2) {
					System.out.println("  >> err : status is not 2.");
				}
			}
			*/
			if (timeStampRes.getStatus() != 0) {
				String freeText = timeStampRes.getPkiFreeText();
				if (bPrintLog){
					System.out.println("  PKIFreeText = " + freeText);
				}
				else {
					if (!freeText.equals("내부 오류")) {
						System.out.println("  >> err : pkiFreeText is not internal error.");
					}
				}
			}
			else
				displayTimeStampTokenInfo(timeStampRes.getTimeStampToken());
			
			System.out.println("  ... ok");
			
		} catch (Exception e) {

			e.printStackTrace();
			nErrCnt++;
		}
	}
	
	void displayTimeStampTokenInfo(TimeStampToken timeStampToken) {
		
		if (!bPrintLog) {
			return;
		}
		
		byte[] bBuf 	= null;
		
		try {
			X509Certificate tsaCert = timeStampToken.getTSACert();
		
			// DN
			System.out.println("  [TSA 서버 DN] " + tsaCert.getSubjectDN());
		
			// SerialNumber
			BigInteger serialNum = timeStampToken.getSerialNumber();
		
			System.out.print("  [토큰 일련번호] " + serialNum + "(");
		
			bBuf = serialNum.toByteArray();
			for (int i=0; i<bBuf.length; i++)
				System.out.print(Dump.getHexString(bBuf[i]));
		
			System.out.println(")");
		
			// GenTime
			System.out.println("  [토큰 생성시간] " + timeStampToken.getGeneratedTime() + timeStampToken.getGeneratedTimeMicro());

			// Policy
			System.out.println("  [토큰 발급정책] " + timeStampToken.getPolicy());
		
			// Hash Algorithm
			System.out.println("  [해쉬 알고리즘] " + timeStampToken.getHashAlgorithm());
		
			// MessageImprint
			System.out.print("  [메시지 해쉬값] ");
		
			bBuf = timeStampToken.getMessageImprint();
			for (int i=0; i<bBuf.length; i++)
				System.out.print(Dump.getHexString(bBuf[i]));
			
			System.out.println(" ");
		
			// Nonce
			System.out.print("  [Nonce] ");
			
			bBuf = timeStampToken.getNonce();
			for (int i=0; i<bBuf.length; i++)
				System.out.print(Dump.getHexString(bBuf[i]));
			
			System.out.println(" ");
		} catch (Exception e) {

			e.printStackTrace();
			nErrCnt++;
		}
	}
}
