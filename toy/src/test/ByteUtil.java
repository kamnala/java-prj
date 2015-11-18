package test;

/*
 * Created on 2007. 6. 25.
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */

/**
 * byte[] 타입의 데이터를 처리하기 위한 클래스이다.
 * 
 * @since 1.0.0.0
 */
public class ByteUtil {

	private ByteUtil(){
		// static class, hide constructor
	}
	
	/**
	 * 두개의 byte[] 타입의 데이터를 연결한다.
	 * 
	 * @param a byte[] 타입의 데이터1
	 * @param b byte[] 타입의 데이터2
	 * @return a,b가 순서대로 연결된 데이터
	 */
	public static byte[] concat(byte[] a, byte[] b) {
		
		if (a == null) {
			return b;
		}
		if (b == null) {
			return a;
		}
		
		return concat(a, 0, a.length, b, 0, b.length);
	}
	   
	/**
	 * 두개의 byte[] 타입의 데이터를 연결한다.
	 * 
	 * @param a byte[] 타입의 데이터1
	 * @param a_offset 연결할 데이터 a의 시작 위치
	 * @param a_length 연결할 데이터 a의 길이
	 * @param b byte[] 타입의 데이터2
	 * @param b_offset 연결할 데이터 b의 시작 위치
	 * @param b_length 연결할 데이터 b의 길이
	 * @return a,b가 순서대로 연결된 데이터
	 */
	public static byte[] concat(byte[] a, int a_offset, int a_length, 
	   							   byte[] b, int b_offset, int b_length) {
	   	
	   		byte buff[] = null;
        
	   		buff = new byte[a_length + b_length];
	   		
	   		System.arraycopy(a, a_offset , buff, 0, a_length);
	   		System.arraycopy(b, b_offset , buff, a_length, b_length);
	   		
	   		return buff;
	   }
	   
	/**
	 * byte[] 타입의 두 데이터를 비교한다.
	 * 
	 * @param a byte[] 타입의 테이터1
	 * @param b byte[] 타입의 데이터2
	 * @return 두 데이터가 같은 경우 true, 그렇지 않은 경우 false
	 */
	static public boolean equals(byte[] a, byte[] b) {
	  	
	  		if (a == b)
	  			return true;
	  		
	  		if (a.length != b.length)
	  			return false;
  		
	  		return equals(a, 0, b, 0, a.length);
	  }
	  
	/**
	 * byte[] 타입의 두 데이터를 비교한다.
	 * 
	 * @param a byte[] 타입의 데이터1
	 * @param a_offset 비교할 a 데이터의 시작 위치
	 * @param b byte[] 타입의 데이터2
	 * @param b_offset 비교할 b 데이터의 시작 위치
	 * @param length 비교할 데이터의 길이
	 * @return 두 데이터가 같은 경우 true, 그렇지 않은 경우 false
	 */
	static public boolean equals(byte[] a, int a_offset, 
								  byte[] b, int b_offset, int length) {

	  		for (int i = 0; i < length; i++) {
	  			if (a[a_offset + i] != b[b_offset + i]) {
	  				return false;
	  			}
	  		}

	  		return true;
	 }
	
	/**
	 * 부분 데이터를 리턴한다. 리턴되는 부분 데이터는 입력한 지점부터 마지막 byte 까지를 포함한다.
	 * 
	 * @param data 데이터
	 * @param beginIndex 시작 지점
	 * @return 부분 데이터
	 */
	static public byte[] subBytes(byte[] data, int beginIndex) {
	
		return subBytes(data, beginIndex, data.length);
	}
	
	/**
	 * 부분 데이터를 리턴한다. 리턴되는 부분 데이터는 시작 지점(beginIndex)부터 마지막 지점(endIndex-1) 까지의
	 * byte를 포함한다.
	 * 
	 * @param data 데이터
	 * @param beginIndex 시작 지점
	 * @param endIndex 마지막 지점
	 * @return 부분 데이터
	 */
	static public byte[] subBytes(byte[] data, int beginIndex, int endIndex) {
		
		int len = endIndex - beginIndex;
		
		byte[] out = new byte[len];
		System.arraycopy(data, beginIndex, out, 0, len);
		return out;
	}
}
