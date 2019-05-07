package it.unipr.netsec.ipstack.dhcp;



/** DhcpMangle collects all static methods for mangling dhcp binary-data structures 
  */
public class Mangle {
	

	/** Compares two arrays of bytes */
	public static boolean compare(byte[] a, byte[] b) {
		if (a.length!=b.length) return false;
		for (int i=0; i<a.length; i++)
			if (a[i]!=b[i]) return false;
		return true;
	}
	
	/** Initalizes a byte array with value <i>value</i> */
	public static byte[] initBytes(byte[] b, int value) {
		for (int i=0; i<b.length; i++) b[i]=(byte)value;
		return b;
	}

	/** Transforms a byte into a unsigned byte (short) */
	public static short uByte(byte b) {
		return (short)(((short)b+256)%256);
	} 

	/** Returns a <i>n</i>-byte array from array <i>b</i> with offset <i>index</i> */
	public static byte[] nBytes(int n, byte[] b, int index) { byte[] bb=new byte[n]; for (int k=0; k<n; k++) bb[k]=b[index+k]; return bb; }
	
	/** Returns a 2-byte array from array <i>b</i> with offset <i>index</i> */
	public static byte[] twoBytes(byte[] b, int index) { return nBytes(2,b,index); }
	
	/** Returns a 4-byte array from array <i>b</i> with offset <i>index</i> */
	public static byte[] fourBytes(byte[] b, int index) { return nBytes(4,b,index); }
	
	/** Copies the first <i>n</i> bytes of array <i>s</i> into array <i>d</i> with offset <i>index</i> */
	public static void copyNBytes(int n, byte[] s, byte[] d, int index) { for (int k=0; k<n; k++) d[index+k]=s[k]; }
	
	/** Copies the all bytes of array <i>s</i> into array <i>d</i> with offset <i>index</i> */
	public static void copyAllBytes(byte[] s, byte[] d, int index) { for (int k=0; k<s.length; k++) d[index+k]=s[k]; }

	/** Copies the first 2 bytes of array <i>s</i> into array <i>d</i> with offset <i>index</i> */
	public static void copyTwoBytes(byte[] s, byte[] d, int index) { copyNBytes(2,s,d,index); }
	
	/** Copies a the first 4 bytes of array <i>s</i> into array <i>d</i> with offset <i>index</i> */
	public static void copyFourBytes(byte[] s, byte[] d, int index) { copyNBytes(4,s,d,index); }

	/** Transforms a string into a null-terminated byte array */
	public static byte[] stringToBytes(String str) {
		if (str==null)
			return null;
		if (str.charAt(str.length()-1)!='\0') str+='\0';
		return str.getBytes();
	}
	
	/** Transforms a string into a null-terminated <i>n</i>-bytes array.
	  * If string length is less than <i>n</i> it is filled with zeros */
	public static byte[] stringToBytes(String str, int n) {
		if (str==null)
			return initBytes(new byte[n],0);
		if (str.charAt(str.length()-1)!='\0') str+='\0';
		byte[] b=new byte[n];
		byte[] buff=str.getBytes();
		for (int i=0; i<n; i++)
			if (i<str.length()) b[i]=buff[i]; else b[i]=0;
		b[n-1]=0; // in case of str is greater than n put a null char at the end
		return b;
	}

	/** Transforms a byte array into a string */
	public static String bytesToString(byte[] b) {
		String s=new String(b);
		return s.trim();
	}

	/** Transforms th first <i>len</i> bytes of an array into a string of hex values */
	public static String bytesToHexString(byte[] b, int len) {
		String s=new String();
		for (int i=0; i<len; i++) {
			s+=Integer.toHexString((((b[i]+256)%256)/16)%16);
			s+=Integer.toHexString(((b[i]+256)%256)%16);
		}
		return s;
	}

	/** Transforms a byte array into a string of hex values */
	public static String bytesToHexString(byte[] b) {
		return bytesToHexString(b,b.length);
	}
		 
	/** Transforms a string of hex values into a <i>n</i>-bytes array.
	  * The string may include ':' chars. 
	  * If string length is less than <i>n</i>, the array is filled with zeros. */
	public static byte[] hexStringToBytes(String str, int n) {
		if (str.indexOf(":")>=0) {
			// the string is in the form of xx:yy:zz:ww.., so remove all ':' first
			String aux="";
			char c;
			for (int i=0; i<str.length(); i++)
				if ((c=str.charAt(i))!=':') aux+=c;
			str=aux; 
		} 
		byte[] b=new byte[n];
		for (int i=0; i<n; i++) {
			//int lo=Integer.parseInt(String.valueOf(str.charAt(i*2)),16);
			//int hi=Integer.parseInt(String.valueOf(str.charAt(i*2+1)),16);
			//b[i]=hi*16+lo;
			if (n<str.length()/2) b[i]=(byte)Integer.parseInt(str.substring(i*2,i*2+2),16);
			else b[i]=0;
		}
		return b;
	}
	
	/** Transforms a string of hex values into a <i>n</i>-bytes array.
	  * The string may include ':' chars. */
	public static byte[] hexStringToBytes(String str) {
		return hexStringToBytes(str,str.length()/2); 
	}

	/** Transforms a four-bytes array into a dotted four-decimals string */
	public static String fourBytesToAddress(byte[] b) {
		return Integer.toString(uByte(b[0]))+"."+Integer.toString(uByte(b[1]))+"."+Integer.toString(uByte(b[2]))+"."+Integer.toString(uByte(b[3]));
	}
	
	/** Transforms a dotted four-decimals string into a four-bytes array */
	public static byte[] addressToFourBytes(String addr) {
		int begin=0, end;
		byte[] b=new byte[4];
		for (int i=0; i<4; i++) {
			String num;
			if (i<3) {
				end=addr.indexOf('.',begin);
				b[i]=(byte)Integer.parseInt(addr.substring(begin,end));
				begin=end+1;
			}
		else b[3]=(byte)Integer.parseInt(addr.substring(begin));
		}
		return b;
	} 
	
	/** Transforms a 4-bytes array into a long, representing a time */
	public static long fourBytesToTime(byte[] b) {
		return ((((((long)uByte(b[0])<<8)+uByte(b[1]))<<8)+uByte(b[2]))<<8)+uByte(b[3]);
	}
	
	/** Transforms a long, representing a time, into a 4-bytes array */
	public static byte[] timeToFourBytes(long secs) {
		byte[] time=new byte[4];
		time[0]=(byte)(secs>>24);
		time[1]=(byte)((secs>>16)%256);
		time[2]=(byte)((secs>>8)%256);
		time[3]=(byte)(secs%256);
		return time;
	}


}
