/*
 * Copyright (c) 2018 Luca Veltri, University of Parma
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. IN NO EVENT
 * SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package org.zoolu.util;


/** Class that collects static methods for dealing with binary materials.
  */
public class BitUtils {
	
	private BitUtils() {
		// no constructors
	}
		
	/** Rotates the integer (32-bit word) w shifting n bits left.
	  * @param w the integer to be rotated
	  * @param n the nuber of bits to be shifted to the left */
	/*public static int rotateLeft(int w, int n) {
		return (w << n) | (w >>> (32-n));
	}*/

	/** Rotates the integer (32-bit word) w shifting n bits right.
	  * @param w the integer to be rotated
	  * @param n the nuber of bits to be shifted to the right */
	/*public static int rotateRight(int w, int n) {
		return (w >>> n) | (w << (32-n));
	}*/

	/** Rotates an array of integers (32-bit words), shifting 1 word left.
	  * @param w the array of integers to be shifted to the left */
	/*public static int[] rotateLeft(int[] w) {
		int len=w.length;
		int w1=w[len-1];
		for (int i=len-1; i>1; i--) w[i]=w[i-1];
		w[0]=w1;
		return w;
	}*/

	/** Rotates an array of integers (32-bit words), shifting 1 word right.
	  * @param w the array of integers to be shifted to the right */
	/*public static int[] rotateRight(int[] w) {
		int len=w.length;
		int w0=w[0];
		for (int i=1; i<len; i++) w[i-1]=w[i];
		w[len-1]=w0;
		return w;
	}*/

	/** Rotates an array of bytes, shifting 1 byte left.
	  * @param b the array of bytes to be shifted to the left */
	/*public static byte[] rotateLeft(byte[] b) {
		int len=b.length;
		byte b1=b[len-1];
		for (int i=len-1; i>1; i--) b[i]=b[i-1];
		b[0]=b1;
		return b;
	}*/

	/** Rotates an array of bytes, shifting 1 byte right.
	  * @param b the array of bytes to be shifted to the right */
	/*public static byte[] rotateRight(byte[] b) {
		int len=b.length;
		byte b0=b[0];
		for (int i=1; i<len; i++) b[i-1]=b[i];
		b[len-1]=b0;
		return b;
	}*/
	
	/** Converts a byte array into a binary string.
	 * @param data the byte array
	 * @return the binary string */
	/*public static String bytesToBinString(byte[] data) {
		return bytesToBinString(data,0,data.length);
	}*/

	/** Converts a byte array into a binary string.
	 * @param buf buffer containing the byte array
	 * @param off the offset within the buffer
	 * @param len the length of the array
	 * @return the binary string */
	/*public static String bytesToBinString(byte[] buf, int off, int len) {
		StringBuffer sb=new StringBuffer();
		int end=off+len;
		for (int i=off; i<end; i++) {
			int b=buf[i];
			for (int k=7; k>=0; k--) {
				sb.append((b>>k)&0x01);
				//if (k==4) sb.append(" ");
			}
			//if (i<(end-1)) sb.append(" ");
		}
		return sb.toString();
	}*/
	
}
