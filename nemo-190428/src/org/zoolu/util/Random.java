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



/** Class Random collects some static methods for generating
  * random numbers and other stuff.
  */
public class Random {
	
	/** The random seed */
	static final long seed=System.currentTimeMillis();
	//static final long seed=0;
	
	static java.util.Random rand=new java.util.Random(seed);
	//static java.util.Random rand=new java.util.Random();

	/** Returns a random integer between 0 and n-1 */
	/*static public int nextInt(int n) {
		seed=(seed*37)%987654321;
		return (int)(seed%n);
	}*/  

	/** Returns true or false respectively with probability p/100 and (1-p/100) */
	/*static boolean percent(int p) {
		return integer(100)<p;
	}*/

	/** Sets the seed of this random number generator using a single long seed */
	public static void setSeed(long seed) {
		rand.setSeed(seed);
	}

	/** Returns a random integer */
	public static int nextInt() {
		return rand.nextInt();
	}

	/** Returns a random integer between 0 and n-1 */
	public static int nextInt(int n) {
		return Math.abs(rand.nextInt())%n;
	}

	/** Returns a random long */
	public static long nextLong() {
		return rand.nextLong();
	}

	/** Returns a random long between 0 and n-1 */
	public static long nextLong(long n) {
		return Math.abs(rand.nextLong())%n;
	}
	/** Returns a random boolean */
	public static boolean nextBoolean() {
		return rand.nextInt(2)==1;
	}

	/** Returns a random double between 0 and 1 (exclusive) */
	public static double nextDouble() {
		return rand.nextDouble();
	}

	/** Returns a random array of bytes */
	public static byte[] nextBytes(int len) {
		byte[] buff=new byte[len];
		for (int i=0; i<len; i++) buff[i]=(byte)nextInt(256);
		return buff;
	}

	/** Returns a random String */
	public static String nextString(int len) {
		byte[] buff=new byte[len];
		for (int i=0; i<len; i++) {
			int n=nextInt(62);
			buff[i]=(byte)((n<10)? 48+n : ((n<36)? 55+n : 61+n));
		}
		return new String(buff);
	}

	/** Returns a random numeric String */
	public static String nextNumString(int len) {
		byte[] buff=new byte[len];
		for (int i=0; i<len; i++) buff[i]=(byte)(48+nextInt(10));
		return new String(buff);
	}

	/** Returns a random hexadecimal String */
	public static String nextHexString(int len) {
		byte[] buff=new byte[len];
		for (int i=0; i<len; i++) {
			int n=nextInt(16);
			buff[i]=(byte)((n<10)? 48+n : 87+n);
		}
		return new String(buff);
	}
}
