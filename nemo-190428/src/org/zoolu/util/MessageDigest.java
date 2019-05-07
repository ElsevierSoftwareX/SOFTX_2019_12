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



/** Generic hash/message-digest algorithm.
  */
public abstract class MessageDigest {
	
	/** MessageDigest block update operation.
	  * Continues a message-digest operation,
	  * processing another message block, and updating the context. */
	abstract public MessageDigest update(byte[] buffer, int offset, int len);


	/** MessageDigest block update operation.
	  * Continues a message-digest operation,
	  * processing another message block, and updating the context. */
	public MessageDigest update(String str) {
		byte[] buf=str.getBytes();
		return update(buf,0,buf.length);
	}


	/** MessageDigest block update operation.
	  * Continues a message-digest operation,
	  * processing another message block, and updating the context. */
	public MessageDigest update(byte[] buffer) {
		return update(buffer,0,buffer.length);
	}


	/** MessageDigest finalization. Ends a message-digest operation, writing the
	  * the message digest and zeroizing the context. */
	abstract public byte[] doFinal();


	/** Gets the MessageDigest. The same as doFinal(). */
	public byte[] getDigest() {
		return doFinal();
	}


	/** Gets the Message Digest as string of hex values. */
	public String asHex() {
		return ByteUtils.asHex(doFinal());
	}

}
