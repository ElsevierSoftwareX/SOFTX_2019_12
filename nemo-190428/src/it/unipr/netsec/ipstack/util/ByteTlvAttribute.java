/*
 * Copyright 2018 NetSec Lab - University of Parma
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author(s):
 * Luca Veltri (luca.veltri@unipr.it)
 */

package it.unipr.netsec.ipstack.util;



/** Type-Length-Value (TLV) attribute with a 8-bit type and 8-bit length.
 * <p>
 * The length field in TLV is the length of the value. The {@link #getTotalLength()} method
 * returns the length of the entire attribute (i.e. value length + 2).
 */
public class ByteTlvAttribute extends TlvAttribute {
	

	
	/** Creates a new attribute.
	 * @param a the attribute */
	protected ByteTlvAttribute(TlvAttribute a) {
		super(a);
	}


	/** Creates a new attribute.
	 * @param type the attribute type
	 * @param value the value */
	public ByteTlvAttribute(int type, byte[] value) {
		super(type,value);
	}


	/** Creates a new attribute.
	 * @param type the attribute type
	 * @param buf buffer containing the value
	 * @param off the offset within the buffer
	 * @param len the value length */
	public ByteTlvAttribute(int type, byte[] buf, int off, int len) {
		super(type,buf,off,len);
	}


	/** Parses a attribute.
	 * @param buf buffer containing the attribute */
	public static ByteTlvAttribute parseTlvAttribute(byte[] buf) {
		return parseTlvAttribute(buf,0);
	}


	/** Parses a attribute.
	 * @param buf buffer containing the attribute
	 * @param off the offset within the buffer */
	public static ByteTlvAttribute parseTlvAttribute(byte[] buf, int off) {
		int type=buf[off]&0xff;
		int len=(buf[off+1]&0xff);
		off+=2;
		return new ByteTlvAttribute(type,buf,off,len);
	}


	@Override
	public int getTotalLength() {
		return len+2;
	}

	
	@Override
	public int getBytes(byte[] buf, int off) {
		buf[off++]=(byte)type;
		buf[off++]=(byte)len; 
		System.arraycopy(this.buf,this.off,buf,off,len);
		return len+2;
	}

}

