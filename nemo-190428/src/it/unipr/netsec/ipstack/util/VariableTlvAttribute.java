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


import org.zoolu.util.ByteUtils;


/** Type-Length-Value (TLV) attribute with type and length fields with given size.
 * <p>
 * The length field in TLV is the length of the value. The {@link #getTotalLength()} method
 * returns the length of the entire attribute (i.e. type field size + length field size + value length).
 */
public class VariableTlvAttribute extends TlvAttribute {
	
	/** Type field size */
	int type_size;
	
	/** Length field size */
	int length_size;

	
	/** Creates a new attribute.
	 * @param a the attribute */
	protected VariableTlvAttribute(VariableTlvAttribute a) {
		super(a);
		this.type_size=a.type_size;
		this.length_size=a.length_size;
	}

	/** Creates a new attribute.
	 * @param type_size the type field size (in bytes)
	 * @param length_size the length_size field size (in bytes)
	 * @param type the attribute type
	 * @param value the value */
	public VariableTlvAttribute(int type_size, int length_size, int type, byte[] value) {
		super(type,value);
		this.type_size=type_size;
		this.length_size=length_size;
	}

	/** Creates a new attribute.
	 * @param type_size the type field size (in bytes)
	 * @param length_size the length_size field size (in bytes)
	 * @param type the attribute type
	 * @param buf buffer containing the value
	 * @param off the offset within the buffer
	 * @param len the value length */
	public VariableTlvAttribute(int type_size, int length_size, int type, byte[] buf, int off, int len) {
		super(type,buf,off,len);
		this.type_size=type_size;
		this.length_size=length_size;
	}

	/** Parses a TLV attribute.
	 * @param type_size the type field size (in bytes)
	 * @param length_size the length_size field size (in bytes)
	 * @param buf buffer containing the attribute
	 * @return the new TLV attribute */
	public static VariableTlvAttribute parseTlvAttribute(int type_size, int length_size, byte[] buf) {
		return parseTlvAttribute(type_size,length_size,buf,0);
	}

	/** Parses a TLV attribute.
	 * @param type_size the type field size (in bytes)
	 * @param length_size the length_size field size (in bytes)
	 * @param buf buffer containing the attribute
	 * @param off the offset within the buffer
	 * @return the new TLV attribute */
	public static VariableTlvAttribute parseTlvAttribute(int type_size, int length_size, byte[] buf, int off) {
		int type=(int)ByteUtils.nBytesToInt(buf,off,type_size);
		off+=type_size;
		int len=(int)ByteUtils.nBytesToInt(buf,off,length_size);
		off+=length_size;		
		return new VariableTlvAttribute(type_size,length_size,type,buf,off,len);
	}

	@Override
	public int getTotalLength() {
		return type_size+length_size+len;
	}
	
	@Override
	public int getBytes(byte[] buf, int off) {
		ByteUtils.intToNBytes(type,buf,off,type_size);
		off+=type_size;
		ByteUtils.intToNBytes(len,buf,off,length_size);
		off+=length_size;
		System.arraycopy(this.buf,this.off,buf,off,len);
		return type_size+length_size+len;
	}

}

