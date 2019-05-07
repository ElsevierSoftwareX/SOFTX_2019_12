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


/** Generic Type-Length-Value (TLV) attribute.
  */
public abstract class TlvAttribute {
	
	/** Type */
	protected int type;

	/** Value buffer */
	protected byte[] buf;

	/** Value offset */
	protected int off;

	/** Length */
	protected int len;
	
	

	/** Creates a new TlvAttribute. */
	protected TlvAttribute() {
		this.type=0;
		this.len=0;
		this.buf=null;
		this.off=0;
	}


	/** Creates a new TlvAttribute.
	 * @param a the attribute to be copied */
	public TlvAttribute(TlvAttribute a) {
		this.type=a.type;
		this.len=a.len;
		this.buf=a.buf;
		this.off=a.off;
	}


	/** Creates a new TlvAttribute.
	 * @param type the value
	 * @param value the value */
	public TlvAttribute(int type, byte[] value) {
		this.type=type;
		this.len=value.length;
		this.buf=value;
		this.off=0;
	}


	/** Creates a new TlvAttribute.
	 * @param type the type
	 * @param buf the buffer containing the value
	 * @param off the offset within the buffer
	 * @param len the length of the value */
	public TlvAttribute(int type, byte[] buf, int off, int len) {
		this.type=type;
		this.buf=buf;
		this.off=off;
		this.len=len;
	}

	 
	/** Gets the type.
	 * @return the type */
	public int getType() {
		return type;
	}


	/** Gets value. */
	public byte[] getValue() {
		if (off==0 && buf.length==len) return buf;
		else {
			byte[] value=new byte[len];
			for (int i=0; i< len; i++) value[i]=buf[off+i];
			return value;
		}
	}


	@Override
	public boolean equals(Object obj) {
		try {
			TlvAttribute a=(TlvAttribute)obj;
			if (a.type==type && a.len==len && ByteUtils.match(a.buf,a.off,a.len,buf,off,len)) return true;
			else return false;
		}
		catch (Exception e) {  return false;  }
	}

	
	/** Gets the total length of the attribute.
	 * @return the total length including type, length, and value fields */
	public abstract int getTotalLength();

	
	/** Gets the byte array of this attribute.
	 * @return the byte array containing the attribute */
	public byte[] getBytes() {
		byte[] data=new byte[getTotalLength()];
		getBytes(data,0);
		return data;
	}

	
	/** Gets the byte array of this attribute.
	 * @param buf the buffer where the attribute has to be written
	 * @param off the offset within the buffer
	 * @return the length of the attribute */
	public abstract int getBytes(byte[] buf, int off);

	
	@Override
	public String toString() {
		StringBuffer sb=new StringBuffer();
		sb.append('{');
		sb.append(type).append(';');
		sb.append(len).append(';');
		sb.append("0x").append(ByteUtils.asHex(buf,off,len));
		sb.append('}');
		return sb.toString();
	}


	/** Gets a hexadecimal string representation value of this object. */
	public String toHexString() {
		return ByteUtils.asHex(getBytes());
	}
	
}
