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

package it.unipr.netsec.ipstack.ip6.exthdr;



/** A generic IPv6 extension header.
 */
public class ExtensionHeader {

	/** Hop-by-Hop Options Header [RFC2460] */
	public static final int HOP_OPTIONS_HDR=0;
	
	/** Routing Header [RFC2460] */
	public static final int ROUTING_HDR=43;

	/** Fragment Header [RFC2460] */
	public static final int FRAGMENT_HDR=44;

	/** Destination Options Header [RFC2460] */
	public static final int DST_OPTIONS_HDR=60;

	/** Encapsulating Security Payload [RFC4303] */
	public static final int ESP_HDR=50;

	/** Authentication header [RFC4302] */
	public static final int AUTH_HDR=51;

	/** Mobility Header [RFC6275] */
	public static final int MOBILITY_HDR=135;

	/** Host Identity Protocol [RFC5201] */
	public static final int HIP_HDR=139;

	/** Shim6 Protocol [RFC5533] */
	public static final int SHIM6_HDR=140;

	/** Use for experimentation and testing [RFC3692] [RFC4727] */
	public static final int TEST253_HDR=253;

	/** Use for experimentation and testing [RFC3692] [RFC4727] */
	public static final int TEST254_HDR=254;

	
	/** Extension header type */
	int type;

	/** Buffer containing the entire header */
	byte[] buf=null;
	
	/** Offset within the buffer */
	int off=0;
	
	/** Header length in octects */
	int len=0;

	/** Next header (1 octect). Identifies the type of header immediately following this header */
	//int next_header;

	
	
	/** Creates a new extension header.
	 * @param type header type */
	/*protected ExtensionHeader(int type) {
		this.type=type;
		this.buf=null;
		this.off=0;
		this.len=0;
	}*/

	
	/** Creates a new extension header.
	 * @param eh the header */
	protected ExtensionHeader(ExtensionHeader eh) {
		this.type=eh.type;
		this.buf=eh.buf;
		this.off=eh.off;
		this.len=eh.len;
	}

	
	/** Creates a new extension header.
	 * @param type header type
	 * @param buf buffer containing the header */
	public ExtensionHeader(int type, byte[] buf) {
		this.type=type;
		this.buf=buf;
		this.off=0;
		this.len=buf.length;
		if ((len%8)!=0) throw new RuntimeException("Extension header length must be a multiple of 8: "+len);
	}

	
	/** Creates a new extension header.
	 * @param type header type
	 * @param buf buffer containing the header
	 * @param off offset within the buffer
	 * @param len header length */
	public ExtensionHeader(int type, byte[] buf, int off, int len) {
		this.type=type;
		this.buf=buf;
		this.off=off;
		this.len=len;
		if ((len%8)!=0) throw new RuntimeException("Extension header length must be a multiple of 8: "+len);
	}

	
	/** Gets header type.
	 * @return the header type */
	public int getHeaderType() {
		return type;
	}

	
	/** Gets the next header field (1 octect).
	 * Identifies the type of header immediately following this header.
	 * @return the next header */
	public int getNextHdr() {
		return buf[off]&0xff;
	}

	
	/** Sets the next header field (1 octect).
	 * Identifies the type of header immediately following this header.
	 * @param next_header the next header */
	public void setNextHdr(int next_header) {
		buf[off]=(byte)next_header;
	}

	
	/** Gets the length of this header.
	 * @return the length */
	public int getLength() {
		return len;
	}

	
	/** Gets a the extension header in a byte array.
	 * @param buf the buffer where the extension header is written
	 * @param off the offset within the buffer
	 * @return the extension header length */
	public int getBytes(byte[] buf, int off) {
		System.arraycopy(this.buf,this.off,buf,off,this.len);
		return this.len;
	}

	
	/** Gets a the extension header in a byte array.
	 * @return a new byte array containing the extension header */
	public byte[] getBytes() {
		int len=getLength();
		byte[] data=new byte[len];
		getBytes(data,0);
		return data;
	}
	
}
