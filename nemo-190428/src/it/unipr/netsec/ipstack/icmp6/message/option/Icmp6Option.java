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

package it.unipr.netsec.ipstack.icmp6.message.option;


import it.unipr.netsec.ipstack.util.ByteTlvAttribute;


/** ICMP6 Neighbor Discovery option.
  * Each option is TLV encoded, with a 8-bit type, 8-bit length, and value.
  */
public class Icmp6Option extends ByteTlvAttribute {
	
	// ICMPv6 option types from RFC 4861:
	
	/** ICMP6 Type 1: Source Link-Layer Address */
	public static final int TYPE_Source_Link_Layer_Address=1;
	/** ICMP6 Type 2: Target Link-Layer Address */
	public static final int TYPE_Target_Link_Layer_Address=2;
	/** ICMP6 Type 3: Prefix Information */
	public static final int TYPE_Prefix_Information=3;
	/** ICMP6 Type 4: Redirected Header */
	public static final int TYPE_Redirected_Header=4;
    /** ICMP6 Type 5: MTU */
	public static final int TYPE_MTU=5;

	
	/** Creates a new ICMP6 option.
	 * @param a a TLV attribute */
	private Icmp6Option(ByteTlvAttribute a) {
		super(a);
		len=(buf[off+1]&0xff)*8-2;
	}

	/** Creates a new ICMP6 option.
	 * @param o the ICMPv6 option */
	protected Icmp6Option(Icmp6Option o) {
		super(o);
	}

	/** Creates a new ICMP6 option.
	 * @param type the option type
	 * @param value the value */
	public Icmp6Option(int type, byte[] value) {
		super(type,value);
		if (((value.length+2)%8)!=0) throw new RuntimeException("the length ("+(value.length+2)+") of the ICMPv6 option is not multiple of 8");
	}

	/** Creates a new ICMP6 option.
	 * @param type the option type
	 * @param buf buffer containing the value
	 * @param off the offset within the buffer
	 * @param len the value length */
	public Icmp6Option(int type, byte[] buf, int off, int len) {
		super(type,buf,off,len);
		if (((len+2)%8)!=0) throw new RuntimeException("the length ("+(len+2)+") of the ICMPv6 option is not multiple of 8");
	}

	/** Parses an ICMP6 option.
	 * @param buf buffer containing the option */
	public static Icmp6Option parseOption(byte[] buf) {
		return parseOption(buf,0);
	}

	/** Parses an ICMP6 option.
	 * @param buf buffer containing the option
	 * @param off the offset within the buffer */
	public static Icmp6Option parseOption(byte[] buf, int off) {
		return new Icmp6Option(ByteTlvAttribute.parseTlvAttribute(buf,off));
	}

	@Override
	public int getBytes(byte[] buf, int off) {
		buf[off++]=(byte)type;
		buf[off++]=(byte)((len+2)/8); 
		System.arraycopy(this.buf,this.off,buf,off,len);
		return len+2;
	}

}
