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


import it.unipr.netsec.ipstack.util.ByteTlvAttribute;


/** IPv6 option.
  * Each option is TLV encoded, with a 8-bit type, 8-bit length, and value.
  */
public class ExtensionHeaderOption extends ByteTlvAttribute {
	

	
	/** Creates a new option.
	 * @param o the option */
	private ExtensionHeaderOption(ByteTlvAttribute a) {
		super(a);
	}


	/** Creates a new option.
	 * @param o the option */
	protected ExtensionHeaderOption(ExtensionHeaderOption o) {
		super(o);
	}


	/** Creates a new option.
	 * @param type the option type
	 * @param value the value */
	public ExtensionHeaderOption(int type, byte[] value) {
		super(type,value);
	}


	/** Creates a new option.
	 * @param type the option type
	 * @param buf buffer containing the value
	 * @param off the offset within the buffer
	 * @param len the value length */
	public ExtensionHeaderOption(int type, byte[] buf, int off, int len) {
		super(type,buf,off,len);
	}


	/** Parses a new option.
	 * @param buf buffer containing the option */
	public static ExtensionHeaderOption parseOption(byte[] buf) {
		return parseOption(buf,0);
	}


	/** Parses a new option.
	 * @param buf buffer containing the option
	 * @param off the offset within the buffer */
	public static ExtensionHeaderOption parseOption(byte[] buf, int off) {
		return new ExtensionHeaderOption(ByteTlvAttribute.parseTlvAttribute(buf,off));
	}

}
