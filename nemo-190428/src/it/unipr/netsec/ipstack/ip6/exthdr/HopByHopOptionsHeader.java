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



/** IPv6 Hop-By-Hop Options Header.
 */
public class HopByHopOptionsHeader extends OptionsHeader {
	

	
	/** Creates a new Destination Options header.
	 * @param eh the header */
	public HopByHopOptionsHeader(ExtensionHeader eh) {
		super(eh);
	}

	
	/** Creates a new Destination Options header.
	 * @param buf buffer containing the header */
	public HopByHopOptionsHeader(byte[] buf) {
		super(HOP_OPTIONS_HDR,buf);
	}

	
	/** Creates a new Destination Options header.
	 * @param buf buffer containing the header
	 * @param off offset within the buffer
	 * @param len extension header length */
	public HopByHopOptionsHeader(byte[] buf, int off, int len) {
		super(HOP_OPTIONS_HDR,buf,off,len);
	}

	
	/** Creates a new Destination Options header.
	 * @param options options */
	public HopByHopOptionsHeader(ExtensionHeaderOption[] options) {
		super(HOP_OPTIONS_HDR,options);
	}

	
	/** Parses the given byte array for a Hop-By-Hop Options Header.
	 * @param buf the buffer containing the Hop-By-Hop Options Header
	 * @param off the offset within the buffer
	 * @param maxlen maximum number of bytes that can be processed
	 * @return the Hop-By-Hop Options Header */
	public static HopByHopOptionsHeader parseHopByHopOptionsHeader(byte[] buf, int off, int maxlen) {
		int len=8*(buf[off+1]+1);
		if (len>maxlen) throw new RuntimeException("Malformed Header: too long");
		// else
		return new HopByHopOptionsHeader(buf,off,len);
	}
}
