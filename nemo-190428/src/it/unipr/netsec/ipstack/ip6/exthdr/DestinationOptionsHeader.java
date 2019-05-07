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



/** IPv6 Destination Options Header.
 */
public class DestinationOptionsHeader extends OptionsHeader {
	

	
	/** Creates a new Destination Options header.
	 * @param eh the header */
	public DestinationOptionsHeader(ExtensionHeader eh) {
		super(eh);
	}

	
	/** Creates a new Destination Options header.
	 * @param buf buffer containing the header */
	public DestinationOptionsHeader(byte[] buf) {
		super(DST_OPTIONS_HDR,buf);
	}

	
	/** Creates a new Destination Options header.
	 * @param buf buffer containing the header
	 * @param off offset within the buffer
	 * @param len extension header length */
	public DestinationOptionsHeader(byte[] buf, int off, int len) {
		super(DST_OPTIONS_HDR,buf,off,len);
	}

	
	/** Creates a new Destination Options header.
	 * @param options options */
	public DestinationOptionsHeader(ExtensionHeaderOption[] options) {
		super(DST_OPTIONS_HDR,options);
	}

	
	/** Parses the given byte array for a Destination Options Header.
	 * @param buf the buffer containing the Destination Options Header
	 * @param off the offset within the buffer
	 * @param maxlen maximum number of bytes that can be processed
	 * @return the Destination Options Header */
	public static DestinationOptionsHeader parseDestinationOptionsHeader(byte[] buf, int off, int maxlen) {
		int len=8*(buf[off+1]+1);
		if (len>maxlen) throw new RuntimeException("Malformed Header: too long");
		// else
		return new DestinationOptionsHeader(buf,off,len);
	}
}
