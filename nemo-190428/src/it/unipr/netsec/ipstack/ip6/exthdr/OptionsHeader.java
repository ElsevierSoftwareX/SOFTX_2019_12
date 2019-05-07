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


import java.util.ArrayList;


/** IPv6 Destination and Hop-By-Hop Options Header.
 */
public abstract class OptionsHeader extends ExtensionHeader {
	

	
	/** Creates a new Destination Options header.
	 * @param eh the header */
	protected OptionsHeader(ExtensionHeader eh) {
		super(eh);
	}

	
	/** Creates a new Destination Options header.
	 * @param type header type
	 * @param buf buffer containing the header */
	protected OptionsHeader(int type, byte[] buf) {
		super(type,buf);
	}

	
	/** Creates a new Destination Options header.
	 * @param type header type
	 * @param buf buffer containing the header
	 * @param off offset within the buffer
	 * @param len extension header length */
	protected OptionsHeader(int type, byte[] buf, int off, int len) {
		super(type,buf,off,len);
	}

	
	/** Creates a new Destination Options header.
	 * @param type header type
	 * @param options options */
	protected OptionsHeader(int type, ExtensionHeaderOption[] options) {
		super(type,new byte[headerLength(options)]);
		int index=0;
		buf[index++]=0; // next hdr
		buf[index++]=(byte)(len/8-1); // len
		for (ExtensionHeaderOption o : options) {
			index+=o.getBytes(buf,index);
		}
		// add pad
		int pad=off+len-index;
		if (pad==1) {
			// append pad1 option
			buf[index++]=0;
		}
		else
		if (pad>1) {
			// append padN option
			buf[index++]=1;
			buf[index++]=(byte)(pad-2);
			while (index<off+len) buf[index++]=0;
		}			
	}

	
	/** Computes the header length based on the selected fields.
	 * @param options options */
	private static int headerLength(ExtensionHeaderOption[] options) {
		int len=2;
		for (ExtensionHeaderOption o : options) len+=o.getTotalLength();
		len=((len+7)/8)*8;
		return len;
	}

	
	/** Gets options.
	 * @return array of options */
	public ExtensionHeaderOption[] getOptions() {
		ArrayList<ExtensionHeaderOption> options=new ArrayList<ExtensionHeaderOption>();
		int index=off+2;
		if (index<off+len) {
			if (buf[index]==0) {
				// Pad1 option
				index++;
			}
			else
			if (buf[index]==1) {
				// PadN option
				index+=buf[index+1];
			}
			else {
				ExtensionHeaderOption o=ExtensionHeaderOption.parseOption(buf,index);
				options.add(o);
				index+=o.getTotalLength();
			}
		}
		return options.toArray(new ExtensionHeaderOption[]{});
	}
	
}
