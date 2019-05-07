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

package it.unipr.netsec.ipstack.tcp.option;


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.util.ByteTlvAttribute;


/** Generic TLV option.
 * <p>
 * The length field in TLV is the length of the entire option.
 */
public class TlvOption extends ByteTlvAttribute implements Option {
	
	private TlvOption(ByteTlvAttribute a) {
		super(a);
		this.len-=2;
	}
	
	public TlvOption(int type, byte[] value) {
		super(type,value);
	}
	
	public TlvOption(int type, byte[] buf, int off, int len) {
		super(type,buf,off,len);
	}

	public TlvOption(TlvOption opt) {
		super(opt);
	}
	
	public static TlvOption parseTlvOption(byte[] buf, int off) {
		return new TlvOption(ByteTlvAttribute.parseTlvAttribute(buf,off));
	}
	
	@Override
	public int getBytes(byte[] buf, int off) {
		buf[off++]=(byte)type;
		buf[off++]=(byte)(len+2); 
		System.arraycopy(this.buf,this.off,buf,off,len);
		return len+2;
	}

	@Override
	public String toString() {
		if (len==0) return "opt:"+type;
		else return "opt:"+type+"=0x"+ByteUtils.asHex(getValue());
	}

}
