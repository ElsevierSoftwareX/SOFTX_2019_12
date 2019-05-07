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


import it.unipr.netsec.ipstack.tcp.TcpPacket;


/** SACK Permitted option.
 */
public class SackPermittedOption extends TlvOption implements Option {
	
	private static final byte[] NO_VALUE=new byte[0];

	
	public SackPermittedOption() {
		super(TcpPacket.OPT_SACK_PERMITTED,NO_VALUE);
	}
	
	public SackPermittedOption(TlvOption opt) {
		super(opt);
		if (type!=TcpPacket.OPT_SACK_PERMITTED) throw new RuntimeException("TCP option type ("+type+") is not a \"SACK Permitted\" ("+TcpPacket.OPT_SACK_PERMITTED+")");
		if ((len+2)!=2) throw new RuntimeException("Length of TCP option \"SACK Permitted\" must be 2: "+(len+2));
	}

	public static SackPermittedOption parseOption(byte[] buf, int off) {
		return new SackPermittedOption(TlvOption.parseTlvOption(buf,off));
	}

	@Override
	public String toString() {
		return "opt:sack-permitted";
	}

}
