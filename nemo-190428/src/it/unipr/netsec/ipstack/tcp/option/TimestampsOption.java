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

import it.unipr.netsec.ipstack.tcp.TcpPacket;


/** Timestamps option.
 */
public class TimestampsOption extends TlvOption {
	
	public TimestampsOption(byte[] value) {
		super(TcpPacket.OPT_TIMESTAMPS,value,0,10);
	}
	
	public TimestampsOption(TlvOption opt) {
		super(opt);
		if (type!=TcpPacket.OPT_TIMESTAMPS) throw new RuntimeException("TCP option type ("+type+") is not a \"Timestamps\" ("+TcpPacket.OPT_TIMESTAMPS+")");
		if ((len+2)!=10) throw new RuntimeException("Length of TCP option \"Timestamps\" must be 10: "+(len+2));
	}

	public static TimestampsOption parseOption(byte[] buf, int off) {
		return new TimestampsOption(TlvOption.parseTlvOption(buf,off));
	}
	
	@Override
	public String toString() {
		return "opt:timestamps=0x"+ByteUtils.asHex(buf,off,len);
	}

}
