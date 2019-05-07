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


/** Window Scale option.
 */
public class WindowScaleOption extends TlvOption {
	
	public WindowScaleOption(int scale) {
		super(TcpPacket.OPT_WINDOW_SCALE,new byte[]{ (byte)scale });
	}
	
	public WindowScaleOption(TlvOption opt) {
		super(opt);
		if (type!=TcpPacket.OPT_WINDOW_SCALE) throw new RuntimeException("TCP option type ("+type+") is not a \"Window Scale\" ("+TcpPacket.OPT_WINDOW_SCALE+")");
		if ((len+2)!=3) throw new RuntimeException("Length of TCP option \"Window Scale\" must be 3: "+(len+2));
	}

	public static WindowScaleOption parseOption(byte[] buf, int off) {
		return new WindowScaleOption(TlvOption.parseTlvOption(buf,off));
	}
	
	public int getScale() {
		return 0xff&buf[off];
	}
	
	@Override
	public String toString() {
		return "opt:window-scale="+getScale();
	}

}
