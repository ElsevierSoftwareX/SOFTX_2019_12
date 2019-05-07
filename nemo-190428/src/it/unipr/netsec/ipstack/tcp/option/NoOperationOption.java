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


/** No-Operation option.
 */
public class NoOperationOption implements Option {

	static final byte[] OPTION_DATA=new byte[]{ (byte)TcpPacket.OPT_NO_OPERATION };
	
	public NoOperationOption() {
	}

	@Override
	public int getType() {
		return OPTION_DATA[0]&0xff;
	}

	@Override
	public int getTotalLength() {
		return 1;
	}

	@Override
	public int getBytes(byte[] buf, int off) {
		buf[off]=OPTION_DATA[0];
		return 1;
	}

	@Override
	public byte[] getBytes() {
		return OPTION_DATA;
	}

	@Override
	public String toString() {
		return "opt:no-operation";
	}

}
