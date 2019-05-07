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


/** Maximum Segment Size option.
 */
public class MaximumSegmentSizeOption extends TlvOption {
	
	public MaximumSegmentSizeOption(int max_segment_size) {
		super(TcpPacket.OPT_MAXIMUM_SEGMENT_SIZE,ByteUtils.intToTwoBytes(max_segment_size));
	}
	
	public MaximumSegmentSizeOption(TlvOption opt) {
		super(opt);
		if (type!=TcpPacket.OPT_MAXIMUM_SEGMENT_SIZE) throw new RuntimeException("TCP option type ("+type+") is not a \"Maximum Segment Size\" ("+TcpPacket.OPT_MAXIMUM_SEGMENT_SIZE+")");
		if ((len+2)!=4) throw new RuntimeException("Length of TCP option \"Maximum Segment Size\" must be 4: "+(len+2));
	}

	public static MaximumSegmentSizeOption parseOption(byte[] buf, int off) {
		return new MaximumSegmentSizeOption(TlvOption.parseTlvOption(buf,off));
	}
	
	public int getMaximumSegmentSize() {
		return ByteUtils.twoBytesToInt(buf,off);
	}
	
	@Override
	public String toString() {
		return "opt:mss="+getMaximumSegmentSize();
	}

}
