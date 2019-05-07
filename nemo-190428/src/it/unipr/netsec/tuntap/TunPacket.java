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

package it.unipr.netsec.tuntap;


import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.DataPacket;

import org.zoolu.util.ByteUtils;


/** Linux/Mac OS TUN data unit.
 */
public class TunPacket extends DataPacket{

	/** Type IP */
	public static final int TYPE_IP; // 0x0800 on Linux, 0x0002 on Mac OS 
	
	static {
		TYPE_IP=System.getProperty("os.name").toLowerCase().startsWith("mac")? 0x0002 : 0x0800;
	}
	
	/** Flags */
	int flags;

	/** Type */
	int type;

	
	/** Creates a new TUN packet. */
	public TunPacket(byte[] buf, int off, int len) {
		super(null,null,buf,off+4,len-4);
		flags=ByteUtils.twoBytesToInt(buf,off);
		type=ByteUtils.twoBytesToInt(buf,off+2);
	}


	/** Creates a new TUN packet. */
	public TunPacket(int flags, int type, byte[] buf, int off, int len) {
		super(null,null,buf,off,len);
		this.flags=flags;
		this.type=type;
	}


	/** Creates a new TUN packet. */
	public TunPacket(int flags, int type, byte[] data) {
		super(null,null,data,0,data.length);
		this.flags=flags;
		this.type=type;
	}


	/** Creates a new TUN packet. */
	public TunPacket(Ip4Packet ip_pkt) {
		super(null,null,ip_pkt.getBytes(),0,ip_pkt.getPacketLength());
		flags=0;
		type=TYPE_IP;
	}


	/** Gets flags */
	public int getFlags() {
		return flags;
	}


	/** Gets payload type */
	public int getPayloadType() {
		return type;
	}


	@Override
	public int getPacketLength() {
		return data_len+4;
	}


	@Override
	public int getBytes(byte[] buf, int off) {
		ByteUtils.intToTwoBytes(flags,buf,off);
		ByteUtils.intToTwoBytes(type,buf,off+2);
		System.arraycopy(data_buf,data_off,buf,off+4,data_len);
		return data_len+4;
	}

	@Override
	public String toString() {
		StringBuffer sb=new StringBuffer();
		sb.append("flags=0x").append(ByteUtils.asHex(ByteUtils.intToTwoBytes(flags)));
		sb.append(",type=0x").append(Integer.toHexString(type));
		sb.append(",length=").append(getPayloadLength());
		sb.append(",data=").append(ByteUtils.asHex(getPayload()));
		return sb.toString();
	}

}
