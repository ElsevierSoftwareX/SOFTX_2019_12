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

package it.unipr.netsec.ipstack.slip;


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.net.DataPacket;


/** Address Resolution Protocol (ARP) packet.
 */
public class SlipPacket extends DataPacket {

	/** END character */
	public static final byte END=(byte)192;

	/** ESC character */
	public static final byte ESC=(byte)219;

	/** Escaped END character */
	public static final byte XEND=(byte)220;

	/** Escaped ESC character */
	public static final byte XESC=(byte)221;

	/** Whether to insert an END delimiter also at the beginning of the frame (Phil Karn variant) */
	public static boolean WITH_BEGIN=false;

	
	/** Creates a new packet.
	 * @param data the payload data */
	public SlipPacket(byte[] data) {
		this(data,0,data.length);
	}
	
	/** Creates a new packet.
	 * @param data_buf the buffer containing the payload data
	 * @param data_off the offset within the buffer
	 * @param data_len the payload length */
	public SlipPacket(byte[] data_buf, int data_off, int data_len) {
		super(null,null,data_buf,data_off,data_len);
	}
	
	
	@Override
	public int getPacketLength() {
		int packet_len=data_len;
		for (int i=data_off, end=data_off+data_len; i<end; i++) {
			byte b=data_buf[i];
			if (b==END || b==ESC) packet_len++;
		}
		return packet_len+(WITH_BEGIN?2:1);
	}
	
	@Override
	public int getBytes(byte[] buf, int off) {
		int index=off;
		if (WITH_BEGIN) buf[index++]=END;
		for (int i=data_off, end=data_off+data_len; i<end; i++) {
			byte b=data_buf[i];
			if (b==END) {
				buf[index++]=ESC;
				buf[index++]=XEND;
			}
			else
			if (b==ESC) {
				buf[index++]=ESC;
				buf[index++]=XESC;
			}
			else buf[index++]=b;
		}
		buf[index++]=END;
		return index-off;
	}
	
	/** Parses the given raw data (array of bytes) for a SLIP packet.
	 * @param buf the buffer containing the packet
	 * @return the SLIP packet */
	public static SlipPacket parseSlipPacket(byte[] buf) {
		return parseSlipPacket(buf,0,buf.length);
	}
	
	/** Parses the given raw data (array of bytes) for a SLIP packet.
	 * @param buf the buffer containing the packet
	 * @param off the offset within the buffer
	 * @param len packet length
	 * @return the SLIP packet */
	public static SlipPacket parseSlipPacket(byte[] buf, int off, int len) {
		// skip initial END characters
		//while (len>0 && buf[off]==END) { off++; len--; }
		//if (len<=0) return null;
		// else
		int data_len=0;
		for (int i=off, end=off+len; ; i++) {
			if (i==end) throw new RuntimeException("Invalid SLIP frame: no END character found");
			byte b=buf[i];
			if (b==END) break;
			if (b==ESC) {
				b=buf[i+1];
				if (b!=XEND && b!=XESC) throw new RuntimeException("Invalid SLIP frame: invalid char sequence ESC+"+(0xff&b));
				continue;
			}
			data_len++;
		}
		if (data_len==0) return null;
		// lese
		byte[] data=new byte[data_len];
		int index=0;
		for (int i=off; ; i++) {
			byte b=buf[i];
			if (b==END) break;
			if (b==ESC) {
				b=buf[++i];
				if (b==XEND) data[index++]=END;
				else data[index++]=ESC;
				continue;
			}
			else data[index++]=b;
		}		
		SlipPacket pkt=new SlipPacket(data,0,data_len);
		return pkt;
	}

	@Override
	public String toString() {
		//return "SLIP packet {datalen="+getPayloadLength()+", payload="+ByteUtils.asHex(getBytes())+"}";
		return "SLIP frame datalen="+getPayloadLength();
	}

}
