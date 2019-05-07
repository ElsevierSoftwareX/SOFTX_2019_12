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

package it.unipr.netsec.ipstack.ppp;


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.net.DataPacket;


/** Point-to-Point Protocol (PPP) encapsulation.
 */
public class PppEncapsulation extends DataPacket {
	
	/** Type Padding Protocol */
	public static final int TYPE_PaddingProtocol=0x0001;
	/** Type IPv4 */
	public static final int TYPE_IP4=0x0021;
	/** Type OSI */
	public static final int TYPE_OSI=0x0023;
	/** Type AppleTalk */
	public static final int TYPE_AppleTalk=0x0029;
	/** Type Van Jacobson Compressed TCP/IP */
	public static final int TYPE_CompressedTCPIP=0x002d;
	/** Type Van Jacobson Uncompressed TCP/IP */
	public static final int TYPE_UncompressedTCPIP=0x002f;
	/** Type Bridging PDU */
	public static final int TYPE_BridgingPDU=0x0031;
	/** Type IPX */
	public static final int TYPE_IPX=0x002B;
	/** Type Multi-Link */
	public static final int TYPE_MultiLink=0x003D;
	/** Type NetBIOS */
	public static final int TYPE_NetBIOS=0x003F;
	/** Type IPv6 */
	public static final int TYPE_IP6=0x0057;
	/** Type MPLS Unicast */
	public static final int TYPE_MPLS=0x0281;
	/** Type MPLS Multicast */
	public static final int TYPE_MPLS_MULTICAST=0x0283;
	
	/** Type Link Control Protocol */
	public static final int TYPE_LCP=0xC021;
	/** Type Password Authentication Protocol */
	public static final int TYPE_PAP=0xC023;
	/** Type Shiva Password Authentication Protocol */
	public static final int TYPE_ShivaPAP=0xC027;
	/** Type CallBack Control Protocol (CBCP) */
	public static final int TYPE_CBCP=0xC029;
	/** Type Challenge Handshake Authentication Protocol */
	public static final int TYPE_CHAP=0xC223;
	/** Type RSA Authentication Protocol */
	public static final int TYPE_RSAP=0xC225;
	/** Type Extensible Authentication Protocol */
	public static final int TYPE_EAP=0xC227;


	/** Payload type */
	int protocol;
	
	/** Creates a new packet.
	 * @param protocol payload type
	 * @param data the payload data */
	public PppEncapsulation(int protocol, byte[] data) {
		this(protocol,data,0,data.length);
	}
	
	/** Creates a new packet.
	 * @param protocol payload type
	 * @param data_buf the buffer containing the payload data
	 * @param data_off the offset within the buffer
	 * @param data_len the payload length */
	public PppEncapsulation(int protocol, byte[] data_buf, int data_off, int data_len) {
		super(null,null,data_buf,data_off,data_len);
		this.protocol=protocol;
	}
	
	/** Gets payload type.
	 * @return the payload type */
	public int getProtocol() {
		return protocol;
	}
	
	@Override
	public int getPacketLength() {
		return data_len+2;
	}
	
	@Override
	public int getBytes(byte[] buf, int off) {
		ByteUtils.intToTwoBytes(protocol,buf,off);
		if (data_len>0) System.arraycopy(data_buf,data_off,buf,off+2,data_len);
		return data_len+2;
	}
	
	/** Parses the given raw data (array of bytes) for a PPP encapsulation.
	 * @param buf the buffer containing the PPP encapsulation
	 * @return the PPP encapsulation */
	public static PppEncapsulation parsePppEncapsulation(byte[] buf) {
		return parsePppEncapsulation(buf,0,buf.length);
	}
	
	/** Parses the given raw data (array of bytes) for a PPP encapsulation.
	 * @param buf the buffer containing the PPP encapsulation
	 * @param off the offset within the buffer
	 * @param len packet length
	 * @return the PPP encapsulation */
	public static PppEncapsulation parsePppEncapsulation(byte[] buf, int off, int len) {
		int protocol=ByteUtils.twoBytesToInt(buf,off);
		PppEncapsulation pkt=new PppEncapsulation(protocol,buf,off+2,len-2);
		return pkt;
	}

	@Override
	public String toString() {
		//return "PPP encapsulation {protocol="+protocol+", datalen="+getPayloadLength()+", payload="+ByteUtils.asHex(getPayload())+"}";
		return "PPP "+src_addr+" > "+dst_addr+" proto="+protocol+" datalen="+getPayloadLength();
	}

}
