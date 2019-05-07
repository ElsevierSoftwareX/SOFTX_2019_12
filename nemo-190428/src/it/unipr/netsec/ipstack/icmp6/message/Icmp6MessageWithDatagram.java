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

package it.unipr.netsec.ipstack.icmp6.message;


import it.unipr.netsec.ipstack.icmp6.Icmp6Message;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;

import java.util.Arrays;


/** Generic ICMPv6 message containing a portion of the original IP datagram.
 */
abstract class Icmp6MessageWithDatagram extends Icmp6Message {

    
	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param type ICMP message type
	 * @param code ICMP subtype code
	 * @param ip_packet the original IP datagram that this ICMP message is referred to */
	protected Icmp6MessageWithDatagram(Ip6Address src_addr, Ip6Address dst_addr, int type, int code, Ip6Packet ip_datagram) {
		super(src_addr,dst_addr,type,code);
		int datagram_len=ip_datagram.getPacketLength();
		if ((datagram_len+8)>Ip6Packet.MIN_MTU) datagram_len=Ip6Packet.MIN_MTU-8;
		icmp_body=new byte[4+datagram_len];
		Arrays.fill(icmp_body,0,4,(byte)0);
		System.arraycopy(ip_datagram.getBytes(),0,icmp_body,4,datagram_len);
	}
	

	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	protected Icmp6MessageWithDatagram(Ip6Address src_addr, Ip6Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
	}	

	
	/** Creates a new ICMP message.
	 * @param msg the ICMP message */
	protected Icmp6MessageWithDatagram(Icmp6Message msg) {
		super(msg);
	}
	
	
	/** Gets the datagram fragment included in the ICMP message.
		@return the datagram fragment */
	public byte[] getDatagramFragment() {
		byte[] datagram=new byte[icmp_body.length-4];
		System.arraycopy(icmp_body,4,datagram,0,datagram.length);
		return datagram;
		
	}
}
