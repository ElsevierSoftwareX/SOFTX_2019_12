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

package it.unipr.netsec.ipstack.icmp4.message;


import it.unipr.netsec.ipstack.icmp4.IcmpMessage;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.Address;

import java.util.Arrays;


/** Generic ICMP message containing a portion of the original IP datagram.
 */
abstract class IcmpMessageWithDatagram extends IcmpMessage {

    
	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param type ICMP message type
	 * @param code ICMP subtype code
	 * @param ip_packet the original IP datagram that this ICMP message is referred to */
	protected IcmpMessageWithDatagram(Address src_addr, Address dst_addr, int type, int code, Ip4Packet ip_datagram) {
		super(src_addr,dst_addr,type,code);
		int ip_payload_len=ip_datagram.getPayloadLength();
		int datagram_len=20+ip_datagram.getOptionsLength()+(ip_payload_len<=64? ip_payload_len : 64);
		icmp_body=new byte[4+datagram_len];
		Arrays.fill(icmp_body,0,4,(byte)0);
		System.arraycopy(ip_datagram.getBytes(),0,icmp_body,4,datagram_len);
	}
	

	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param type ICMP message type
	 * @param code ICMP subtype code
	 * @param datagram_buf the buffer with the portion of the original IP datagram that this ICMP message is referred to
	 * @param datagram_off the offset within the buffer
	 * @param datagram_len the length of the portion of the IP datagram included in this message */
	/*protected IcmpMessageWithDatagram(Address src_addr, Address dst_addr, int type, int code, byte[] datagram_buf, int datagram_off, int datagram_len) {
		super(src_addr,dst_addr,type,code);
		icmp_data=new byte[4+datagram_len];
		Arrays.fill(icmp_data,0,4,(byte)0);
		System.arraycopy(datagram_buf,datagram_off,icmp_data,4,datagram_len);
	}*/
	

	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	protected IcmpMessageWithDatagram(Address src_addr, Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
	}	

	
	/** Creates a new ICMP message.
	 * @param msg the ICMP message */
	protected IcmpMessageWithDatagram(IcmpMessage msg) {
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
