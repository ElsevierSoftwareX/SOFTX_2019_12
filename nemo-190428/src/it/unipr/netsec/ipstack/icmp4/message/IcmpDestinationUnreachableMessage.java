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


/** ICMP Destination Unreachable message.
 */
public class IcmpDestinationUnreachableMessage extends IcmpMessageWithDatagram {

    
	/** ICMP code: net unreachable */
	public static final int CODE_net_unreachable=0;

	/** ICMP code: host unreachable */
	public static final int CODE_host_unreachable=1;

	/** ICMP code: protocol unreachable */
	public static final int CODE_protocol_unreachable=2;

	/** ICMP code: port unreachable */
	public static final int CODE_port_unreachable=3;

	/** ICMP code: fragmentation needed and DF set */
	public static final int CODE_fragmentation_needed_and_DF_set=4;

	/** ICMP code: source route failed */
	public static final int CODE_source_route_failed=5;

	
	
	/** Creates a new ICMP Destination Unreachable message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param code ICMP subtype code
	 * @param ip_packet the original IP packet that triggered this ICMP message */
	public IcmpDestinationUnreachableMessage(Address src_addr, Address dst_addr, int code, Ip4Packet ip_packet) {
		super(src_addr,dst_addr,IcmpMessage.TYPE_Destination_Unreachable,code,ip_packet);
	}

	
	/** Creates a new ICMP Destination Unreachable message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	public IcmpDestinationUnreachableMessage(Address src_addr, Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
		if (type!=IcmpMessage.TYPE_Destination_Unreachable) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a \"Destination Unreachable\" ("+IcmpMessage.TYPE_Destination_Unreachable+") ICMP message");
	}	

	
	/** Creates a new ICMP Destination Unreachable message.
	 * @param msg the ICMP message */
	public IcmpDestinationUnreachableMessage(IcmpMessage msg) {
		super(msg);
		if (type!=IcmpMessage.TYPE_Destination_Unreachable) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a \"Destination Unreachable\" ("+IcmpMessage.TYPE_Destination_Unreachable+") ICMP message");
	}	

}
