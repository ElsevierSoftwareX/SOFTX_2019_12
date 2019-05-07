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


/** ICMPv6 Destination Unreachable message.
 */
public class Icmp6DestinationUnreachableMessage extends Icmp6MessageWithDatagram {

	/** ICMP type */
	public static final int TYPE=Icmp6Message.TYPE_Destination_Unreachable;

	/** ICMP code 0: No route to destination */
	public static final int CODE_No_route_to_destination=0;

	/** ICMP code 1: Communication with destination administratively prohibited */
	public static final int CODE_Communication_with_destination_administratively_prohibited=1;

	/** ICMP code 2: Beyond scope of source address */
	public static final int CODE_Beyond_scope_of_source_address=2;

	/** ICMP code 3: Address unreachable */
	public static final int CODE_Address_unreachable=3;

	/** ICMP code 4: Port unreachable */
	public static final int CODE_Port_unreachable=4;

	/** ICMP code 5: Source address failed ingress/egress policy */
	public static final int CODE_Source_address_failed_ingress_egress_policy=5;

	/** ICMP code 6: Reject route to destination */
	public static final int CODE_Reject_route_to_destination=6;
	
	
	/** Creates a new ICMP Destination Unreachable message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param code ICMP subtype code
	 * @param ip_packet the original IP packet that triggered this ICMP message */
	public Icmp6DestinationUnreachableMessage(Ip6Address src_addr, Ip6Address dst_addr, int code, Ip6Packet ip_packet) {
		super(src_addr,dst_addr,TYPE,code,ip_packet);
	}

	
	/** Creates a new ICMP Destination Unreachable message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	public Icmp6DestinationUnreachableMessage(Ip6Address src_addr, Ip6Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a \"Destination Unreachable\" ("+TYPE+") ICMP message");
	}	

	
	/** Creates a new ICMP Destination Unreachable message.
	 * @param msg the ICMP message */
	public Icmp6DestinationUnreachableMessage(Icmp6Message msg) {
		super(msg);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a \"Destination Unreachable\" ("+TYPE+") ICMP message");
	}	

}
