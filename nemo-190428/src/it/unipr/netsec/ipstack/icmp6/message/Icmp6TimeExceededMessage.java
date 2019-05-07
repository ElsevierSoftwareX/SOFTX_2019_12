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


/** ICMPv6 Time Exceeded message.
 */
public class Icmp6TimeExceededMessage extends Icmp6MessageWithDatagram {
   
	/** ICMP type */
	public static final int TYPE=Icmp6Message.TYPE_Time_Exceeded;

	/** ICMP code: time to live exceeded in transit */
	public static final int CODE_time_to_live_exceeded_in_transit=0;

	/** ICMP code: fragment reassembly time exceeded */
	public static final int CODE_fragment_reassembly_time_exceeded=1;

	
	
	/** Creates a new ICMP Time Exceeded message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param code ICMP subtype code
	 * @param ip_packet the original IP packet that triggered this ICMP message */
	public Icmp6TimeExceededMessage(Ip6Address src_addr, Ip6Address dst_addr, int code, Ip6Packet ip_packet) {
		super(src_addr,dst_addr,TYPE,code,ip_packet);
	}

	
	/** Creates a new ICMP Time Exceeded message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	public Icmp6TimeExceededMessage(Ip6Address src_addr, Ip6Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a \"Time Exceeded\" ("+TYPE+") ICMP message");
	}	

	
	/** Creates a new ICMP Time Exceeded message.
	 * @param msg the ICMP message */
	public Icmp6TimeExceededMessage(Icmp6Message msg) {
		super(msg);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a \"Time Exceeded\" ("+TYPE+") ICMP message");
	}	

}
