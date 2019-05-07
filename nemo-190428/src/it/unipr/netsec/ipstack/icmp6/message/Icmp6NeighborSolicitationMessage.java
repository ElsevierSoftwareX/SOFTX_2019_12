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
import it.unipr.netsec.ipstack.icmp6.message.option.Icmp6Option;
import it.unipr.netsec.ipstack.ip6.Ip6Address;


/** ICMP Neighbor Solicitation message.
 */
public class Icmp6NeighborSolicitationMessage extends Icmp6MessageWithOptions {

	/** ICMP type */
	public static final int TYPE=Icmp6Message.TYPE_Neighbor_Solicitation;

	/** ICMP code: 0 */
	public static final int CODE=0;

	/** Options offset within the message body */
	private static final int OPT_OFF=20;

	
	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param target_address target address, that is the IP address of the target of the solicitation
	 * @param options array of options */
	public Icmp6NeighborSolicitationMessage(Ip6Address src_addr, Ip6Address dst_addr, Ip6Address target_address, Icmp6Option[] options) {
		super(src_addr,dst_addr,TYPE,CODE,OPT_OFF,options);
		target_address.getBytes(icmp_body,4);
	}
	

	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	public Icmp6NeighborSolicitationMessage(Ip6Address src_addr, Ip6Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,OPT_OFF,buf,off,len);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a ICMPv6 \"Neighbor Solicitation\" ("+TYPE+") message");
		if (code!=CODE) throw new RuntimeException("ICMP code missmatch ("+code+"): the code should be "+CODE);
	}	

	
	/** Creates a new ICMP message.
	 * @param msg the ICMP message */
	public Icmp6NeighborSolicitationMessage(Icmp6Message msg) {
		super(msg,OPT_OFF);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a ICMPv6 \"Neighbor Solicitation\" ("+TYPE+") message");
		if (code!=CODE) throw new RuntimeException("ICMP code missmatch ("+code+"): the code should be "+CODE);
	}	

	
	/** Gets the target address, that is the IP address of the target of the solicitation.
	 * @return the target address */
	public Ip6Address getTargetAddress() {
		return new Ip6Address(icmp_body,4);
	}

}
