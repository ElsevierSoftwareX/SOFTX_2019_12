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


/** ICMP Neighbor Advertisement message.
 */
public class Icmp6NeighborAdvertisementMessage extends Icmp6MessageWithOptions {

	/** ICMP type */
	public static final int TYPE=Icmp6Message.TYPE_Neighbor_Advertisement;

	/** ICMP code: 0 */
	public static final int CODE=0;

	/** Options offset within the message body */
	private static final int OPT_OFF=20;

	
	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param r_flag the "Router" flag. When set, the R-bit indicates that the sender is a router
	 * @param s_flag the "Solicited" flag. When set, the S-bit indicates that the advertisement was sent in response to a Neighbor Solicitation from the Destination address
	 * @param o_flag the "Override" flag. When set, the O-bit indicates that the advertisement should override an existing cache entry and update the cached link-layer address
	 * @param target_address target address. For solicited advertisements, the target address field in the Neighbor Solicitation message that prompted this advertisement.  For an unsolicited advertisement, the address whose link-layer address has changed
	 * @param options array of options */
	public Icmp6NeighborAdvertisementMessage(Ip6Address src_addr, Ip6Address dst_addr, boolean r_flag, boolean s_flag, boolean o_flag, Ip6Address target_address, Icmp6Option[] options) {
		super(src_addr,dst_addr,TYPE,CODE,OPT_OFF,options);
		icmp_body[0]=(byte)((r_flag?0x80:0)|(s_flag?0x40:0)|(o_flag?0x20:0));
		target_address.getBytes(icmp_body,4);
	}
	

	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	public Icmp6NeighborAdvertisementMessage(Ip6Address src_addr, Ip6Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,OPT_OFF,buf,off,len);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a ICMPv6 \"Neighbor Solicitation\" ("+TYPE+") message");
		if (code!=CODE) throw new RuntimeException("ICMP code missmatch ("+code+"): the code should be "+CODE);
	}	

	
	/** Creates a new ICMP message.
	 * @param msg the ICMP message */
	public Icmp6NeighborAdvertisementMessage(Icmp6Message msg) {
		super(msg,OPT_OFF);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a ICMPv6 \"Neighbor Solicitation\" ("+TYPE+") message");
		if (code!=CODE) throw new RuntimeException("ICMP code missmatch ("+code+"): the code should be "+CODE);
	}	

	
	/** Gets the the "Router" flag.
	 * When set, the R-bit indicates that the sender is a router
	 * @return the flag value */
	public boolean getRFlag() {
		return (icmp_body[0]&0x80)!=0;
	}


	/** Gets the "Solicited" flag.
	 * When set, the S-bit indicates that the advertisement was sent in response to a Neighbor Solicitation from the Destination address.
	 * @return the flag value */
	public boolean getSFlag() {
		return (icmp_body[0]&0x40)!=0;
	}


	/** Gets the "Override" flag.
	 * When set, the O-bit indicates that the advertisement should override an existing cache entry and update the cached link-layer address.
	 * @return the flag value */
	public boolean getOFlag() {
		return (icmp_body[0]&0x20)!=0;
	}


	/** Gets the target address.
	 * For solicited advertisements, the target address field in the Neighbor Solicitation message that prompted this advertisement.
	 * For an unsolicited advertisement, the address whose link-layer address has changed
	 * @return the target address */
	public Ip6Address getTargetAddress() {
		return new Ip6Address(icmp_body,4);
	}

}
