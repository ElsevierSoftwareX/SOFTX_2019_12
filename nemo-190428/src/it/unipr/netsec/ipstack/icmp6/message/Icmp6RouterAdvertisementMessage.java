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


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.icmp6.Icmp6Message;
import it.unipr.netsec.ipstack.icmp6.message.option.Icmp6Option;
import it.unipr.netsec.ipstack.ip6.Ip6Address;


/** ICMP RRouter Advertisement message.
 */
public class Icmp6RouterAdvertisementMessage extends Icmp6MessageWithOptions {

	/** ICMP type */
	public static final int TYPE=Icmp6Message.TYPE_Router_Advertisement;

	/** ICMP code: 0 */
	public static final int CODE=0;

	/** Options offset within the message body */
	private static final int OPT_OFF=12;
	
	
	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param hop_limit the default value that should be placed in the Hop Count field of the IP header for outgoing IP packets.  A value of zero means unspecified (by this router)
	 * @param m_flag the "Managed address configuration" flag. When set, it indicates that addresses are available via DHCPv6
	 * @param o_flag the "Other configuration" flag. When set, it indicates that other configuration information is available via DHCPv6.  Examples of such information
	 * @param router_lifetime the lifetime associated with the default router in units of seconds
	 * @param reachable_time the time, in milliseconds, that a node assumes a neighbor is reachable after having received a reachability confirmation
     * @param retrans_timer the time, in milliseconds, between retransmitted Neighbor Solicitation messages
	 * @param options array of options */
	public Icmp6RouterAdvertisementMessage(Ip6Address src_addr, Ip6Address dst_addr, int hop_limit, boolean m_flag, boolean o_flag, int router_lifetime, long reachable_time, long retrans_timer, Icmp6Option[] options) {
		super(src_addr,dst_addr,TYPE,CODE,OPT_OFF,options);
		icmp_body[0]=(byte)(hop_limit&0xff);
		icmp_body[1]=(byte)((m_flag?0x80:0)|(o_flag?0x40:0));
		ByteUtils.intToTwoBytes(router_lifetime,icmp_body,2);
		ByteUtils.intToFourBytes(reachable_time,icmp_body,4);
		ByteUtils.intToFourBytes(retrans_timer,icmp_body,8);
	}
	

	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	public Icmp6RouterAdvertisementMessage(Ip6Address src_addr, Ip6Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,OPT_OFF,buf,off,len);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a ICMPv6 \"Router Advertisement\" ("+TYPE+") message");
		if (code!=CODE) throw new RuntimeException("ICMP code missmatch ("+code+"): the code should be "+CODE);
	}	

	
	/** Creates a new ICMP message.
	 * @param msg the ICMP message */
	public Icmp6RouterAdvertisementMessage(Icmp6Message msg) {
		super(msg,OPT_OFF);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a ICMPv6 \"Router Advertisement\" ("+TYPE+") message");
		if (code!=CODE) throw new RuntimeException("ICMP code missmatch ("+code+"): the code should be "+CODE);
	}	

	
	/** Gets the Current hop Limit, that is the default value that should be placed in the Hop Count field of the IP header for outgoing IP packets.
	 * @return the hop limit */
	public int getCurrentHopLimit() {
		return icmp_body[0]&0xff;
	}

	
	/** Gets the M flag.
	 * @return the flag value */
	public boolean getMFlag() {
		return (icmp_body[1]&0x80)!=0;
	}

	
	/** Gets the O flag.
	 * @return the flag value */
	public boolean getOFlag() {
		return (icmp_body[1]&0x40)!=0;
	}


	/** Gets the Router Lifetime.
	 * @return the lifetime in seconds */
	public int getRouterLifetime() {
		return ByteUtils.twoBytesToInt(icmp_body,2);
	}

	
	/** Gets the Reachable Time.
	 * @return the time in milliseconds */
	public long getReachableTime() {
		return ByteUtils.fourBytesToInt(icmp_body,4);
	}

	
	/** Gets the Retransmission Timer.
	 * @return the timer in milliseconds */
	public long getRetransTimer() {
		return ByteUtils.fourBytesToInt(icmp_body,8);
	}

}
