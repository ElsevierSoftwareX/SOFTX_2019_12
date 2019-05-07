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


/** ICMP Echo Reply message.
 */
public class Icmp6EchoReplyMessage extends Icmp6EchoMessage {
   
	/** ICMP type */
	public static final int TYPE=Icmp6Message.TYPE_Echo_Reply;

	
	/** Creates a new ICMP Echo Reply message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param id identifier to aid in matching echos and replies (may be zero)
	 * @param sqn sequence number to aid in matching echos and replies (may be zero)
	 * @param echo_data the data to be included in the ICMP message */
	public Icmp6EchoReplyMessage(Ip6Address src_addr, Ip6Address dst_addr, int id, int sqn, byte[] echo_data) {
		super(src_addr,dst_addr,TYPE,id,sqn,echo_data);
	}

	
	/** Creates a new ICMP Echo Reply message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	public Icmp6EchoReplyMessage(Ip6Address src_addr, Ip6Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not an \"Echo Reply\" ("+TYPE+") ICMP message");
	}	

	
	/** Creates a new ICMP Echo Reply message.
	 * @param msg the ICMP message */
	public Icmp6EchoReplyMessage(Icmp6Message msg) {
		super(msg);
		if (type!=TYPE) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not an \"Echo Reply\" ("+TYPE+") ICMP message");
	}	

}
