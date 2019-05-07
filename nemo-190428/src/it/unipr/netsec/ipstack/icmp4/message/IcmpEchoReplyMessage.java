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
import it.unipr.netsec.ipstack.net.Address;


/** ICMP Echo Reply message.
 */
public class IcmpEchoReplyMessage extends IcmpEchoMessage {

    
	/** Creates a new ICMP Echo Reply message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param id identifier to aid in matching echos and replies (may be zero)
	 * @param sqn sequence number to aid in matching echos and replies (may be zero)
	 * @param echo_data the data to be included in the ICMP message */
	public IcmpEchoReplyMessage(Address src_addr, Address dst_addr, int id, int sqn, byte[] echo_data) {
		super(src_addr,dst_addr,IcmpMessage.TYPE_Echo_Reply,id,sqn,echo_data);
	}

	
	/** Creates a new ICMP Echo Reply message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	public IcmpEchoReplyMessage(Address src_addr, Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
		if (type!=IcmpMessage.TYPE_Echo_Reply) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not an \"Echo Reply\" ("+IcmpMessage.TYPE_Echo_Reply+") ICMP message");
	}	

	
	/** Creates a new ICMP Echo Reply message.
	 * @param msg the ICMP message */
	public IcmpEchoReplyMessage(IcmpMessage msg) {
		super(msg);
		if (type!=IcmpMessage.TYPE_Echo_Reply) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not an \"Echo Reply\" ("+IcmpMessage.TYPE_Echo_Reply+") ICMP message");
	}	

}
