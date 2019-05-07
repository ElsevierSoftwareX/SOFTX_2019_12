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
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.Address;


/** ICMP Redirect message.
 */
public class IcmpRedirectMessage extends IcmpMessageWithDatagram {

    
	/** ICMP code: Redirect datagrams for the Network */
	public static final int CODE_Network=0;

	/** ICMP code: Redirect datagrams for the Host */
	public static final int CODE_Host=1;

	/** ICMP code: Redirect datagrams for the Type of Service and Network */
	public static final int CODE_Type_of_Service_and_Network=2;

	/** ICMP code: Redirect datagrams for the Type of Service and Host */
	public static final int CODE_Type_of_Service_and_Host=3;


	
	/** Address of the gateway to which traffic for the network specified in the internet destination network field of the original datagram's data should be sent */
	//Ip4Address gateway;
	
	
	
	/** Creates a new ICMP Redirect message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param code ICMP subtype code
	 * @param gateway address of the gateway to which traffic for the network specified in the internet destination network field of the original datagram's data should be sent
	 * @param ip_packet the original IP packet that triggered this ICMP message */
	public IcmpRedirectMessage(Address src_addr, Address dst_addr, int code, Ip4Address gateway, Ip4Packet ip_packet) {
		super(src_addr,dst_addr,IcmpMessage.TYPE_Redirect,code,ip_packet);
		gateway.getBytes(icmp_body,0);
	}

	
	/** Creates a new ICMP Redirect message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	public IcmpRedirectMessage(Address src_addr, Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
		if (type!=IcmpMessage.TYPE_Redirect) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a \"Redirect\" ("+IcmpMessage.TYPE_Redirect+") ICMP message");
	}	

	
	/** Creates a new ICMP Redirect message.
	 * @param msg the ICMP message */
	public IcmpRedirectMessage(IcmpMessage msg) {
		super(msg);
		if (type!=IcmpMessage.TYPE_Redirect) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a \"Redirect\" ("+IcmpMessage.TYPE_Redirect+") ICMP message");
	}	
	
	
	/** Gets gateway address.
	 * @return the gateway IP address */
	public Ip4Address getPointer() {
		return new Ip4Address(icmp_body,0);
	}

}
