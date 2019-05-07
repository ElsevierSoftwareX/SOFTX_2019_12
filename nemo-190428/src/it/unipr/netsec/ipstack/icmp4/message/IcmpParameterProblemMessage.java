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


/** ICMP Parameter Problem message.
 */
public class IcmpParameterProblemMessage extends IcmpMessageWithDatagram {

    
	/** ICMP code: pointer indicates the error */
	public static final int CODE_pointer_indicates_the_error=0;

	
	/** Pointer that identifies the octet where an error was detected */
	//int pointer;
	
	
	
	/** Creates a new ICMP Parameter Problem message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param code ICMP subtype code
	 * @param pointer pointer that identifies the octet where an error was detected
	 * @param ip_packet the original IP packet that triggered this ICMP message */
	public IcmpParameterProblemMessage(Address src_addr, Address dst_addr, int code, int pointer, Ip4Packet ip_packet) {
		super(src_addr,dst_addr,IcmpMessage.TYPE_Parameter_Problem,code,ip_packet);
		icmp_body[4]=(byte)pointer;
	}

	
	/** Creates a new ICMP Parameter Problem message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	public IcmpParameterProblemMessage(Address src_addr, Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
		if (type!=IcmpMessage.TYPE_Parameter_Problem) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a \"Parameter Problem\" ("+IcmpMessage.TYPE_Parameter_Problem+") ICMP message");
	}	

	
	/** Creates a new ICMP Parameter Problem message.
	 * @param msg the ICMP message */
	public IcmpParameterProblemMessage(IcmpMessage msg) {
		super(msg);
		if (type!=IcmpMessage.TYPE_Parameter_Problem) throw new RuntimeException("ICMP type missmatch ("+type+"): this is not a \"Parameter Problem\" ("+IcmpMessage.TYPE_Parameter_Problem+") ICMP message");
	}	

	
	/** Gets the pointer.
	 * @return the pointer */
	public int getPointer() {
		return icmp_body[0]&0xff;
	}
	
}
