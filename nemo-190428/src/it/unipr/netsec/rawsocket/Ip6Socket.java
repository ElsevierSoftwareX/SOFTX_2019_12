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

package it.unipr.netsec.rawsocket;


import it.unipr.netsec.ipstack.ip6.Ip6Packet;


/** It implements an IPv6 socket for sending and receiving IPv6 packets. 
 * <p>
 * An Ip6Socket is always associated to a protocol number (i.e. the 'IP_PROTO' header field).
 */
public class Ip6Socket extends Socket {
	

	/** Maximum receiver buffer size */
	public static int RECV_BUFFER_SIZE=65535;

	
	/** Receiver buffer */
	byte[] recv_buffer=null;



	/** Creates a new IPv6 socket.
	 * @param proto the protocol number to bind the socket to */
	public Ip6Socket(int proto) {
		super(Socket.PF_INET6,Socket.SOCK_RAW,proto);
	}

	 
	/** Receives a packet.
	  * <p> This method is blocking, that is it returns only when a packet is received.
	  * @return the received IP packet */
	public Ip6Packet receive() {
		if (recv_buffer==null) recv_buffer=new byte[RECV_BUFFER_SIZE];
		int len=recv(recv_buffer,0,0);
		//return new Ip6Packet(recv_buffer,0,len);
		return null;
	}


	/** Receives a packet.
	  * <p> This method is blocking, that is it returns only when a packet is received.
	  * @param pkt the packet used for returning the incoming packet */
	/*public void receive(Ip6Packet pkt) {
		Ip6Packet pkt2=receive();
		int data_len=pkt2.getDataLength();
		System.arraycopy(pkt2.getDataBuffer(),pkt2.getDataOffset(),pkt.getDataBuffer(),pkt.getDataOffset(),data_len);
		pkt.setDataLength(data_len);
		pkt.setSourceAddress(pkt2.getSourceAddress());
		pkt.setDestAddress(pkt2.getDestAddress());
	}*/

}
