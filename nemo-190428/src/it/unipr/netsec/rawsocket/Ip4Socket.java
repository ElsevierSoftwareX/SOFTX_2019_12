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


import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.DataPacket;


/** It implements an IPv4 socket for sending and receiving IPv4 packets. 
 * <p>
 * An Ip4Socket is always associated to a protocol number (i.e. the 'IP_PROTO' header field).
 */
public class Ip4Socket extends Socket {
	

	/** Maximum receiver buffer size */
	public static int RECV_BUFFER_SIZE=65535;

	/** Maximum options buffer size */
	private static int OPTIONS_BUFFER_SIZE=40;


	// Some IPv4 Socket options to be used with getsockopt() and setsockopt() methods:

	/** IPv4 Socket option: IP type of service (TOS); to be used with getsockopt() and setsockopt() methods.
	 * It is a byte and it is used to prioritize packets on the network. */
	public static final int IP_TOS=1;
	/** IPv4 Socket option: IP time to live (TTL); to be used with getsockopt() and setsockopt() methods.
	  * Argument is an integer. */
	public static final int IP_TTL=2;
	/** IPv4 Socket option: Header is included with data; to be used with getsockopt() and setsockopt() methods.
	  * If enabled, the user supplies an IP header in front of the user data.
	  * When it is enabled the values set by IP_OPTIONS, IP_TTL and
	  * IP_TOS are ignored. */
	public static final int IP_HDRINCL=3;
	/** IPv4 Socket option: IP options; to be used with getsockopt() and setsockopt() methods.
	  * The option arguments are a pointer to a memory buffer containing the
	  * options and the option length.  The maximum option size for IPv4 is
	  * 40 bytes.  See RFC 791 for the allowed options. */
	public static final int IP_OPTIONS=4;


	
	/** Whether IP options has been set for the raw socket */
	boolean options=false;

	/** Receiver buffer */
	byte[] recv_buffer=null;



	/** Creates a new socket.
	 * @param proto the protocol number to bind the socket to */
	public Ip4Socket(int proto) {
		super(Socket.PF_INET,Socket.SOCK_RAW,proto);
	}

	 
	@Override
	public void send(DataPacket pkt) {
		if (pkt instanceof Ip4Packet) {
			Ip4Packet ip4_pkt=(Ip4Packet)pkt;
			if (ip4_pkt.hasOptions()) {
				setIPv4Options(ip4_pkt.getOptionsBuffer(),ip4_pkt.getOptionsOffset(),ip4_pkt.getOptionsLength());
				options=true;
			}
			else
			if (options) {
				setIPv4Options(null,0,0);
				options=false;
			}
		}
		super.sendto(pkt.getPayloadBuffer(),pkt.getPayloadOffset(),pkt.getPayloadLength(),0,pkt.getDestAddress().toString(),0);
	}

	 
	/** Receives an IP packet.
	  * <p> This method is blocking, that is it returns only when a packet is received.
	  * @return the received IP packet */
	public Ip4Packet receive() {
		if (recv_buffer==null) recv_buffer=new byte[RECV_BUFFER_SIZE];
		int len=recv(recv_buffer,0,0);
		return Ip4Packet.parseIp4Packet(recv_buffer,0,len);
	}


	/** Receives an IP packet.
	  * <p> This method is blocking, that is it returns only when a packet is received.
	  * @param packet the IP packet used for returning the received packet */
	public void receive(Ip4Packet packet) {
		Ip4Packet pkt2=receive();
		int data_len=pkt2.getPayloadLength();
		System.arraycopy(pkt2.getPayloadBuffer(),pkt2.getPayloadOffset(),packet.getPayloadBuffer(),packet.getPayloadOffset(),data_len);
		packet.setPayloadLength(data_len);
		packet.setSourceAddress(pkt2.getSourceAddress());
		packet.setDestAddress(pkt2.getDestAddress());
		if (pkt2.hasOptions()) {
			int opts_len=pkt2.getOptionsLength();
			if (packet.getOptionsBuffer()==null) packet.setOptions((new byte[OPTIONS_BUFFER_SIZE]),0,OPTIONS_BUFFER_SIZE);
			System.arraycopy(pkt2.getOptionsBuffer(),pkt2.getOptionsOffset(),packet.getOptionsBuffer(),packet.getOptionsOffset(),opts_len);
			packet.setOptionsLength(opts_len);
		}
		else {
			packet.setOptionsLength(0);
		}
	}


	/** Sets IPv4 options.
	 * @param options_buf the buffer containing IP options field
	 * @param options_off the offset within the buffer 
	 * @param options_len the length of the options field */
	public void setIPv4Options(byte[] options_buf, int options_off, int options_len) {
		setsockopt(Ip4Packet.IPPROTO_IP,IP_OPTIONS,options_buf,options_off,options_len);
	}


	/** Gets IP options.
	 * @return the IP options field */
	public byte[] getIPv4Options() {
		byte[] buff=new byte[40];
		int len=getsockopt(Ip4Packet.IPPROTO_IP,IP_OPTIONS,buff,0);
		if (len>0) {
			byte[] options=new byte[len];
			for (int i=0; i<len; i++) options[i]=buff[i];
			return options;
		}
		else return null;
	}	

	
	/** Sets the IP Header Included Option (raw mode).
	 * @param hdrincl <pre>true</pre> for header included (raw mode on);  <pre>false</pre> for header not included (raw mode off) */
	private void setIPv4HdrInclOpt(boolean hdrincl) {
		final byte[] VAL01={ 0x01 };
		final byte[] VAL00={ 0x00 }; 
		setsockopt(Ip4Packet.IPPROTO_IP,IP_HDRINCL,hdrincl?VAL01:VAL00,0,1);
	}

}
