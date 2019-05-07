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


/** RawIpSocket implements an IP socket interface for sending and receiving IP packets as raw byte arrays. 
 * <p>
 * When receiving an IPv4 packet, the entire packet (including the IP header) is obtained.
 * When receiving an IPv6 packet, only the packet payload is obtained.
 * <p>
 * When sending an IPv4 packet, if the parameter '<i>raw</i>' has been set to <i>true</i>
 * the IPv4 header must also be included within the byte array passed to the send method.
 * Conversely, if the parameter '<i>raw</i>' has been set to <i>false</i>, the IP header
 * is automatically added and must not be included within the byte array passed to the send method.
 * In this case only the packet payload must be provided.
 * <p>
 * A RawIpSocket is associated to a protocol number (i.e. the 'IP_PROTO' header field).
 * <p>
 * If the <i>raw</i> parameter is <i>false</i> (non raw mode), the behavior of the socket is identical to
 * {@link Ip4Socket} or {@link Ip6Socket} (depending on the <i>version</i> parameter). For IPv6 see also
 * the note below.
 * <p>
 * <b>IMPORTANT</b>: The 'raw' mode can only be used with IP version 4. 
 * Unfortunately standard API for IP version 6 does not provide a raw interface.
 * For sending/receiving IPv6 raw packets you probably should use a level 2 socket (e.g. 'PF_PACKET' socket domain).
 */
public class RawIpSocket extends Socket {
	

	/** Creates a new socket.
	* @param version IP version (4 or 6)
	* @param proto the protocol number to bind the socket to
	* @param raw if <i>true</i>, the IP header must be included within the byte array passed to the send method; conversely, if <i>false</i>, the header is automatically added  */
	public RawIpSocket(int version, int proto, boolean raw) {
		super(version==6?Socket.PF_INET6:Socket.PF_INET,Socket.SOCK_RAW,proto);
		if (raw) setIPv4HdrInclOpt(true);
	}


	/** Creates a new socket.
	* @param IP version (4 or 6) */
	/*public RawIpSocket(int version) {
		super(version==6?Socket.PF_INET6:Socket.PF_INET,Socket.SOCK_RAW,IpPacket.IPPROTO_RAW);
	}*/
	
		
	/** Sets the IP Header Included Option (raw mode).
	 * @param raw <pre>true</pre> for header included (raw mode on);  <pre>false</pre> for header not included (raw mode off) */
	private void setIPv4HdrInclOpt(boolean raw) {
		final byte[] VAL01={ 0x01 };
		final byte[] VAL00={ 0x00 }; 
		setsockopt(Ip4Packet.IPPROTO_IP,Ip4Socket.IP_HDRINCL,raw?VAL01:VAL00,0,1);
	}

	
	/** Sets IP options.
	 * @param options_buf the buffer containing IP options field
	 * @param options_off the offset within the buffer 
	 * @param options_len the length of the options field */
	public void setIPv4Options(byte[] options_buf, int options_off, int options_len) {
		setsockopt(Ip4Packet.IPPROTO_IP,Ip4Socket.IP_OPTIONS,options_buf,options_off,options_len);
	}


	/** Gets IP options.
	 * @return the IP options field */
	public byte[] getIPv4Options() {
		byte[] buff=new byte[40];
		int len=getsockopt(Ip4Packet.IPPROTO_IP,Ip4Socket.IP_OPTIONS,buff,0);
		if (len>0) {
			byte[] options=new byte[len];
			for (int i=0; i<len; i++) options[i]=buff[i];
			return options;
		}
		else return null;
	}	

}
