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


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;


/** PaddedIpSocket implements an IP socket for sending and receiving IP packets
  * with data size greater or equal to a given value. 
  * <p>
  * If the length of a IP packet is less than a given minimum transfer unit, the
  * packet is zero-padded before sending. The packet length field of the IP header
  * changes when padding is added.
  * <p>
  * For developers: in order to let the packet length field unchanged, the raw mode
  * should be used instead. In this case the IP header should be explicitly generated.
  */
public class PaddedIpSocket extends Ip4Socket {
	

	/** Default minimum transfer unit */
	public static int DEFAULT_MINIMUM_TRANSFER_UNIT=46;


	/** Minimum transfer unit */
	int minimum_transfer_unit=DEFAULT_MINIMUM_TRANSFER_UNIT;




	/** Creates a new IP socket.
	 * @param proto the protocol number to bind the socket to */
	public PaddedIpSocket(int proto) {
		super(proto);
	}

	 
	/** Creates a new IP socket.
	 * @param proto the protocol number to bind the socket to
	 * @param minimum_transfer_unit the minimum transfer unit */
	public PaddedIpSocket(int proto, int minimum_transfer_unit) {
		super(proto);
		this.minimum_transfer_unit=minimum_transfer_unit;
	}


	/** Sets minimum transfer unit.
	 * @param minimum_transfer_unit the minimum transfer unit */
	public void setMinimumTransferUnit(int minimum_transfer_unit) {
		this.minimum_transfer_unit=minimum_transfer_unit;
	}


	/** Sends an IP packet.
	 * @param packet the IP packet to be sent */
	public void send(Ip4Packet packet) {
		if ((20+packet.getOptionsLength()+packet.getPayloadLength())>=minimum_transfer_unit) super.send(packet);
		else {
			int minimum_data_len=minimum_transfer_unit-20-packet.getOptionsLength();
			byte[] padded_data=new byte[minimum_data_len];
			copyBytes(packet.getPayloadBuffer(),packet.getPayloadOffset(),padded_data,0,packet.getPayloadLength());
			for (int i=packet.getPayloadLength(); i<minimum_data_len; i++) padded_data[i]=0;
			Ip4Packet padded_packet=new Ip4Packet((Ip4Address)packet.getSourceAddress(),(Ip4Address)packet.getDestAddress(),packet.getProto(),padded_data);
			if (packet.hasOptions()) {
				padded_packet.setOptions(packet.getOptionsBuffer(),packet.getOptionsOffset(),packet.getOptionsLength());
			}
			super.send(padded_packet);
		}
	}


	/** Copies bytes between two byte arrays.
	 * @param src the source buffer where the bytes are read from 
	 * @param src_off the offset within the source puffer
	 * @param dst the destination buffer where the bytes are written to
	 * @param dst_off the offset within the destination buffer
	 * @param dst_off the number of bytes to be copied
	 * @return the number of copied bytes */
	private static int copyBytes(byte[] src, int src_off, byte[] dst, int dst_off, int len) {
		for (int k=0; k<len; k++) dst[dst_off+k]=src[src_off+k];
		return len;
	}
	
}
