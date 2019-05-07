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


import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.ethernet.EthPacket;
import it.unipr.netsec.ipstack.net.DataPacket;


/** It implements a Layer two socket for sending and receiving layer two packets.
 * <p>
 * When receiving a packet, the entire layer two packet (including the data-link header) is obtained.
 * <p>
 * When sending a packet, the data-link header must also be included
 * within the {@link DataPacket} passed to the method {@link #send(DataPacket)}, or
 * within the byte array passed to the method {@link #sendto(byte[], int, int, int, String, int)}.
 * <p>
 * When using the {@link #sendto(byte[], int, int, int, String dst_addr, int)} method,
 * parameter <i>dst_addr</i> must contains the interface to be used for sending the packet.
 * <p>
 * Note: it uses a socket with domain PF_PACKET and type SOCK_RAW that is not supported either on Windows
 * and Mac OS. As a result, this class can be used only with Linux OS.
 */
public class RawLinkSocket extends Socket {
	
	/** Any L2 protocol */
	private static final int ETH_P_ALL=0x0003;
	

	/** Converts a 16-bit integer from host to network byte order.
	 * @param the 16-bit integer (in host byte order)
	 * @return the 16-bit integer in network byte order */
	private static int htons(int n) {
		return ((n&0xff00)>>8) + ((n&0xff)<<8);
	}

	
	/** Creates a new socket. */
	public RawLinkSocket() {
		super(Socket.PF_PACKET,Socket.SOCK_RAW,htons(ETH_P_ALL));
		is_bound=true;
	}

	
	@Override
	public void send(DataPacket pkt) {
		byte[] raw_packet=pkt.getBytes();
		String out_interface=((EthPacket)pkt).getOutInterface();
		if (out_interface==null) {
			EthAddress eth_src_addr=(EthAddress)pkt.getSourceAddress();
			try {
				for (Enumeration<NetworkInterface> i=NetworkInterface.getNetworkInterfaces(); i.hasMoreElements(); ) {
					NetworkInterface ni=i.nextElement();
					if (new EthAddress(ni.getHardwareAddress()).equals(eth_src_addr)) {
						out_interface=ni.getName();
						break;
					}
				}
			}
			catch (SocketException e) {
				e.printStackTrace();
			}
			if (out_interface==null) throw new RuntimeException("Ethernet interface with address "+eth_src_addr+" not found");
		}
		sendto(raw_packet,0,raw_packet.length,0,out_interface,0);
	}

}
