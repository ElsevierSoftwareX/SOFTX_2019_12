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

package it.unipr.netsec.ipstack.link;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.SocketAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.ppp.PppEncapsulation;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.ArrayList;

import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;


/** Hub that connects a set of PPP over UDP tunnels.
 * <p>
 * UDP packets contains a PPP envelop with a two-byte protocol field and the encapsulated packet as payload.
 * The two-byte protocol field specifies the protocol type of the packet (e.g. IPv4, IPv6, etc).
 * <p>
 * The hub uses a set of independent interfaces, each with a different local port, for communicating with the remote nodes.
 */
public class PppTunnelHub {

	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
	}


	/** Default port */
	public static int DEFAULT_PORT=7000;

	/** Default maximum number of endpoints */
	private static int DEFAULT_HUB_SIZE=32;

	/** Receiver buffer size */
	private static final int BUFFER_SIZE=8000;

	/** UDP socket */
	DatagramSocket sock;
	
	/** Maximum number of connected endpoints */
	int max_endpoints;
	
	/** Active endpoints attached to this hub */
	ArrayList<SocketAddress> endpoints=new ArrayList<SocketAddress>();

	
	/** Creates a new hub. 
	 * @throws SocketException */
	public PppTunnelHub() throws SocketException {
		this(DEFAULT_PORT,DEFAULT_HUB_SIZE);
	}
	
	/** Creates a new hub.
	 * @param port the local UDP port 
	 * @throws SocketException */
	public PppTunnelHub(int port) throws SocketException {
		this(port,DEFAULT_HUB_SIZE);
	}
	
	/** Creates a new hub. 
	 * @param port the local UDP port 
	 * @param max_endpoints maximum number of connected endpoints
	 * @throws SocketException */
	public PppTunnelHub(int port, int max_endpoints) throws SocketException {
		System.out.println("Virtual hub on UDP port "+port+", maximum number of virtual PH ports: "+max_endpoints);
		this.sock=new DatagramSocket(port);
		this.max_endpoints=max_endpoints;		
		run();
	}
	
	/** Runs the hub. */
	private void run() {
		final int max_endpoints1=max_endpoints;
		new Thread() {
			public void run() {
				DatagramPacket datagram=new DatagramPacket(new byte[BUFFER_SIZE],BUFFER_SIZE);
				int index=0; // virtual index of the next end-point
				try {
					while (true) {
						sock.receive(datagram);
						PppEncapsulation ppp_pkt=PppEncapsulation.parsePppEncapsulation(datagram.getData(),datagram.getOffset(),datagram.getLength());						
						if (DEBUG) debug("packet received: "+ppp_pkt);
						int proto=ppp_pkt.getProtocol();
						SocketAddress src_soaddr=new SocketAddress(new Ip4Address(datagram.getAddress()),datagram.getPort());
						if (!endpoints.contains(src_soaddr)) {
							System.out.println("new endpoint ["+index+"]: "+src_soaddr);							
							if (max_endpoints1>0 && max_endpoints1==endpoints.size()) {
								//if (DEBUG) debug("too much endpoints already connected ("+max_endpoints1+"): packet discarded");
								//continue;
								System.out.println("there are already "+max_endpoints1+" end-points connected: disconnecting "+endpoints.get(0));
								endpoints.remove(0);
							}
							// else
							endpoints.add(src_soaddr);
							index=(index+1)%max_endpoints;
						}
						Packet pkt;
						if (proto==PppTunnelInterface.PING_TYPE) {
							if (DEBUG) debug("it's a ping");
							continue;
						}
						if (proto==PppEncapsulation.TYPE_IP4) pkt=Ip4Packet.parseIp4Packet(ppp_pkt.getPayloadBuffer(),ppp_pkt.getPayloadOffset(),ppp_pkt.getPayloadLength());
						else
						if (proto==PppEncapsulation.TYPE_IP6) pkt=Ip6Packet.parseIp6Packet(ppp_pkt.getPayloadBuffer(),ppp_pkt.getPayloadOffset(),ppp_pkt.getPayloadLength());
						else {
							if (DEBUG) debug("protocol "+proto+" not supported: packet discarded");
							continue;
						}
						for (SocketAddress dst_soaddr : endpoints) {
							if (!dst_soaddr.equals(src_soaddr)) {
								if (DEBUG) debug("packet sent to "+dst_soaddr);
								datagram.setAddress(dst_soaddr.getIpAddress().toInetAddress());
								datagram.setPort(dst_soaddr.getPort());
								sock.send(datagram);
							}
						}		
					}
				}
				catch (IOException e1) {
					e1.printStackTrace();
				}
			}
		}.start();
	}
	
	@Override
	public String toString() {
		return getClass().getSimpleName()+"["+sock.getLocalPort()+"]";
	}

	
	/** Main method for running a stand-alone hub. 
	 * @throws SocketException */
	public static void main(String[] args) throws SocketException {
		Flags flags=new Flags(args);
		int port=flags.getInteger("-p","<port>",DEFAULT_PORT,"local UDP port (default "+DEFAULT_PORT+")");
		int max_endpoints=flags.getInteger("-n","<num>",DEFAULT_HUB_SIZE,"maximum number of endpoints (default "+DEFAULT_HUB_SIZE+")");
		boolean verbose=flags.getBoolean("-v","verbose mode");
		boolean help=flags.getBoolean("-h","prints this help");
		if (help) {
			System.out.println(flags.toUsageString(PppTunnelHub.class.getSimpleName()));
			System.exit(0);
		}
		// else
		if (verbose) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			PppTunnelHub.DEBUG=true;
		}
		new PppTunnelHub(port,max_endpoints);
	}

}
