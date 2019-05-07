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


import java.io.IOException;
import java.net.DatagramPacket;
import it.unipr.netsec.rawsocket.udp.DatagramSocket;
import java.net.SocketException;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.SocketAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.ppp.PppEncapsulation;


/** PPP over UDP tunnel toward a selected end-point.
 */
public class PppTunnelInterface extends NetInterface {

	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
	}


	/** Ping protocol type */
	public static final int PING_TYPE=0;

	/** Ping packet */
	//private static final byte[] PING=new byte[]{0x00, 0x00};
	private static final byte[] PING=new PppEncapsulation(PING_TYPE,null,0,0).getBytes();

	/** Receiver buffer size */
	private static final int BUFFER_SIZE=8000;

	/** Local UDP end-point */
	DatagramSocket datagram_socket;
	
	/** Remote UDP end-point */
	SocketAddress remote_soaddr;

	/** Reverse UDP */
	//boolean reverse_udp=false;

			
	/** Creates a new PPP over UDP tunnel interface.
	 * @param addr interface address
	 * @param local_port UDP port for the local tunnel end-point
	 * @param remote_soaddr remote tunnel end-point 
	 * @throws SocketException */
	public PppTunnelInterface(Address addr, int local_port, SocketAddress remote_soaddr) throws SocketException {
		super(addr);
		if (local_port>0) this.datagram_socket=new DatagramSocket(local_port);
		else this.datagram_socket=new DatagramSocket();
		this.remote_soaddr=remote_soaddr;
		if (DEBUG) debug("UdpTunnelInterface()");
		start();
	}

	/** Starts the receiver. */
	private void start() {
		new Thread() {
			public void run() {
				DatagramPacket datagram=new DatagramPacket(new byte[BUFFER_SIZE],BUFFER_SIZE);
				try {
					while (true) {
						datagram_socket.receive(datagram);
						PppEncapsulation ppp_pkt=PppEncapsulation.parsePppEncapsulation(datagram.getData(),datagram.getOffset(),datagram.getLength());
						if (DEBUG) debug("run(): packet received: "+ppp_pkt);
						int proto=ppp_pkt.getProtocol();
						if (remote_soaddr==null) {
							remote_soaddr=new SocketAddress(new Ip4Address(datagram.getAddress()),datagram.getPort());
							if (DEBUG) debug("run(): remote-soaddr="+remote_soaddr);
						}
						Packet pkt;
						if (proto==PING_TYPE) {
							if (DEBUG) debug("run(): ping received");
							continue;
						}
						if (proto==PppEncapsulation.TYPE_IP4) pkt=Ip4Packet.parseIp4Packet(ppp_pkt.getPayloadBuffer(),ppp_pkt.getPayloadOffset(),ppp_pkt.getPayloadLength());
						else
						if (proto==PppEncapsulation.TYPE_IP6) pkt=Ip6Packet.parseIp6Packet(ppp_pkt.getPayloadBuffer(),ppp_pkt.getPayloadOffset(),ppp_pkt.getPayloadLength());
						else {
							if (DEBUG) debug("run(): protocol "+proto+" not supported: discarded");
							continue;
						}
						for (NetInterfaceListener li : getListeners()) {
							try { li.onIncomingPacket(PppTunnelInterface.this,pkt); } catch (Exception e) {
								e.printStackTrace();
							}
						}		
					}
				}
				catch (IOException e1) {
					e1.printStackTrace();
				}
			}
		}.start();
		// PING
		if (remote_soaddr!=null) ping();
	}
	
	/** Sends a ping packet to a remote end-point (typically for create an association). */
	public void ping() {
		if (DEBUG) debug("ping(): "+remote_soaddr);
		DatagramPacket datagram=new DatagramPacket(PING,PING.length,remote_soaddr.getIpAddress().toInetAddress(),remote_soaddr.getPort());
		try {
			datagram_socket.send(datagram);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public void send(Packet pkt, Address dest_addr) {
		//if (DEBUG) debug("send(): "+pkt);
		if (remote_soaddr==null){
			if (DEBUG) debug("send(): no remote end-point address: packet discarded");
			return;
		}
		int proto;
		if (pkt instanceof Ip4Packet) proto=PppEncapsulation.TYPE_IP4;
		else
		if (pkt instanceof Ip6Packet) proto=PppEncapsulation.TYPE_IP6;
		else {
			if (DEBUG) debug("send(): packet protocol not supported: discarded");
			return;
		}
		PppEncapsulation ppp_pkt=new PppEncapsulation(proto,pkt.getBytes());
		if (DEBUG) debug("send(): "+ppp_pkt);
		byte[] data=ppp_pkt.getBytes();
		DatagramPacket datagram=new DatagramPacket(data,data.length,remote_soaddr.getIpAddress().toInetAddress(),remote_soaddr.getPort());
		try {
			datagram_socket.send(datagram);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public String toString() {
		return getClass().getSimpleName()+"["+datagram_socket.getLocalPort()+","+remote_soaddr+"]";
	}
	
}
