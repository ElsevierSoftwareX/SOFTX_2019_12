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
import java.lang.reflect.Field;
import java.net.DatagramPacket;
import java.net.SocketException;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.ethernet.EthPacket;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.SocketAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;


/** Ethernet over UDP tunnel toward a selected end-point.
 */
public class EthTunnelInterface extends NetInterface {

	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
	}


	/** Ping protocol type */
	public static final int PING_TYPE=0;

	/** Ping packet */
	private static final byte[] PING=new EthPacket(EthAddress.BROADCAST_ADDRESS,EthAddress.BROADCAST_ADDRESS,PING_TYPE,null,0,0).getBytes();

	/** Receiver buffer size */
	private static final int BUFFER_SIZE=8000;
	
	/** Local UDP from standard java.net package */
	java.net.DatagramSocket datagram_socket_std=null;
	
	/** Local UDP from rawsocket package */
	it.unipr.netsec.rawsocket.udp.DatagramSocket datagram_socket_raw=null;

	/** Remote UDP end-point */
	SocketAddress remote_soaddr;

	/** Reverse UDP */
	//boolean reverse_udp=false;

			
	/** Creates a new PPP over UDP tunnel interface.
	 * @param addr interface address
	 * @param remote_soaddr remote tunnel end-point 
	 * @throws SocketException */
	public EthTunnelInterface(Address addr, SocketAddress remote_soaddr) throws SocketException {
		this(addr,-1,remote_soaddr);
	}

	/** Creates a new PPP over UDP tunnel interface.
	 * @param addr interface address
	 * @param local_port UDP port for the local tunnel end-point
	 * @param remote_soaddr remote tunnel end-point 
	 * @throws SocketException */
	public EthTunnelInterface(Address addr, int local_port, SocketAddress remote_soaddr) throws SocketException {
		super(addr);
		try {
			Field provider=java.net.DatagramSocket.class.getField("PROVIDER"); // throws an exception in case of standard DatagramSocket
			if (local_port>0) datagram_socket_raw=new it.unipr.netsec.rawsocket.udp.DatagramSocket(local_port);
			else datagram_socket_raw=new it.unipr.netsec.rawsocket.udp.DatagramSocket();
			if (DEBUG) debug("DatagramSocket impl: "+provider.get(null).toString());
		}
		catch (Exception e) {
			if (local_port>0) datagram_socket_std=new java.net.DatagramSocket(local_port);
			else datagram_socket_std=new java.net.DatagramSocket();
			if (DEBUG) debug("DatagramSocket impl: standard");
		}		
		this.remote_soaddr=remote_soaddr;
		start();
	}

	/** Starts the receiver. */
	private void start() {
		new Thread() {
			public void run() {
				DatagramPacket datagram=new DatagramPacket(new byte[BUFFER_SIZE],BUFFER_SIZE);
				try {
					while (true) {
						if (datagram_socket_std!=null) datagram_socket_std.receive(datagram);
						else datagram_socket_raw.receive(datagram);
						EthPacket eth_pkt=EthPacket.parseEthPacket(datagram.getData(),datagram.getOffset(),datagram.getLength());
						if (DEBUG) debug("run(): packet received: "+eth_pkt);
						int proto=eth_pkt.getType();
						if (remote_soaddr==null) {
							remote_soaddr=new SocketAddress(new Ip4Address(datagram.getAddress()),datagram.getPort());
							if (DEBUG) debug("run(): remote-soaddr="+remote_soaddr);
						}
						Packet pkt;
						if (proto==PING_TYPE) {
							if (DEBUG) debug("run(): ping received");
							continue;
						}
						if (proto==EthPacket.ETH_IP4) pkt=Ip4Packet.parseIp4Packet(eth_pkt.getPayloadBuffer(),eth_pkt.getPayloadOffset(),eth_pkt.getPayloadLength());
						else
						if (proto==EthPacket.ETH_IP6) pkt=Ip6Packet.parseIp6Packet(eth_pkt.getPayloadBuffer(),eth_pkt.getPayloadOffset(),eth_pkt.getPayloadLength());
						else {
							if (DEBUG) debug("run(): protocol "+proto+" not supported: discarded");
							continue;
						}
						EthAddress eth_dest_addr=(EthAddress)eth_pkt.getDestAddress();
						if (eth_dest_addr.equals(EthAddress.BROADCAST_ADDRESS) || eth_dest_addr.equals(ipToMac((IpAddress)EthTunnelInterface.this.getAddresses()[0]))) {
							for (NetInterfaceListener li : getListeners()) {
								try { li.onIncomingPacket(EthTunnelInterface.this,pkt); } catch (Exception e) {
									e.printStackTrace();
								}
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
			if (datagram_socket_std!=null) datagram_socket_std.send(datagram);
			else datagram_socket_raw.send(datagram);
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
		if (pkt instanceof Ip4Packet) proto=EthPacket.ETH_IP4;
		else
		if (pkt instanceof Ip6Packet) proto=EthPacket.ETH_IP6;
		else {
			if (DEBUG) debug("send(): packet protocol not supported: discarded");
			return;
		}
		EthPacket eth_pkt=new EthPacket(EthAddress.BROADCAST_ADDRESS,ipToMac((IpAddress)dest_addr),proto,pkt.getBytes());
		if (DEBUG) debug("send(): "+eth_pkt);
		byte[] data=eth_pkt.getBytes();
		DatagramPacket datagram=new DatagramPacket(data,data.length,remote_soaddr.getIpAddress().toInetAddress(),remote_soaddr.getPort());
		try {
			if (datagram_socket_std!=null) datagram_socket_std.send(datagram);
			else datagram_socket_raw.send(datagram);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/** Maps IP address to MAC address. */
	private static EthAddress ipToMac(IpAddress addr) {
		byte[] eth_addr=new byte[6];
		eth_addr[0]=2;
		eth_addr[1]=0;
		if (addr instanceof Ip4Address) addr.getBytes(eth_addr,2);
		else
		if (addr instanceof Ip6Address) {
			byte[] ip6_addr=((Ip6Address)addr).getBytes();
			System.arraycopy(ip6_addr,12,eth_addr,2,4);
		}
		return new EthAddress(eth_addr);
	}
	
	@Override
	public String toString() {
		int port=datagram_socket_std!=null? datagram_socket_std.getLocalPort() : datagram_socket_raw.getLocalPort();
		return getClass().getSimpleName()+"["+port+","+remote_soaddr+"]";
	}
	
}
