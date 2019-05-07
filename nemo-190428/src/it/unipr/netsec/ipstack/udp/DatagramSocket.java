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

package it.unipr.netsec.ipstack.udp;


import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.udp.UdpLayer;
import it.unipr.netsec.ipstack.udp.UdpLayerListener;
import it.unipr.netsec.ipstack.udp.UdpPacket;


/** UDP socket.
 * It provides the same interface of {@link java.net.DatagramSocket} while it uses {@link UdpLayer} as UDP implementation.
 */
public class DatagramSocket {
	
	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	
	/** Maximum buffer size */
	static int MAX_BUFFER_SIZE=65535;

	/** Unspecified address */
	static InetAddress UNSPECIFIED_ADDRESS=Ip4Address.ADDR_UNSPECIFIED.toInetAddress();

	/** UDP layer */
	UdpLayer udp_layer;
	
	/** Whether the socket has been closed */
	boolean closed=false;
	
	/** Local IP address */
	InetAddress local_inetaddr=null;
	
	/** Local port */
	int local_port;
	
	/** Remote IP address */
	InetAddress remote_inetaddr=null;
	
	/** Remote port */
	int remote_port;
	
	/** Buffer of received packets */
	ArrayList<UdpPacket> received_packets=new ArrayList<UdpPacket>();
	
	/** This UDP layer listener */
	UdpLayerListener this_udp_layer_listener=new UdpLayerListener(){
		@Override
		public void onReceivedPacket(UdpLayer udp_layer, UdpPacket udp_pkt) {
			processReceivedPacket(udp_layer,udp_pkt);
		}
	};

	
	/** Creates a datagram socket and binds it to any available port on the local host machine. */
	public DatagramSocket(UdpLayer udp_layer) throws SocketException {
		init(udp_layer,null,-1);
	}

	/** Creates an unbound datagram socket with the specified DatagramSocketImpl. */
	/*protected DatagramSocket(DatagramSocketImpl impl) {
	}*/

	/** Creates a datagram socket and binds it to the specified port on the local host machine. */
	public DatagramSocket(UdpLayer udp_layer, int port) throws SocketException {
		init(udp_layer,null,port);
	}

	/** Creates a datagram socket, bound to the specified local address. */
	public DatagramSocket(UdpLayer udp_layer, int port, InetAddress laddr) throws SocketException {
		init(udp_layer,laddr,port);
	}

	/** Creates a datagram socket, bound to the specified local socket address. */
	public DatagramSocket(UdpLayer udp_layer, SocketAddress bindaddr) throws SocketException {
		InetSocketAddress inetsoaddr=(InetSocketAddress)bindaddr;
		init(udp_layer,inetsoaddr.getAddress(),inetsoaddr.getPort());
	}

	private void init(UdpLayer udp_layer, InetAddress inetaddr, int port) {
		if (DEBUG) debug("init(): "+(inetaddr!=null?inetaddr.getHostAddress()+":"+port:port));
		if (port<=0) port=udp_layer.getFreePort();
		this.udp_layer=udp_layer;
		this.local_inetaddr=inetaddr;
		this.local_port=port;
		udp_layer.setListener(local_port,this_udp_layer_listener);		
	}

	/** Binds this DatagramSocket to a specific address and port. */
	public void bind(SocketAddress addr) throws SocketException {
		if (closed) return;
		// else
		udp_layer.removeListener(this_udp_layer_listener);
		InetSocketAddress inetsoaddr=(InetSocketAddress)addr;
		init(udp_layer,inetsoaddr.getAddress(),inetsoaddr.getPort());
	}

	/** Connects the socket to a remote address for this socket. */
	public void connect(InetAddress address, int port) {
		this.remote_inetaddr=address;
		this.remote_port=port;
	}

	/** Connects this socket to a remote socket address (IP address and port). */
	public void connect(SocketAddress addr) throws SocketException {
		InetSocketAddress inetsoaddr=(InetSocketAddress)addr;
		connect(inetsoaddr.getAddress(),inetsoaddr.getPort());
	}

	/** Disconnects the socket. */
	public void disconnect() {
		remote_inetaddr=null;
	}

	/** Returns the binding state of the socket. */
	public boolean isBound() {
		return true;
	}

	/** Returns the connection state of the socket. */
	public boolean isConnected() {
		return (remote_inetaddr!=null);
	}

	/** Returns the address to which this socket is connected. */
	public InetAddress getInetAddress() {
		return remote_inetaddr;
	}

	/** Returns the port number to which this socket is connected. */
	public int getPort() {
		return remote_port;
	}

	/** Returns the address of the endpoint this socket is connected to, or null if it is unconnected. */
	public SocketAddress getRemoteSocketAddress() {
		return new InetSocketAddress(remote_inetaddr,remote_port);
	}

	/** Returns the address of the endpoint this socket is bound to. */
	public SocketAddress getLocalSocketAddress() {
		return new InetSocketAddress(local_inetaddr,local_port);
	}

	/** Gets the local address to which the socket is bound. */
	public InetAddress getLocalAddress() {
		return isClosed()? null : local_inetaddr!=null? local_inetaddr : UNSPECIFIED_ADDRESS;
	}

	/** Returns the port number on the local host to which this socket is bound. */
	public int getLocalPort() {
		return isClosed()? -1 : local_port;
	}

	/** Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds. */
	public void setSoTimeout(int timeout) throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		if (timeout<0) throw new IllegalArgumentException("Timeout can't be negative");
		// TODO
	}

	/** Retrieve setting for SO_TIMEOUT. */
	public int getSoTimeout() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		// TODO
		return 0;
	}

	/** Sets the SO_SNDBUF option to the specified value for this DatagramSocket. */
	public void setSendBufferSize(int size) throws SocketException {
		// TODO
	}

	/** Get value of the SO_SNDBUF option for this DatagramSocket, that is the buffer size used by the platform for output on this DatagramSocket. */
	public int getSendBufferSize() throws SocketException {
		return MAX_BUFFER_SIZE;
	}

	/** Sets the SO_RCVBUF option to the specified value for this DatagramSocket. */
	public void setReceiveBufferSize(int size) throws SocketException {
		// TODO
	}

	/** Get value of the SO_RCVBUF option for this DatagramSocket, that is the buffer size used by the platform for input on this DatagramSocket. */
	public int getReceiveBufferSize() throws SocketException {
		return MAX_BUFFER_SIZE;
	}

	/** Enable/disable the SO_REUSEADDR socket option. */
	/*public void setReuseAddress(boolean on) throws SocketException {
	}*/

	/** Tests if SO_REUSEADDR is enabled. */
	/*public boolean getReuseAddress() throws SocketException {
		return false;
	}*/

	/** Enable/disable SO_BROADCAST. */
	/*public void setBroadcast(boolean on) throws SocketException {
	}*/

	/** Tests if SO_BROADCAST is enabled. */
	public boolean getBroadcast() throws SocketException {
		return true;
	}

	/** Sets traffic class or type-of-service octet in the IP datagram header for datagrams sent from this DatagramSocket. */
	/*public void setTrafficClass(int tc) throws SocketException {
	}*/
	
	/** Gets traffic class or type-of-service in the IP datagram header for packets sent from this DatagramSocket. */
	/*public int getTrafficClass() throws SocketException {
		return 0;
	}*/

	/** Closes this datagram socket. */
	public void close() {
		udp_layer.removeListener(this_udp_layer_listener);
		closed=true;
	}

	/** Returns whether the socket is closed or not. */
	public boolean isClosed() {
		return closed;
	}

	/** Returns the unique DatagramChannel object associated with this datagram socket, if any. */
	/*public DatagramChannel getChannel() {
		return null;
	}*/

	/** Sets the datagram socket implementation factory for the application. */
	/*public static void setDatagramSocketImplFactory(DatagramSocketImplFactory fac) throws IOException {
	}*/

	/** Sends a datagram packet from this socket. */
	public void send(DatagramPacket p) throws IOException {
		if (DEBUG) debug("send(): "+local_inetaddr+":"+local_port+"-->"+p.getAddress().getHostAddress()+":"+p.getPort()+" ["+p.getLength()+"]");		
		IpAddress dst_addr=new Ip4Address(p.getAddress());
		IpAddress src_addr=local_inetaddr!=null? new Ip4Address(local_inetaddr) : udp_layer.getSourceAddress(dst_addr);
		UdpPacket udp_pkt=new UdpPacket(src_addr,local_port,dst_addr,p.getPort(),p.getData(),p.getOffset(),p.getLength());
		udp_layer.send(udp_pkt);
	}

	/** Receives a datagram packet from this socket. */
	public void receive(DatagramPacket p) throws IOException {
		if (DEBUG) debug("receive()");
		UdpPacket udp_pkt=null;
		synchronized (received_packets) {
			if (received_packets.size()==0) try { received_packets.wait(); } catch (InterruptedException e) {}
			udp_pkt=received_packets.get(0);
			received_packets.remove(0);
		}
		try {
			p.setAddress(InetAddress.getByAddress(udp_pkt.getSourceAddress().getBytes()));
		}
		catch (UnknownHostException e) {
		}
		p.setPort(udp_pkt.getSourcePort());
		p.setLength(udp_pkt.getPayloadLength());
		System.arraycopy(udp_pkt.getPayloadBuffer(),udp_pkt.getPayloadOffset(),p.getData(),p.getOffset(),udp_pkt.getPayloadLength());
		if (DEBUG) debug("receive(): "+udp_pkt);
	}

	// PRIVATE METHODS:
	
	/** Processes a received packet. */
	private void processReceivedPacket(UdpLayer udp_layer, UdpPacket udp_pkt) {
		if (DEBUG) debug("processReceivedPacket(): "+udp_pkt);
		synchronized (received_packets) {
			received_packets.add(udp_pkt);
			received_packets.notifyAll();
		}		
	}

}
