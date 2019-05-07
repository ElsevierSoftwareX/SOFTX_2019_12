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

package it.unipr.netsec.rawsocket.udp;


import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.rawsocket.Socket;


/** UDP socket.
 * It is implemented on top of JNI {@link it.unipr.netsec.rawsocket.Socket socket}.
 * <p>
 * It provides the same interface of {@link java.net.DatagramSocket}.
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

	/** UDP socket */
	Socket sock;
	
	/** Local IP address */
	InetAddress local_inetaddr=null;
	
	/** Local port */
	//int local_port;
	
	/** Remote IP address */
	InetAddress remote_inetaddr=null;
	
	/** Remote port */
	int remote_port;
	
	/** Whether it is bound */
	boolean bound=false;

	/** Whether it is connected */
	boolean connected=false;
	
	/** Whether it is closed */
	boolean closed=false;
	
	
	/** Creates a datagram socket and binds it to any available port on the local host machine. */
	public DatagramSocket() throws SocketException {
		this(-1);
	}

	/** Creates an unbound datagram socket with the specified DatagramSocketImpl. */
	/*protected DatagramSocket(DatagramSocketImpl impl) {
	}*/

	/** Creates a datagram socket and binds it to the specified port on the local host machine. */
	public DatagramSocket(int port) throws SocketException {
		this(port,null);
	}

	/** Creates a datagram socket, bound to the specified local address. */
	public DatagramSocket(int port, InetAddress laddr) throws SocketException {
		sock=new Socket(Socket.PF_INET,Socket.SOCK_DGRAM,0);
		if (port>0) bind(laddr,port);
	}

	/** Creates a datagram socket, bound to the specified local socket address. */
	public DatagramSocket(SocketAddress bindaddr) throws SocketException {
		this(((InetSocketAddress)bindaddr).getPort(),((InetSocketAddress)bindaddr).getAddress());
	}

	/** Binds this DatagramSocket to a specific address and port. */
	public void bind(SocketAddress addr) throws SocketException {
		InetSocketAddress bindaddr=(InetSocketAddress)addr;
		bind(bindaddr.getAddress(),bindaddr.getPort());
	}

	/** Binds this DatagramSocket to a specific port. */
	private void bind(InetAddress inetaddr, int port) throws SocketException {
		if (closed) throw new SocketException("Socket is closed");
		if (bound) throw new SocketException("Socket is already bound");
		// else
		IpAddress ipaddr=null;
		if (inetaddr instanceof Inet4Address) ipaddr=new Ip4Address(inetaddr);
		else if (inetaddr instanceof Inet6Address) ipaddr=new Ip6Address(inetaddr);
		sock.bind(ipaddr,port);
		bound=true;
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
		return new InetSocketAddress(local_inetaddr,sock.getProtocol());
	}

	/** Gets the local address to which the socket is bound. */
	public InetAddress getLocalAddress() {
		return local_inetaddr;
	}

	/** Returns the port number on the local host to which this socket is bound. */
	public int getLocalPort() {
		return sock.getProtocol();
	}

	/** Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds. */
	public void setSoTimeout(int timeout) throws SocketException {
	}

	/** Retrieve setting for SO_TIMEOUT. */
	public int getSoTimeout() throws SocketException {
		return 0;
	}

	/** Sets the SO_SNDBUF option to the specified value for this DatagramSocket. */
	/*public void setSendBufferSize(int size) throws SocketException {
	}*/

	/** Get value of the SO_SNDBUF option for this DatagramSocket, that is the buffer size used by the platform for output on this DatagramSocket. */
	public int getSendBufferSize() throws SocketException {
		return MAX_BUFFER_SIZE;
	}

	/** Sets the SO_RCVBUF option to the specified value for this DatagramSocket. */
	/*public void setReceiveBufferSize(int size) throws SocketException {
	}*/

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
		sock.close();
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
		if (DEBUG) debug("send(): "+local_inetaddr+":"+sock.getProtocol()+"-->"+p.getAddress().getHostAddress()+":"+p.getPort()+" ["+p.getLength()+"]");		
		sock.sendto(p.getData(),p.getOffset(),p.getLength(),0,p.getAddress().getHostAddress().toString(),p.getPort());
	}

	/** Receives a datagram packet from this socket. */
	public void receive(DatagramPacket p) throws IOException {
		if (DEBUG) debug("receive()");
		byte[] src_addr=new byte[4];
		byte[] src_port=new byte[2];
		//int len=sock.recv(p.getData(),p.getOffset(),0);
		int len=sock.recvfrom(p.getData(),p.getOffset(),0,src_addr,src_port);
		p.setLength(len);
		//if (DEBUG) debug("receive(): src addr="+new Ip4Address(src_addr)+", port="+ByteUtils.twoBytesToInt(src_port)+", data="+ByteUtils.asHex(p.getData(),p.getOffset(),p.getLength()));
		if (DEBUG) debug("receive(): src addr="+new Ip4Address(src_addr)+", port="+ByteUtils.twoBytesToInt(src_port)+", len="+p.getLength());
	}

}
