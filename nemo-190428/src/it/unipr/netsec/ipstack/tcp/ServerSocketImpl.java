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

package it.unipr.netsec.ipstack.tcp;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** Server socket.
 * It provides the same interface of {@link java.net.ServerSocket}, except for the method {@link java.net.ServerSocket#accept()} that is missing.
 */
public abstract class ServerSocketImpl implements java.io.Closeable {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	
	/** Local IP address */
	protected InetAddress local_inetaddr=null;
	
	/** Local port */
	protected int local_port;
	
	/** Listen backlog */
	int backlog;
	
	/** Tcp layer */
	TcpLayer tcp_layer;

			
	/** Whether it is created */
	boolean created=true;
	
	/** Whether it is bound */
	boolean bound=false;

	/** Whether it is closed */
	boolean closed=false;

	
	
	/** Creates an unbound server socket.
	 * @param tcp_layer the TCP layer
	 * @throws IOException */
	public ServerSocketImpl(TcpLayer tcp_layer) throws IOException {
		this.tcp_layer=tcp_layer;
	}

	/** Creates a server socket, bound to the specified port. A port number of {@code 0} means that the port number is automatically allocated.
	 * @param tcp_layer the TCP layer
	 * @param port the server port
	 * @throws IOException */
	public ServerSocketImpl(TcpLayer tcp_layer, int port) throws IOException {
		this.tcp_layer=tcp_layer;
		bind(null,port,50);
	}

	/** Creates a server socket and binds it to the specified local port number, with the specified backlog.
	 * @param tcp_layer the TCP layer
	 * @param port the server port
	 * @param backlog a given backlog
	 * @throws IOException */
	public ServerSocketImpl(TcpLayer tcp_layer, int port, int backlog) throws IOException {
		this.tcp_layer=tcp_layer;
		bind(null,port,backlog);
	}

	/** Create a server with the specified port, listen backlog, and local IP address to bind to.
	 * @param tcp_layer the TCP layer
	 * @param port the server port
	 * @param backlog a given backlog
	 * @param bindAddr the IP address to be bound to
	 * @throws IOException */
	public ServerSocketImpl(TcpLayer tcp_layer, int port, int backlog, InetAddress bindAddr) throws IOException {
		this.tcp_layer=tcp_layer;
		bind(bindAddr,port,backlog);
	}

	/** Binds the server socket to a specific address (IP address and port number).
	 * @param endpoint the socket address
	 * @throws IOException */
	public void bind(SocketAddress endpoint) throws IOException {
		bind(endpoint,50);
	}

	/** Binds the server socket to a specific address (IP address and port number).
	 * @param endpoint the socket address
	 * @param backlog a given backlog
	 * @throws IOException */
	public void bind(SocketAddress endpoint, int backlog) throws IOException {
		if (endpoint==null) bind(null,0,backlog);
		else {
			if (!(endpoint instanceof InetSocketAddress)) throw new IllegalArgumentException("Unsupported address type: "+endpoint);
			// else
			InetSocketAddress soaddr=(InetSocketAddress)endpoint;
			bind(soaddr.getAddress(),soaddr.getPort(),backlog);
		}
	}

	/** Binds the server socket to a specific address (IP address and port number) with given listen backlog. */
	private void bind(InetAddress bindAddr, int port, int backlog) throws IOException {
		if (DEBUG) debug("bind(): bindAddr="+bindAddr+", port="+port+", backlog="+backlog);
		if (isClosed()) throw new SocketException("Socket is closed");
		if (isBound()) throw new SocketException("Already bound");
		if (port<0||port>0xFFFF) throw new IllegalArgumentException("Port value out of range: "+port);
		// else
		if (backlog<1) backlog=50;
		this.local_inetaddr=bindAddr;
		this.local_port=port;
		this.backlog=backlog;
		bound=true;
	}

	/** Gets the local address of this server socket.
	 * @return the address */
	public InetAddress getInetAddress() {
		if (!isBound()) return null;
		return local_inetaddr;
	}

	/** Gets the port number on which this socket is listening.
	 * @return the port number */
	public int getLocalPort() {
		if (!isBound()) return -1;
		return local_port;
	}

	/** Returns the address of the endpoint this socket is bound to. */
	public SocketAddress getLocalSocketAddress() {
		if (!isBound()) return null;
		return new InetSocketAddress(getInetAddress(),getLocalPort());
	}

	/** Closes this socket. */
	public void close() throws IOException {
		if (isClosed()) return;
		closed=true;
	}

	/** Returns the unique ServerSocketChannel object. */
	/*public ServerSocketChannel getChannel() {
		return null;
	}*/

	/** Returns the binding state of the ServerSocket. */
	public boolean isBound() {
		return bound;
	}

	/** Returns the closed state of the ServerSocket. */
	public boolean isClosed() {
		return closed;
	}

	/** Enable/disable SO_TIMEOUT SO_TIMEOUT. */
	public synchronized void setSoTimeout(int timeout) throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		// TODO
	}

	/** Retrieve setting for SO_TIMEOUT SO_TIMEOUT. */
	public int getSoTimeout() throws IOException {
		if (isClosed()) throw new SocketException("Socket is closed");
		// TODO
		return 0;
	}

	/** Enable/disable the SO_REUSEADDR SO_REUSEADDR socket option. */
	/*public void setReuseAddress(boolean on) throws SocketException {
		if (isClosed())throw new SocketException("Socket is closed");
	}*/

	/** Tests if SO_REUSEADDR SO_REUSEADDR is enabled. */
	/*public boolean getReuseAddress() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		return false;
	}*/

	@Override
	public String toString() {
		return getClass().getSimpleName()+"["+(isBound()? "addr="+getInetAddress()+",localport="+getLocalPort() : "unbound")+"]";
	}

	/** Sets the server socket implementation factory. */
	/*public static void setSocketFactory(SocketImplFactory fac) throws IOException {
	}*/

	/** Sets a default proposed value for the SO_RCVBUF SO_RCVBUF option. */
	/*public void setReceiveBufferSize(int size) throws SocketException {
		if (size<=0) throw new IllegalArgumentException("Negative receive size");
		if (isClosed()) throw new SocketException("Socket is closed");
	}*/

	/** Gets the value of the SO_RCVBUF SO_RCVBUF option. */
	/*public int getReceiveBufferSize() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		return 0;
	}*/

	/** Sets performance preferences for this ServerSocket. */
	/*public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
	}*/

}
