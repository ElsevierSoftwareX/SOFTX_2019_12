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


import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.tcp.TcpConnection;
import it.unipr.netsec.ipstack.tcp.TcpConnectionListener;
import it.unipr.netsec.ipstack.tcp.TcpLayer;


/** Socket.
 * It provides the same interface of {@link java.net.Socket} while it uses {@link TcpLayer} as TCP implementation.
 */
public class Socket {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
	}

	
	/** Tcp layer */
	TcpLayer tcp_layer;

	/** Tcp connection */
	TcpConnection tcp_conn=null;

	/** Maximum input buffer size */
	static int MAX_BUFFER_SIZE=4000000;

	/** Whether the socket has been closed */
	//boolean closed=false;
	
	/** Local IP address */
	InetAddress local_inetaddr=null;
	
	/** Local port */
	int local_port;
	
	/** Remote IP address */
	InetAddress remote_inetaddr=null;
	
	/** Remote port */
	int remote_port;

	/** Connection timeout */
	int timeout;
	
	/** Buffer of received data */
	StreamBuffer receiver_buffer=new StreamBuffer();

	/** Whether it is bound */
	boolean bound=false;

	/** Whether it is connected */
	boolean connected=false;
	
	/** Whether it is closed */
	boolean closed=false;
	
	/** Whether input stream is closed */
	boolean shutdown_in=false;

	/** Whether output stream is closed */
	boolean shutdown_out=false;

	/** Lock until connected */
	Object connecting_lock=new Object();

	/** This TCP connection listener */
	protected TcpConnectionListener this_tcp_conn_listener=new TcpConnectionListener(){
		@Override
		public void onConnected(TcpConnection tcp_conn) {
			if (DEBUG) debug("onConnected()");
			Socket.this.tcp_conn=tcp_conn;
			synchronized (connecting_lock) {
				connected=true;
				connecting_lock.notifyAll();
			}
		}
		@Override
		public void onReceivedData(TcpConnection tcp_conn, byte[] buf, int off, int len) {
			if (DEBUG) debug("onReceivedData(): "+len+"B");
			if (!isInputShutdown()) {
				synchronized (receiver_buffer) {
					receiver_buffer.write(buf,off,len);
					if (DEBUG) debug("onReceivedData(): buffered: "+receiver_buffer.available());				
					receiver_buffer.notifyAll();
				}
			}
			else {
				if (DEBUG) debug("onReceivedData(): input stream has been already closed: discared");				
			}
		}
		@Override
		public void onClose(TcpConnection tcp_conn) {
			if (DEBUG) debug("onClose()");
			closed=true;
		}
		@Override
		public void onReset(TcpConnection tcp_conn) {
			if (DEBUG) debug("onReset()");
			closed=true;
		}
		@Override
		public void onClosed(TcpConnection tcp_conn) {
			if (DEBUG) debug("onClosed()");
			closed=true;
		}
	};
	
	
	/** Creates a connected socket. */
	/*protected NewSocket(NewTcpLayer tcp_layer, NewTcpConnection tcp_conn) {
		if (DEBUG) debug("Socket(conn)");
		this.tcp_layer=tcp_layer;
		this.tcp_conn=tcp_conn;
		bound=true;
		connected=true;
		//tcp_conn.setListener(this_tcp_conn_listener);
	}*/

	/** Creates an unconnected socket. */
	public Socket(TcpLayer tcp_layer) {
		if (DEBUG) debug("Socket()");
		this.tcp_layer=tcp_layer;
	}

	/** Creates an unconnected socket, specifying the type of proxy, if any, that should be used regardless of any other settings. */
	/*public Socket(Proxy proxy) {
	}*/

	/** Creates a stream socket and connects it to the specified port number at the specified IP address. */
	public Socket(TcpLayer tcp_layer, InetAddress address, int port) throws IOException {
		if (DEBUG) debug("Socket(addr,port)");
		this.tcp_layer=tcp_layer;
		connect(address,port,0);
	}

	/** Creates a stream socket and connects it to the specified port number on the named host. */
	public Socket(TcpLayer tcp_layer, String host, int port) throws UnknownHostException, IOException {
		if (DEBUG) debug("Socket(addr,port)");
		this.tcp_layer=tcp_layer;
		connect(host!=null?InetAddress.getByName(host):null,port,0);
	}

	/** Creates a socket and connects it to the specified remote host on the specified remote port. The Socket will also bind() to the local address and port supplied. */
	public Socket(TcpLayer tcp_layer, String host, int port, InetAddress localAddr, int localPort) throws IOException {
		if (DEBUG) debug("Socket(addr,port)");
		this.tcp_layer=tcp_layer;
		bind(localAddr,localPort);
		connect(host!=null?InetAddress.getByName(host):null,port,0);
	}

	/** Creates a socket and connects it to the specified remote address on the specified remote port. The Socket will also bind() to the local address and port supplied. */
	public Socket(TcpLayer tcp_layer, InetAddress address, int port, InetAddress localAddr, int localPort) throws IOException {
		if (DEBUG) debug("Socket(addr,port)");
		this.tcp_layer=tcp_layer;
		bind(localAddr,localPort);
		connect(address,port,0);
	}

	/** Binds the socket to a local address. */
	public void bind(SocketAddress bindpoint) throws IOException {
		if (isClosed()) throw new SocketException("Socket is closed");
		if (isBound()) throw new SocketException("Socket is already bound");	
		if (bindpoint!=null &&(!(bindpoint instanceof InetSocketAddress))) throw new IllegalArgumentException("Unsupported address type: "+bindpoint);
		// else
		if (bindpoint!=null) {
			InetSocketAddress soaddr=(InetSocketAddress)bindpoint;
			if (soaddr.isUnresolved()) throw new SocketException("Unresolved address: "+soaddr);
			bind(soaddr.getAddress(),soaddr.getPort());
		}
		else {
			bind(null,0);
		}
	}
	
	/** Binds the socket to a local address. */
	private void bind(InetAddress inetaddr, int port) throws IOException {
		if (DEBUG) debug("bind(): "+(inetaddr!=null?inetaddr.getHostAddress()+":"+port:port));
		checkAddress(inetaddr);
		if (port<=0) port=tcp_layer.getFreePort();
		this.local_inetaddr=inetaddr;
		this.local_port=port;
		// TODO
		bound=true;
	}
	
	/** Listens for an incoming connection 
	 * @throws IOException */
	public void listen() throws IOException {
		if (isClosed()) throw new SocketException("Socket is closed");
		if (isConnected()) throw new SocketException("Socket is already connected");
		// else
		if (!isBound()) try { bind(null,tcp_layer.getFreePort()); } catch (IOException e) { throw new SocketException(e.getMessage()); }	
		if (DEBUG) debug("listen(): "+local_port);
		
		tcp_conn=new TcpConnection(tcp_layer,null,local_port,this_tcp_conn_listener);
		tcp_conn.listen();
		synchronized (connecting_lock) {
			if (connected==false) try { connecting_lock.wait(); } catch (InterruptedException e) {}
		}
	}

	/** Connects this socket to the server. */
	public void connect(SocketAddress endpoint) throws IOException {
		connect(endpoint,0);
	}

	/** Connects this socket to the server with a specified timeout value. */
	public void connect(SocketAddress endpoint, int timeout) throws IOException {
		if (!(endpoint instanceof InetSocketAddress)) throw new IllegalArgumentException("Unsupported address type: "+endpoint);
		// else
		InetSocketAddress inetsoaddr=(InetSocketAddress)endpoint;
		connect(inetsoaddr.getAddress(),inetsoaddr.getPort(),timeout);
	}

	/** Connects this socket to a remote socket address (IP address and port) with a given timeout value. 
	 * @throws SocketException */
	private void connect(InetAddress address, int port, int timeout) throws SocketException {
		if (DEBUG) debug("connect(): "+(address!=null? address.getHostAddress()+":"+port : port));
		this.remote_inetaddr=address;
		this.remote_port=port;
		this.timeout=timeout;
		if (address==null) throw new IllegalArgumentException("The address can't be null");
		if (isClosed()) throw new SocketException("Socket is closed");
		if (isConnected()) throw new SocketException("Socket is already connected");
		// else
		if (!isBound()) try { bind(null,tcp_layer.getFreePort()); } catch (IOException e) { throw new SocketException(e.getMessage()); }	
		
		tcp_conn=new TcpConnection(tcp_layer,null,local_port,this_tcp_conn_listener);
		try {
			tcp_conn.connect(new it.unipr.netsec.ipstack.ip4.SocketAddress(address,port));
		}
		catch (IOException e) {
			throw new SocketException(e.getMessage());
		}
		synchronized (connecting_lock) {
			if (connected==false) try { connecting_lock.wait(); } catch (InterruptedException e) {}
		}
	}

	private void checkAddress(InetAddress addr) {
		if (addr==null) return;
		if (!(addr instanceof Inet4Address || addr instanceof Inet6Address)) throw new IllegalArgumentException("Invalid address type: "+addr);
	}

	/** Returns the address to which the socket is connected. */
	public InetAddress getInetAddress() {
		if (!isConnected()) return null;
		return remote_inetaddr;
	}

	/** Gets the local address to which the socket is bound. */
	public InetAddress getLocalAddress() {
		//if (!isBound() || local_inetaddr==null) return InetAddress.anyLocalAddress();
		if (!isBound() || local_inetaddr==null) return null;
		return local_inetaddr;
	}

	/** Returns the remote port number to which this socket is connected. */
	public int getPort() {
		if (!isConnected()) return 0;
		return remote_port;
	}

	/** Returns the local port number to which this socket is bound. */
	public int getLocalPort() {
		if (!isBound()) return -1;
		return local_port;
	}

	/** Returns the address of the endpoint this socket is connected to, or {@code null} if it is unconnected. */
	public SocketAddress getRemoteSocketAddress() {
		if (!isConnected()) return null;
		return new InetSocketAddress(getInetAddress(),getPort());
	}

	/** Returns the address of the endpoint this socket is bound to. */
	public SocketAddress getLocalSocketAddress() {
		if (!isBound()) return null;
		return new InetSocketAddress(getLocalAddress(),getLocalPort());
	}

	/** Returns the unique SocketChannel.  */
	/*public SocketChannel getChannel() {
		return null;
	}*/

	/** Returns an input stream for this socket. */
	public InputStream getInputStream() throws IOException {
		if (DEBUG) debug("getInputStream()");				
		if (isClosed()) throw new SocketException("Socket is closed");
		if (!isConnected()) throw new SocketException("Socket is not connected");
		if (isInputShutdown()) throw new SocketException("Socket input is shutdown");
		// else
		return new InputStream(){
			@Override
			public int read() throws IOException {
				if (DEBUG) debug("getInputStream(): read()");				
				synchronized (receiver_buffer) {
					if (DEBUG) debug("getInputStream(): read()1: "+receiver_buffer.available());				
					while (receiver_buffer.available()==0) try { receiver_buffer.wait(); } catch (InterruptedException e) {}
					if (DEBUG) debug("getInputStream(): read()2: "+receiver_buffer.available());				
					return receiver_buffer.read();
				}
			}
			@Override
			public int read(byte[] buf) throws IOException {
				if (DEBUG) debug("getInputStream(): read(buf)");				
				synchronized (receiver_buffer) {
					if (DEBUG) debug("getInputStream(): read(buf)1: "+receiver_buffer.available());				
					while (receiver_buffer.available()==0) try { receiver_buffer.wait(); } catch (InterruptedException e) {}
					if (DEBUG) debug("getInputStream(): read(buf)2: "+receiver_buffer.available());				
					return receiver_buffer.read(buf);
				}
			}
			@Override
			public int read(byte[] buf, int off, int len) throws IOException {
				if (DEBUG) debug("getInputStream(): read(buf,off,len)");				
				synchronized (receiver_buffer) {
					if (DEBUG) debug("getInputStream(): read(buf,off,len)1: "+receiver_buffer.available());				
					while (receiver_buffer.available()==0) try { receiver_buffer.wait(); } catch (InterruptedException e) {}
					if (DEBUG) debug("getInputStream(): read(buf,off,len)2: "+receiver_buffer.available());				
					return receiver_buffer.read(buf,off,len);
				}
			}
			@Override
			public int available() {
				return receiver_buffer.available();
			}			
		};
	}

	/** Returns an output stream for this socket. */
	public OutputStream getOutputStream() throws IOException {
		if (DEBUG) debug("getOutputStream()");				
		if (isClosed()) throw new SocketException("Socket is closed");
		if (!isConnected()) throw new SocketException("Socket is not connected");
		if (isOutputShutdown()) throw new SocketException("Socket output is shutdown");
		// else
		return new OutputStream(){
			@Override
			public void write(int b) throws IOException {
				tcp_conn.send(new byte[]{(byte)b});
			}
			@Override
			public void write(byte[] buf) throws IOException {
				tcp_conn.send(buf);
			}
			@Override
			public void write(byte[] buf, int off, int len) throws IOException {
				tcp_conn.send(buf,off,len);
			}
		};
	}

	/** Enable/disable TCP_NODELAY TCP_NODELAY. */
	/*public void setTcpNoDelay(boolean on) throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
	}*/

	/** Tests if TCP_NODELAY TCP_NODELAY is enabled. */
	/*public boolean getTcpNoDelay() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		return false;
	}*/

	/** Enable/disable SO_LINGER SO_LINGER with the specified linger time in seconds. */
	/*public void setSoLinger(boolean on, int linger) throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
	}*/

	/** Returns setting for SO_LINGER SO_LINGER.  */
	/*public int getSoLinger() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		return -1;
	}*/

	/** Send one byte of urgent data on the socket. */
	/*public void sendUrgentData(int data) throws IOException  {
		throw new SocketException("Urgent data not supported");
	}*/

	/** Enable/disable SO_OOBINLINE SO_OOBINLINE. */
	/*public void setOOBInline(boolean on) throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
	}*/

	/** Tests if SO_OOBINLINE SO_OOBINLINE is enabled. */
	/*public boolean getOOBInline() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		return false;
	}*/

	/**  Enable/disable SO_TIMEOUT SO_TIMEOUT. */
	public synchronized void setSoTimeout(int timeout) throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		//if (timeout<0) throw new IllegalArgumentException("Timeout can't be negative");
		// TODO
	}

	/** Returns setting for SO_TIMEOUT SO_TIMEOUT. */
	public synchronized int getSoTimeout() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		// TODO
		return 0;
	}

	/** Sets the SO_SNDBUF SO_SNDBUF option. */
	/*public synchronized void setSendBufferSize(int size) throws SocketException {
		if (size<=0) throw new IllegalArgumentException("Negative buffer size");
		if (isClosed()) throw new SocketException("Socket is closed");
	}*/

	/** Get value of the SO_SNDBUF SO_SNDBUF option. */
	/*public synchronized int getSendBufferSize() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		return 0;
	}*/

	/** Sets the SO_RCVBUF SO_RCVBUF option. */
	/*public synchronized void setReceiveBufferSize(int size) throws SocketException {
		if (size<=0) throw new IllegalArgumentException("invalid receive size");
	}*/

	/** Gets the value of the SO_RCVBUF SO_RCVBUF option. */
	/*public synchronized int getReceiveBufferSize() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		return 0;
	}*/

	/** Enable/disable SO_KEEPALIVE SO_KEEPALIVE. */
	/*public void setKeepAlive(boolean on) throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
	}*/

	/** Tests if SO_KEEPALIVE SO_KEEPALIVE is enabled. */
	/*public boolean getKeepAlive() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
	}*/

	/** Sets traffic class or type-of-service octet in the IP header for packets sent from this Socket. */
	/*public void setTrafficClass(int tc) throws SocketException {
		if (tc<0 || tc>255) throw new IllegalArgumentException("tc is not in range [0-255]");
		if (isClosed()) throw new SocketException("Socket is closed");
	}*/

	/** Gets traffic class or type-of-service in the IP header for packets sent from this Socket. */
	/*public int getTrafficClass() throws SocketException {
	}*/

	/** Enable/disable the SO_REUSEADDR SO_REUSEADDR socket option. */
	/*public void setReuseAddress(boolean on) throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
	}*/

	/** Tests if SO_REUSEADDR SO_REUSEADDR is enabled. */
	/*public boolean getReuseAddress() throws SocketException {
		if (isClosed()) throw new SocketException("Socket is closed");
		return false;
	}*/

	/** Closes this socket. */
	public void close() throws IOException {
		tcp_conn.close();
		closed=true;
	}

	/** Places the input stream for this socket at "end of stream". */
	public void shutdownInput() throws IOException {
		if (isClosed()) throw new SocketException("Socket is closed");
		if (!isConnected()) throw new SocketException("Socket is not connected");
		if (isInputShutdown()) throw new SocketException("Socket input is already shutdown");
		shutdown_in=true;
	}

	/** Disables the output stream for this socket. */
	public void shutdownOutput() throws IOException {
		if (isClosed()) throw new SocketException("Socket is closed");
		if (!isConnected()) throw new SocketException("Socket is not connected");
		if (isOutputShutdown()) throw new SocketException("Socket output is already shutdown");
		tcp_conn.close();
		shutdown_out=true;
	}

	/*@Override
	public String toString() {
		if (isConnected()) return "Socket[addr="+getInetAddress()+",port="+getPort()+",localport="+getLocalPort()+"]";
		else return "Socket[unconnected]";
	}*/

	/** Returns the connection state of the socket. */
	public boolean isConnected() {
		return connected;
	}

	/** Returns the binding state of the socket. */
	public boolean isBound() {
		return bound;
	}

	/** Returns the closed state of the socket. */
	public boolean isClosed() {
		return closed;
	}

	/** Returns whether the read-half of the socket connection is closed. */
	public boolean isInputShutdown() {
		return shutdown_in;
	}

	/** Returns whether the write-half of the socket connection is closed. */
	public boolean isOutputShutdown() {
		return shutdown_out;
	}

	/** Sets the client socket implementation factory for the application. */
	/*public static synchronized void setSocketImplFactory(SocketImplFactory fac) throws IOException {
	}*/

	/** Sets performance preferences for this socket. */
	/*public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
		// Not implemented yet
	}*/
}
