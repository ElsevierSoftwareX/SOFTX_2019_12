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
import java.net.SocketException;


/** Server socket.
 * It provides the same interface of {@link java.net.ServerSocket}.
 * It extends {@link it.unipr.netsec.ipstack.tcp.ServerSocketImpl} by adding the missing method {@link #accept()}.
 */
public class ServerSocket extends ServerSocketImpl {

	/** Creates an unbound server socket.
	 * @param tcp_layer the TCP layer
	 * @throws IOException */
	public ServerSocket(TcpLayer tcp_layer) throws IOException {
		super(tcp_layer);
	}

	/** Creates a server socket, bound to the specified port. A port number of {@code 0} means that the port number is automatically allocated.
	 * @param tcp_layer the TCP layer
	 * @param port the server port
	 * @throws IOException */
	public ServerSocket(TcpLayer tcp_layer, int port) throws IOException {
		super(tcp_layer,port);
	}

	/** Creates a server socket and binds it to the specified local port number, with the specified backlog.
	 * @param tcp_layer the TCP layer
	 * @param port the server port
	 * @param backlog a given backlog
	 * @throws IOException */
	public ServerSocket(TcpLayer tcp_layer, int port, int backlog) throws IOException {
		super(tcp_layer,port,backlog);
	}

	/** Create a server with the specified port, listen backlog, and local IP address to bind to.
	 * @param tcp_layer the TCP layer
	 * @param port the server port
	 * @param backlog a given backlog
	 * @param bindAddr the IP address to be bound to
	 * @throws IOException */
	public ServerSocket(TcpLayer tcp_layer, int port, int backlog, InetAddress bindAddr) throws IOException {
		super(tcp_layer,port,backlog,bindAddr);
	}

	/** Listens for a connection to be made to this socket and accepts it.
	 * @return the new socket
	 * @throws IOException */
	public Socket accept() throws IOException {
		if (DEBUG) debug("acceptSocket()");
		if (isClosed()) throw new SocketException("Socket is closed");
		if (!isBound()) throw new SocketException("Socket is not bound yet");
		// else
		Socket socket=new Socket(tcp_layer);
		socket.bind(new InetSocketAddress(local_inetaddr,local_port));
		socket.listen();
		return socket;
	}

}
