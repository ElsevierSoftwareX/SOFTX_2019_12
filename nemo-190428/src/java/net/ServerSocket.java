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

package java.net;


import it.unipr.netsec.ipstack.netstack.NetStack;
import it.unipr.netsec.ipstack.tcp.TcpLayer;

import java.io.IOException;


/** Server socket.
 */
public class ServerSocket extends it.unipr.netsec.ipstack.tcp.ServerSocket {

	/** Tcp layer */
	static TcpLayer tcp_layer=NetStack.TCP_LAYER;

	/** Creates an unbound server socket. */
	public ServerSocket() throws IOException {
		super(tcp_layer);
	}

	/** Creates a server socket, bound to the specified port. A port number of {@code 0} means that the port number is automatically allocated. */
	public ServerSocket(int port) throws IOException {
		super(tcp_layer,port);
	}

	/** Creates a server socket and binds it to the specified local port number, with the specified backlog. */
	public ServerSocket(int port, int backlog) throws IOException {
		super(tcp_layer,port,backlog);
	}

	/** Create a server with the specified port, listen backlog, and local IP address to bind to. */
	public ServerSocket(int port, int backlog, InetAddress bindAddr) throws IOException {
		super(tcp_layer,port,backlog,bindAddr);
	}

	/** Listens for a connection to be made to this socket and accepts it. */
	public Socket accept() throws IOException {
		if (isClosed()) throw new SocketException("Socket is closed");
		if (!isBound()) throw new SocketException("Socket is not bound yet");
		// else
		Socket socket=new Socket();
		socket.bind(new InetSocketAddress(local_inetaddr,local_port));
		socket.listen();
		return socket;
	}


}
